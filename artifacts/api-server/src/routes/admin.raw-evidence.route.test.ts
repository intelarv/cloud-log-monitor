import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { and, desc, eq, gt, sql } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";
import {
  setRawEvidenceStore,
  resetRawEvidenceStoreForTests,
  DatabaseRawEvidenceStore,
  type RawEvidenceStore,
} from "../lib/raw-evidence-store";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the break-glass raw-PHI read endpoint
// (GET /api/admin/findings/:id/raw) when the external raw-evidence store is
// unreachable / misconfigured / absent.
//
// The resolution branching (raw-evidence-store.ts resolveRawEvidence) and the
// ingest-side failure path (ingest.test.ts) are unit-tested, but until now
// there was NO route-level test exercising the full session + step-up + grant
// flow end-to-end. These tests drive the real Express app over HTTP so the
// "honest unresolved signal" guarantee can't silently regress in the route
// wiring (ledger flags, response shape, store lookup).
//
// All findings here are severity `high` (NOT critical) so the grant flow needs
// only session + step-up, no second-person approval — keeping the harness
// focused on the unresolved-signal cases.
// ---------------------------------------------------------------------------

const TENANT = "default";
import { uniq, ledgerHeadSeq } from "../test-support/ledger-harness";

let server: Server;
let baseUrl: string;
// One shared authed client for the whole file. Step-up is per-IP rate-limited
// (5/min) so minting a fresh session+step-up per test would trip the limiter
// once the file has more than five cases. The session identity is irrelevant to
// the resolution branches under test (all findings are `high`, no two-person
// approval), so a single client driving every case is both sufficient and
// limiter-safe; break-glass issuance (10/min per user) stays under cap.
let client: Client;

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  await new Promise<void>((resolve) => {
    server = createServer(app);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (addr && typeof addr === "object") {
        baseUrl = `http://127.0.0.1:${addr.port}`;
      }
      resolve();
    });
  });
  client = await authedClient(`req-${uniq()}`);
  return async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
});

afterEach(() => {
  // The route reads the module-level store singleton at request time; reset
  // between cases (vitest runs tests in a file sequentially, fileParallelism
  // is off) so a previous case's store can't leak into the next.
  resetRawEvidenceStoreForTests();
});

// Minimal cookie jar over fetch (fetch does not persist Set-Cookie itself).
class Client {
  private jar = new Map<string, string>();

  private cookieHeader(): string {
    return [...this.jar.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
  }

  private absorb(res: Response): void {
    for (const raw of res.headers.getSetCookie()) {
      const pair = raw.split(";")[0]!;
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      this.jar.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
  }

  async post(path: string, body: unknown): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
      body: JSON.stringify(body),
    });
    this.absorb(res);
    return res;
  }

  async get(path: string): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: this.jar.size ? { cookie: this.cookieHeader() } : {},
    });
    this.absorb(res);
    return res;
  }
}

/** Drive login + step-up so the returned client carries both cookies. */
async function authedClient(user: string): Promise<Client> {
  const c = new Client();
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "route test raw-evidence resolution",
  });
  expect(stepUp.status).toBe(200);
  return c;
}

/** Insert a finding (severity high → no two-person approval) with the given
 *  raw-evidence state, returning its id. */
async function createFinding(opts: {
  rawEvidence?: unknown;
  rawEvidenceRef?: unknown;
}): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      source: `fixture:routetest:${uniq()}`,
      fingerprint: `phi:ssn:routetest:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: opts.rawEvidence ?? null,
      rawEvidenceRef: opts.rawEvidenceRef ?? null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Create a break-glass grant for `findingId` via the real HTTP flow. */
async function createGrant(c: Client, findingId: string): Promise<string> {
  const res = await c.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification: "route test break-glass raw read",
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as { id: string; pending_approval: boolean };
  expect(body.pending_approval).toBe(false);
  return body.id;
}

interface RawAccessPayload {
  grant_id: unknown;
  finding_id: unknown;
  raw_present: unknown;
  raw_resolved: unknown;
  raw_source: unknown;
  raw_fallback_used: unknown;
}

/** Fetch the latest break_glass.raw_phi_accessed ledger entry for a finding. */
async function latestRawAccessLedger(
  findingId: string,
  sinceSeq: number,
): Promise<RawAccessPayload | null> {
  const rows = await db
    .select({ payload: ledgerEntriesTable.payload })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, "break_glass.raw_phi_accessed"),
        eq(ledgerEntriesTable.subjectId, findingId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (rows.length === 0) return null;
  return rows[0]!.payload as RawAccessPayload;
}


interface FallbackAlertPayload {
  finding_id: unknown;
  store: unknown;
  reason: unknown;
}

/** Fetch the latest break_glass.raw_fallback_used ledger entry for a finding. */
async function latestFallbackAlertLedger(
  findingId: string,
  sinceSeq: number,
): Promise<FallbackAlertPayload | null> {
  const rows = await db
    .select({ payload: ledgerEntriesTable.payload })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, "break_glass.raw_fallback_used"),
        eq(ledgerEntriesTable.subjectId, findingId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (rows.length === 0) return null;
  return rows[0]!.payload as FallbackAlertPayload;
}

function externalStore(over?: Partial<RawEvidenceStore>): RawEvidenceStore {
  return {
    name: "fake-worm",
    external: true,
    async put() {
      throw new Error("put not used in route resolution tests");
    },
    async get() {
      return { payload: "should-not-be-reached" };
    },
    ...over,
  };
}

const validRef = { first: "s3://fake/a.json", latest: "s3://fake/b.json" };

describe("GET /api/admin/findings/:id/raw — external store unreachable", () => {
  it("external write failed at ingest (ref NULL, no inline) → raw_unresolved", async () => {
    // External store configured, but the finding has neither inline raw nor a
    // ref — the ingest-time object write failed and left ref NULL by design.
    setRawEvidenceStore(externalStore());
    const c = client;
    const findingId = await createFinding({});
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      raw_evidence: unknown;
      raw_unresolved?: string;
    };
    expect(body.raw_evidence).toBeNull();
    expect(body.raw_unresolved).toBeDefined();
    expect(body.raw_unresolved).toMatch(/external write likely failed at ingest/);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led).not.toBeNull();
    expect(led!.raw_present).toBe(false);
    expect(led!.raw_resolved).toBe(false);
    expect(led!.raw_fallback_used).toBe(false);
  });

  it("ref present but no external store configured → raw_unresolved", async () => {
    // A ref exists on the row, but no store is registered to resolve it.
    resetRawEvidenceStoreForTests();
    const c = client;
    const findingId = await createFinding({ rawEvidenceRef: validRef });
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      raw_evidence: unknown;
      raw_unresolved?: string;
    };
    expect(body.raw_evidence).toBeNull();
    expect(body.raw_unresolved).toMatch(/no external store is configured/);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led!.raw_present).toBe(true);
    expect(led!.raw_resolved).toBe(false);
    expect(led!.raw_fallback_used).toBe(false);
  });

  it("ref present but malformed → raw_unresolved", async () => {
    setRawEvidenceStore(externalStore());
    const c = client;
    const findingId = await createFinding({
      rawEvidenceRef: { not: "a-ref" },
    });
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      raw_evidence: unknown;
      raw_unresolved?: string;
    };
    expect(body.raw_evidence).toBeNull();
    expect(body.raw_unresolved).toMatch(/malformed raw_evidence_ref/);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led!.raw_present).toBe(true);
    expect(led!.raw_resolved).toBe(false);
    expect(led!.raw_fallback_used).toBe(false);
  });

  it("ref present and store.get throws → raw_unresolved + raw_evidence null", async () => {
    setRawEvidenceStore(
      externalStore({
        async get() {
          throw new Error("simulated WORM outage on read");
        },
      }),
    );
    const c = client;
    const findingId = await createFinding({ rawEvidenceRef: validRef });
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      raw_evidence: unknown;
      raw_unresolved?: string;
    };
    expect(body.raw_evidence).toBeNull();
    expect(body.raw_unresolved).toMatch(
      /failed to resolve raw evidence from external store/,
    );

    const led = await latestRawAccessLedger(findingId, before);
    expect(led!.raw_present).toBe(true);
    expect(led!.raw_resolved).toBe(false);
    expect(led!.raw_fallback_used).toBe(false);
  });

  it("ref unresolvable BUT inline raw present → inline fallback served, NO raw_unresolved", async () => {
    // Mixed-state row during a provider migration: an external ref exists but
    // cannot be resolved (store.get throws — WORM outage), while the legacy
    // inline raw_evidence column still carries raw. The break-glass read must
    // serve the inline copy rather than failing closed, and the ledger must
    // record the fallback honestly (raw_resolved: true, raw_fallback_used: true).
    setRawEvidenceStore(
      externalStore({
        async get() {
          throw new Error("simulated WORM outage on read");
        },
      }),
    );
    const c = client;
    const inlinePayload = { first: { snippet: "ssn=123-45-6789" }, latest: { snippet: "ssn=123-45-6789" } };
    const findingId = await createFinding({
      rawEvidence: inlinePayload,
      rawEvidenceRef: validRef,
    });
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.raw_evidence).toEqual(inlinePayload);
    expect("raw_unresolved" in body).toBe(false);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led).not.toBeNull();
    expect(led!.raw_present).toBe(true);
    expect(led!.raw_resolved).toBe(true);
    expect(led!.raw_source).toBe("database");
    expect(led!.raw_fallback_used).toBe(true);

    // Degraded durable-read alert: the WORM tier failed the read, so a
    // dedicated `break_glass.raw_fallback_used` event (ALERT_RULES → high,
    // routed through the channel router) must fire, carrying finding id +
    // store name + reason only (NO raw PHI).
    const alert = await latestFallbackAlertLedger(findingId, before);
    expect(alert).not.toBeNull();
    expect(alert!.finding_id).toBe(findingId);
    expect(alert!.store).toBe("fake-worm");
    expect(alert!.reason).toMatch(
      /failed to resolve raw evidence from external store/,
    );
    // The alert must never carry the raw payload.
    expect(JSON.stringify(alert)).not.toContain("123-45-6789");
  });

  it("external store resolves normally → NO fallback alert", async () => {
    // Happy path: the external ref resolves from the WORM store. The durable
    // tier is healthy, so the degraded-read alert must NOT fire.
    const resolved = { snippet: "ssn=123-45-6789" };
    setRawEvidenceStore(
      externalStore({
        async get() {
          return resolved;
        },
      }),
    );
    const c = client;
    const findingId = await createFinding({ rawEvidenceRef: validRef });
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect("raw_unresolved" in body).toBe(false);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led!.raw_resolved).toBe(true);
    expect(led!.raw_source).toBe("external_store");
    expect(led!.raw_fallback_used).toBe(false);

    const alert = await latestFallbackAlertLedger(findingId, before);
    expect(alert).toBeNull();
  });

  it("DB store, raw genuinely absent → bare null, NO raw_unresolved", async () => {
    // Database store (external=false): a null here is genuinely absent, not a
    // failed external write. The gate + ledger still operate, but the response
    // must NOT carry a (misleading) raw_unresolved marker.
    setRawEvidenceStore(new DatabaseRawEvidenceStore());
    const c = client;
    const findingId = await createFinding({});
    await createGrant(c, findingId);

    const before = await ledgerHeadSeq();
    const res = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.raw_evidence).toBeNull();
    expect("raw_unresolved" in body).toBe(false);

    const led = await latestRawAccessLedger(findingId, before);
    expect(led!.raw_present).toBe(false);
    expect(led!.raw_resolved).toBe(true);
    expect(led!.raw_fallback_used).toBe(false);
  });
});
