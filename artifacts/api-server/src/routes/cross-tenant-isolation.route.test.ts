import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import {
  db,
  bootstrap,
  findingsTable,
  chatSessionsTable,
  chatMessagesTable,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// M12.4 — Cross-tenant escalation guard.
//
// Threat model §EoP "Cross-tenant escalation" + §Information Disclosure
// ("Cross-tenant retrieval contexts"): no authenticated endpoint may return,
// confirm the existence of, or act on another tenant's data. Authentication is
// per-tenant (tenant_id is bound into the session cookie at login and is
// immutable for the session), so a fully-authenticated, fully-stepped-up user
// in tenant A is exactly the actor we must prove cannot reach tenant B.
//
// This test seeds two independent tenants with the full spread of tenant-owned
// data — findings (with raw evidence), chat sessions + messages, and an active
// break-glass grant each — then drives the REAL Express app over HTTP and
// asserts every data-returning endpoint is isolated. It is the route-level
// counterpart to the RLS policies + `withTenant` GUC: a regression that drops a
// `tenant_id` predicate (or adds an unscoped query like the pre-M12.4
// `GET /api/ledger`) must fail here rather than ship.
// ---------------------------------------------------------------------------

import { uniq, ledgerHeadSeq } from "../test-support/ledger-harness";

let server: Server;
let baseUrl: string;

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
  return async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  };
});

// Minimal cookie jar over fetch + a distinct source IP per client so the
// per-IP login/step-up rate limiters key on the client, not shared loopback.
class Client {
  private jar = new Map<string, string>();

  constructor(private readonly ip: string) {}

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
        "x-forwarded-for": this.ip,
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
      body: JSON.stringify(body),
    });
    this.absorb(res);
    return res;
  }

  async get(path: string): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: {
        "x-forwarded-for": this.ip,
        ...(this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
    });
    this.absorb(res);
    return res;
  }
}

let ipCounter = 0;
function nextClientIp(): string {
  ipCounter += 1;
  return `10.20.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

/** Drive login (binding tenant_id) + step-up so the client carries both cookies. */
async function authedClient(
  user: string,
  tenantId: string,
): Promise<{ c: Client; sub: string }> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: tenantId,
  });
  expect(login.status).toBe(200);
  const loginBody = (await login.json()) as { sub: string };
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "cross-tenant isolation route test",
  });
  expect(stepUp.status).toBe(200);
  return { c, sub: loginBody.sub };
}

/** Insert a HIGH finding (so a grant on it is immediately active — no second
 *  approval) with an inline raw payload, in the given tenant. */
async function createHighFinding(tenantId: string): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      source: `fixture:xtenant:${uniq()}`,
      fingerprint: `phi:ssn:xtenant:${uniq()}:v1`,
      redactedEvidence: {
        snippet: "x=[REDACTED:ssn]",
        redactions: ["ssn"],
        truncated: false,
        trust: "untrusted",
      },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Insert a CRITICAL finding (so a grant on it stays pending second approval
 *  and therefore shows up in /break-glass/pending-approvals) in the tenant. */
async function createCriticalFinding(tenantId: string): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: "phi",
      subclass: "ssn",
      severity: "critical",
      source: `fixture:xtenant-crit:${uniq()}`,
      fingerprint: `phi:ssn:xtenant-crit:${uniq()}:v1`,
      redactedEvidence: {
        snippet: "x=[REDACTED:ssn]",
        redactions: ["ssn"],
        truncated: false,
        trust: "untrusted",
      },
      rawEvidence: { snippet: "ssn=987-65-4321" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Insert a chat session owned by (tenant, user) plus one message. */
async function createChatSession(
  tenantId: string,
  userId: string,
): Promise<string> {
  const id = `cs_${randomUUID()}`;
  await withTenant(tenantId, async (tx) => {
    await tx
      .insert(chatSessionsTable)
      .values({ id, tenantId, userId, title: `xtenant ${uniq()}` });
    await tx.insert(chatMessagesTable).values({
      id: `cm_${randomUUID()}`,
      sessionId: id,
      tenantId,
      role: "user",
      content: `tenant-private message ${uniq()}`,
      citations: [],
      agentIdentity: null,
    });
  });
  return id;
}


interface Fixture {
  tenant: string;
  user: string;
  sub: string;
  client: Client;
  findingId: string;
  sessionId: string;
  grantId: string;
  justification: string;
  // A critical finding + the grant created over it. Critical severity keeps the
  // grant pending second approval, so it surfaces in /pending-approvals — the
  // surface we use to prove that approval queue is tenant-isolated too.
  criticalFindingId: string;
  pendingGrantId: string;
}

/** Stand up a tenant with a user, a finding, a chat session, and an active
 *  break-glass grant created over the real HTTP flow (so it leaves a ledger
 *  entry carrying the tenant-private justification sentinel). */
async function setupTenant(label: string): Promise<Fixture> {
  const tenant = `t_${label}_${uniq()}`;
  const user = `${label}-${uniq()}`;
  const { c: client, sub } = await authedClient(user, tenant);
  const findingId = await createHighFinding(tenant);
  const sessionId = await createChatSession(tenant, sub);
  const justification = `JUSTIFICATION_SENTINEL_${label}_${uniq()}`;
  const grantRes = await client.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification,
  });
  expect(grantRes.status).toBe(201);
  const grant = (await grantRes.json()) as { id: string; active: boolean };
  // High severity → no second approval → grant is active immediately.
  expect(grant.active).toBe(true);

  // Critical finding + grant → stays pending second approval, so it appears in
  // this tenant's /pending-approvals queue (when polled by a different user).
  const criticalFindingId = await createCriticalFinding(tenant);
  const pendingRes = await client.post("/api/admin/break-glass/grants", {
    finding_id: criticalFindingId,
    justification: `${justification}_CRIT`,
  });
  expect(pendingRes.status).toBe(201);
  const pendingGrant = (await pendingRes.json()) as {
    id: string;
    active: boolean;
  };
  // Critical severity → requires second approval → not active yet.
  expect(pendingGrant.active).toBe(false);

  return {
    tenant,
    user,
    sub,
    client,
    findingId,
    sessionId,
    grantId: grant.id,
    justification,
    criticalFindingId,
    pendingGrantId: pendingGrant.id,
  };
}

describe("cross-tenant isolation (HTTP)", () => {
  let A: Fixture;
  let B: Fixture;
  let sinceSeq: number;

  beforeAll(async () => {
    // Capture the ledger head BEFORE creating the two tenants' grants so the
    // /api/ledger assertions can scope to just-created rows (the shared dev
    // ledger is polluted by other test files — see replit.md "Gotchas").
    sinceSeq = await ledgerHeadSeq();
    A = await setupTenant("alice");
    B = await setupTenant("bob");
  });

  it("findings list returns only the caller's tenant", async () => {
    const res = await A.client.get("/api/findings?severity=high");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{ id: string; tenant_id: string }>;
    expect(rows.some((r) => r.id === A.findingId)).toBe(true);
    expect(rows.some((r) => r.id === B.findingId)).toBe(false);
    expect(rows.every((r) => r.tenant_id === A.tenant)).toBe(true);
  });

  it("single-finding read of another tenant's finding is 404, own is 200", async () => {
    const cross = await A.client.get(`/api/findings/${B.findingId}`);
    expect(cross.status).toBe(404);
    const own = await A.client.get(`/api/findings/${A.findingId}`);
    expect(own.status).toBe(200);
  });

  it("ledger view is scoped to the caller's tenant (no cross-tenant payloads)", async () => {
    const res = await A.client.get(`/api/ledger?after_seq=${sinceSeq}&limit=500`);
    expect(res.status).toBe(200);
    const text = await res.text();
    const body = JSON.parse(text) as {
      entries: Array<{ tenant_id: string; event_type: string }>;
    };
    // A sees its own break-glass grant entry...
    expect(
      body.entries.some(
        (e) =>
          e.tenant_id === A.tenant && e.event_type === "break_glass.granted",
      ),
    ).toBe(true);
    // ...and NEVER any entry tagged with tenant B.
    expect(body.entries.every((e) => e.tenant_id !== B.tenant)).toBe(true);
    // Belt-and-suspenders: B's tenant-private justification text (which lands
    // in the ledger payload) must not appear anywhere in A's ledger response.
    expect(text).not.toContain(B.justification);
  });

  it("ledger head is tenant-local, not the global chain head", async () => {
    // The `head` query is independently scoped to the caller's tenant; a
    // regression that reverts only the head predicate would leak the global
    // cross-tenant event count/hash even while the entries list stays scoped.
    // The global head necessarily has a seq >= any single tenant's head (the
    // shared dev ledger interleaves every tenant + test-marker row), and A's
    // head must be the seq of A's own most-recent entry.
    const globalHead = await ledgerHeadSeq();
    const fullRow = (
      await db.execute(
        sql`SELECT seq, hash FROM ledger_entries WHERE tenant_id = ${A.tenant} ORDER BY seq DESC LIMIT 1`,
      )
    ).rows[0] as { seq: string | number; hash: string };
    // `seq` is a bigint column → raw driver returns it as a string; the route
    // response coerces it to a number via the LedgerPage Zod schema.
    const tenantHeadSeq = Number(fullRow.seq);

    const res = await A.client.get(`/api/ledger?after_seq=${sinceSeq}&limit=500`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { head_seq: number; head_hash: string };
    expect(body.head_seq).toBe(tenantHeadSeq);
    expect(body.head_hash).toBe(fullRow.hash);
    // A's tenant head trails the polluted global head (other tenants/markers).
    expect(body.head_seq).toBeLessThanOrEqual(globalHead);
  });

  it("chat sessions list returns only the caller's tenant", async () => {
    const res = await A.client.get("/api/chat/sessions");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{ id: string; tenant_id: string }>;
    expect(rows.some((r) => r.id === A.sessionId)).toBe(true);
    expect(rows.some((r) => r.id === B.sessionId)).toBe(false);
    expect(rows.every((r) => r.tenant_id === A.tenant)).toBe(true);
  });

  it("chat messages of another tenant's session are not readable", async () => {
    const res = await A.client.get(
      `/api/chat/sessions/${B.sessionId}/messages`,
    );
    expect(res.status).toBe(200);
    const rows = (await res.json()) as unknown[];
    expect(rows).toHaveLength(0);
  });

  it("break-glass grant list returns only the caller's grants", async () => {
    const res = await A.client.get("/api/admin/break-glass/grants");
    expect(res.status).toBe(200);
    const rows = (await res.json()) as Array<{ id: string; tenant_id: string }>;
    expect(rows.some((g) => g.id === A.grantId)).toBe(true);
    expect(rows.some((g) => g.id === B.grantId)).toBe(false);
    expect(rows.every((g) => g.tenant_id === A.tenant)).toBe(true);
  });

  it("cannot approve or revoke another tenant's grant", async () => {
    const approve = await A.client.post(
      `/api/admin/break-glass/grants/${B.grantId}/approve`,
      { approval_note: "attempting cross-tenant approval of another tenant" },
    );
    expect(approve.status).toBe(404);
    const revoke = await A.client.post(
      `/api/admin/break-glass/grants/${B.grantId}/revoke`,
      { reason: "attempting cross-tenant revoke" },
    );
    expect(revoke.status).toBe(404);
  });

  it("pending-approvals queue is tenant-isolated", async () => {
    // A's pending grant (on its critical finding) must surface in A's queue but
    // never in B's, and vice-versa. We poll as the SAME user who requested the
    // grant; the requester is filtered out of their own queue, but the grant is
    // still visible to others in-tenant — the cross-tenant guarantee is that B's
    // queue never contains A's grant regardless of who polls.
    const aQueue = await A.client.get("/api/admin/break-glass/pending-approvals");
    expect(aQueue.status).toBe(200);
    const aRows = (await aQueue.json()) as Array<{
      id: string;
      tenant_id: string;
    }>;
    expect(aRows.every((g) => g.tenant_id === A.tenant)).toBe(true);
    expect(aRows.some((g) => g.id === B.pendingGrantId)).toBe(false);

    const bQueue = await B.client.get("/api/admin/break-glass/pending-approvals");
    expect(bQueue.status).toBe(200);
    const bRows = (await bQueue.json()) as Array<{
      id: string;
      tenant_id: string;
    }>;
    expect(bRows.every((g) => g.tenant_id === B.tenant)).toBe(true);
    expect(bRows.some((g) => g.id === A.pendingGrantId)).toBe(false);
  });

  it("cannot create a break-glass grant over another tenant's finding", async () => {
    const res = await A.client.post("/api/admin/break-glass/grants", {
      finding_id: B.findingId,
      justification: "attempting grant over another tenant's finding",
    });
    expect(res.status).toBe(404);
  });

  it("cannot read another tenant's raw evidence (fails closed, no grant)", async () => {
    const res = await A.client.get(`/api/admin/findings/${B.findingId}/raw`);
    expect(res.status).toBe(403);
    const body = (await res.json()) as { break_glass_required?: boolean };
    expect(body.break_glass_required).toBe(true);
  });

  it("get_finding tool cannot resolve another tenant's finding", async () => {
    const cross = await A.client.post("/api/tools/get_finding", {
      finding_id: B.findingId,
    });
    expect(cross.status).toBe(404);
    const own = await A.client.post("/api/tools/get_finding", {
      finding_id: A.findingId,
    });
    expect(own.status).toBe(200);
  });

  it("ledger ?actor filter returns only that human actor's entries, server-side", async () => {
    // The break-glass grants A created over the HTTP flow are ledgered with
    // actor {kind:"human", id:A.sub}. Filtering by A.sub must return A's own
    // entries and nothing attributed to a different actor.
    const res = await A.client.get(
      `/api/ledger?actor=${encodeURIComponent(A.sub)}&after_seq=${sinceSeq}&limit=500`,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      entries: Array<{
        tenant_id: string;
        event_type: string;
        actor: { kind: string; id: string };
      }>;
    };
    // Every returned row is A's human actor — never agent/system rows, never
    // another human's rows.
    expect(body.entries.length).toBeGreaterThan(0);
    expect(
      body.entries.every((e) => e.actor.kind === "human" && e.actor.id === A.sub),
    ).toBe(true);
    // A's own break-glass grant entry is present in the filtered view.
    expect(
      body.entries.some((e) => e.event_type === "break_glass.granted"),
    ).toBe(true);
  });

  it("ledger ?actor filter stays tenant-scoped (cannot pivot to another tenant's actor)", async () => {
    // Even asking for B's actor id from A's session returns nothing: the tenant
    // predicate still applies, so B's entries are unreachable.
    const res = await A.client.get(
      `/api/ledger?actor=${encodeURIComponent(B.sub)}&after_seq=${sinceSeq}&limit=500`,
    );
    expect(res.status).toBe(200);
    const text = await res.text();
    const body = JSON.parse(text) as { entries: unknown[] };
    expect(body.entries).toHaveLength(0);
    expect(text).not.toContain(B.justification);
  });

  it("isolation is symmetric: B cannot see A's findings or ledger", async () => {
    const findings = await B.client.get("/api/findings?severity=high");
    expect(findings.status).toBe(200);
    const rows = (await findings.json()) as Array<{
      id: string;
      tenant_id: string;
    }>;
    expect(rows.some((r) => r.id === A.findingId)).toBe(false);
    expect(rows.every((r) => r.tenant_id === B.tenant)).toBe(true);

    const ledger = await B.client.get(
      `/api/ledger?after_seq=${sinceSeq}&limit=500`,
    );
    expect(ledger.status).toBe(200);
    const text = await ledger.text();
    const body = JSON.parse(text) as {
      entries: Array<{ tenant_id: string }>;
    };
    expect(body.entries.every((e) => e.tenant_id !== A.tenant)).toBe(true);
    expect(text).not.toContain(A.justification);
  });
});
