import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, eq, gt, desc } from "drizzle-orm";
import {
  db,
  breakGlassGrantsTable,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";
import { uniq, ledgerHeadSeq } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the break-glass RE-REQUEST flow (Task #115).
//
// The dashboard lets an analyst whose grant has lapsed (TTL expired) or been
// revoked request a FRESH grant on the same finding — the "re-request" affordance
// (finding-detail break-glass modal, prefilled with the prior justification +
// duration, Tasks #114). The lifecycle edges (expiry/revocation blocking the raw
// read, approval 410s) are covered in admin.grant-lifecycle.route.test.ts; this
// file closes the end-to-end gap that the *re-grant* itself works:
//
//   1. analyst gets a grant (high severity → one-step) and reads raw OK;
//   2. the grant lapses (expire) / is revoked → the raw read fails closed (403);
//   3. the analyst re-requests → a NEW, distinct grant id is issued and the raw
//      read succeeds again on that fresh grant.
//
// All findings are severity `high` (NOT critical) so the grant flow needs only
// session + step-up, no second-person approval. Each analyst uses a distinct
// source IP (the app runs with `trust proxy`) so the per-IP step-up limiter
// (5/min) keys per client rather than on the shared loopback.
// ---------------------------------------------------------------------------

const TENANT = "default";

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
  return `10.40.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

async function authedClient(user: string): Promise<Client> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", { username: user, tenant_id: TENANT });
  expect(login.status).toBe(200);
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "route test break-glass re-request",
  });
  expect(stepUp.status).toBe(200);
  return c;
}

/** Insert a high-severity PHI finding with inline raw evidence. */
async function createHighFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      source: `fixture:rerequest:${uniq()}`,
      fingerprint: `phi:ssn:rerequest:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Create a one-step grant (high severity) via the real route; returns its id. */
async function createGrant(c: Client, findingId: string, justification: string): Promise<string> {
  const res = await c.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification,
    ttl_seconds: 120,
  });
  expect(res.status).toBe(201);
  const body = (await res.json()) as { id: string; pending_approval: boolean };
  expect(body.pending_approval).toBe(false);
  return body.id;
}

async function expireGrant(grantId: string): Promise<void> {
  await withTenant(TENANT, async (tx) => {
    await tx
      .update(breakGlassGrantsTable)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(
        and(
          eq(breakGlassGrantsTable.id, grantId),
          eq(breakGlassGrantsTable.tenantId, TENANT),
        ),
      );
  });
}

/** Count break_glass.granted ledger rows for a finding after `sinceSeq`. */
async function countGrantedEvents(findingId: string, sinceSeq: number): Promise<number> {
  const rows = await db
    .select({ seq: ledgerEntriesTable.seq })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, "break_glass.granted"),
        eq(ledgerEntriesTable.subjectId, findingId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq));
  return rows.length;
}

describe("break-glass re-request flow over the live login flow (HTTP)", () => {
  it("re-requests a fresh grant after the prior grant expired, restoring raw access", async () => {
    const findingId = await createHighFinding();
    const c = await authedClient(`req-${uniq()}`);
    const before = await ledgerHeadSeq();

    // 1. First grant → raw read OK.
    const grant1 = await createGrant(c, findingId, "initial incident triage");
    const read1 = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(read1.status).toBe(200);
    const body1 = (await read1.json()) as { raw_evidence: { snippet?: string } | null };
    expect(body1.raw_evidence?.snippet).toBe("ssn=123-45-6789");

    // 2. TTL lapses → raw read fails closed.
    await expireGrant(grant1);
    const readExpired = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(readExpired.status).toBe(403);
    const expiredBody = (await readExpired.json()) as { break_glass_required?: boolean };
    expect(expiredBody.break_glass_required).toBe(true);

    // 3. Re-request → a NEW, distinct grant id is issued and raw access returns.
    const grant2 = await createGrant(c, findingId, "re-request: still investigating");
    expect(grant2).not.toBe(grant1);
    const read2 = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(read2.status).toBe(200);
    const body2 = (await read2.json()) as { raw_evidence: { snippet?: string } | null };
    expect(body2.raw_evidence?.snippet).toBe("ssn=123-45-6789");

    // Both the original and the re-requested grant are independently ledgered.
    expect(await countGrantedEvents(findingId, before)).toBe(2);
  });

  it("re-requests after revoking the prior grant, and the old grant id stays dead", async () => {
    const findingId = await createHighFinding();
    const c = await authedClient(`req-${uniq()}`);

    const grant1 = await createGrant(c, findingId, "initial access");
    // Revoke the first grant through the real route.
    const revoke = await c.post(`/api/admin/break-glass/grants/${grant1}/revoke`, {
      reason: "wrong finding, re-requesting on a clean grant",
    });
    expect(revoke.status).toBe(200);

    // Raw read is blocked while no active grant exists.
    const readRevoked = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(readRevoked.status).toBe(403);

    // Re-request → distinct grant id; raw access restored.
    const grant2 = await createGrant(c, findingId, "re-request after revoke");
    expect(grant2).not.toBe(grant1);
    const read2 = await c.get(`/api/admin/findings/${findingId}/raw`);
    expect(read2.status).toBe(200);

    // Re-revoking the ORIGINAL grant must conflict (409) — it is already
    // terminal; the fresh grant is the only live one.
    const reRevokeOld = await c.post(
      `/api/admin/break-glass/grants/${grant1}/revoke`,
      {},
    );
    expect(reRevokeOld.status).toBe(409);
  });
});
