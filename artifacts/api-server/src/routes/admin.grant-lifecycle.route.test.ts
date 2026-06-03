import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, desc, eq, gt, sql } from "drizzle-orm";
import {
  db,
  breakGlassGrantsTable,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the break-glass grant LIFECYCLE edges —
// expiry (TTL elapsed) and revocation — over the real session + step-up
// cookie flow. The two-person *approval* happy/refusal paths are covered in
// admin.two-person.route.test.ts; this file closes the gap for the lifecycle
// branches that were only ever exercised at the unit level:
//
//   - GET  /admin/findings/:id/raw filters grants on
//     `revoked_at IS NULL AND expires_at > now()`, so an expired OR revoked
//     grant must fail the raw read closed (403, break_glass_required) — the
//     grant effectively disappears from the lookup.
//   - POST /admin/break-glass/grants/:id/approve has explicit 410 branches:
//     `grant revoked` (revoked_at set) and `grant expired` (expires_at past).
//     A regression that dropped either filter/branch would silently let a
//     stale grant be approved or keep authorizing raw reads.
//
// Grants can only be created with `ttl_seconds >= 60` through the API, and a
// revoke endpoint is not exposed, so both edges are forced by writing the
// row's `expires_at` / `revoked_at` directly through the same tenant-scoped
// DB context the route uses — exactly the state the route's filters guard
// against, without sleeping out a real TTL.
// ---------------------------------------------------------------------------

const TENANT = "default";
const uniq = () => Math.random().toString(36).slice(2, 10);

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

// Minimal cookie jar over fetch (fetch does not persist Set-Cookie itself).
// Each client also presents a distinct source IP via X-Forwarded-For (the app
// runs with `trust proxy`), so the per-IP login/step-up rate limiters key on
// the client rather than on the shared 127.0.0.1 loopback — otherwise the
// cumulative step-ups across this file's tests would trip the 5/min cap.
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
/** A fresh, unique source IP per client so per-IP rate limiters don't collide. */
function nextClientIp(): string {
  ipCounter += 1;
  return `10.20.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

/** Drive login + step-up so the returned client carries both cookies. */
async function authedClient(user: string): Promise<{ c: Client; sub: string }> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  const loginBody = (await login.json()) as { sub: string };
  const stepUp = await c.post("/api/auth/step-up", {
    token: process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup",
    reason: "route test break-glass grant lifecycle",
  });
  expect(stepUp.status).toBe(200);
  return { c, sub: loginBody.sub };
}

/** Insert a CRITICAL finding (so the grant flow exposes the approve path),
 *  with an inline raw-evidence payload so a successful read could return it. */
async function createCriticalFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "critical",
      source: `fixture:lifecycletest:${uniq()}`,
      fingerprint: `phi:ssn:lifecycle:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

/** Create a pending grant on a critical finding via the real route. */
async function createPendingGrant(
  requester: Client,
  findingId: string,
): Promise<string> {
  const grantRes = await requester.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification: "route test grant lifecycle edge",
    ttl_seconds: 60,
  });
  expect(grantRes.status).toBe(201);
  const grant = (await grantRes.json()) as {
    id: string;
    requires_second_approval: boolean;
    pending_approval: boolean;
  };
  expect(grant.requires_second_approval).toBe(true);
  expect(grant.pending_approval).toBe(true);
  return grant.id;
}

/** Force the grant's `expires_at` into the past — the state a lapsed TTL
 *  produces, without waiting out the (minimum 60s) real lifetime. */
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

/** Force the grant's `revoked_at` — the state an operator revocation produces. */
async function revokeGrant(grantId: string): Promise<void> {
  await withTenant(TENANT, async (tx) => {
    await tx
      .update(breakGlassGrantsTable)
      .set({ revokedAt: new Date() })
      .where(
        and(
          eq(breakGlassGrantsTable.id, grantId),
          eq(breakGlassGrantsTable.tenantId, TENANT),
        ),
      );
  });
}

async function ledgerHeadSeq(): Promise<number> {
  const res = await db.execute(
    sql`SELECT COALESCE(MAX(seq), 0)::int AS head FROM ledger_entries`,
  );
  return Number((res.rows[0] as { head?: number }).head ?? 0);
}

/** True if a ledger entry of `eventType` for `findingId` exists after `sinceSeq`. */
async function hasLedgerEvent(
  eventType: string,
  findingId: string,
  sinceSeq: number,
): Promise<boolean> {
  const rows = await db
    .select({ seq: ledgerEntriesTable.seq })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, eventType),
        eq(ledgerEntriesTable.subjectId, findingId),
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  return rows.length > 0;
}

describe("break-glass grant lifecycle over the live login flow (HTTP)", () => {
  it("an expired grant blocks the raw read (403) and approval is rejected (410)", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);
    const grantId = await createPendingGrant(requester, findingId);

    // TTL elapses.
    await expireGrant(grantId);

    // The raw read fails closed: the expired grant is filtered out of the
    // lookup entirely, so the route reports "no active grant" (not approval).
    const readBefore = await ledgerHeadSeq();
    const read = await requester.get(`/api/admin/findings/${findingId}/raw`);
    expect(read.status).toBe(403);
    const readBody = (await read.json()) as {
      break_glass_required?: boolean;
      approval_required?: boolean;
    };
    expect(readBody.break_glass_required).toBe(true);
    // No raw access was disclosed, so nothing was ledgered for the read.
    expect(
      await hasLedgerEvent(
        "break_glass.raw_phi_accessed",
        findingId,
        readBefore,
      ),
    ).toBe(false);

    // A second user attempting to approve the now-expired grant hits the
    // dedicated 410 branch — the grant is too stale to ever be activated.
    const { c: approver } = await authedClient(`appr-${uniq()}`);
    const approve = await approver.post(
      `/api/admin/break-glass/grants/${grantId}/approve`,
      { approval_note: "attempting to approve an expired grant" },
    );
    expect(approve.status).toBe(410);
    const approveBody = (await approve.json()) as { error?: string };
    expect(approveBody.error).toMatch(/expired/);
  });

  it("a revoked grant is rejected on approval (410) and blocks the raw read (403)", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);
    const grantId = await createPendingGrant(requester, findingId);

    // Operator revokes the grant before it is ever approved.
    await revokeGrant(grantId);

    // Approval hits the dedicated 410 "grant revoked" branch.
    const { c: approver } = await authedClient(`appr-${uniq()}`);
    const approve = await approver.post(
      `/api/admin/break-glass/grants/${grantId}/approve`,
      { approval_note: "attempting to approve a revoked grant" },
    );
    expect(approve.status).toBe(410);
    const approveBody = (await approve.json()) as { error?: string };
    expect(approveBody.error).toMatch(/revoked/);

    // And the requester's raw read is blocked — the revoked grant is filtered
    // out of the lookup, so it reads as "no active grant".
    const readBefore = await ledgerHeadSeq();
    const read = await requester.get(`/api/admin/findings/${findingId}/raw`);
    expect(read.status).toBe(403);
    const readBody = (await read.json()) as { break_glass_required?: boolean };
    expect(readBody.break_glass_required).toBe(true);
    expect(
      await hasLedgerEvent(
        "break_glass.raw_phi_accessed",
        findingId,
        readBefore,
      ),
    ).toBe(false);
  });

  it("revoking via the route ledgers, blocks the raw read (403), and rejects approval (410)", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester, sub } = await authedClient(`req-${uniq()}`);
    const grantId = await createPendingGrant(requester, findingId);

    // The requester revokes their own grant through the real route.
    const before = await ledgerHeadSeq();
    const revoke = await requester.post(
      `/api/admin/break-glass/grants/${grantId}/revoke`,
      { reason: "incident resolved, no longer need raw access" },
    );
    expect(revoke.status).toBe(200);
    const revokeBody = (await revoke.json()) as {
      id: string;
      revoked_at: string | null;
      active: boolean;
    };
    expect(revokeBody.id).toBe(grantId);
    expect(revokeBody.revoked_at).not.toBeNull();
    expect(revokeBody.active).toBe(false);

    // The revocation is ledgered against the finding.
    expect(
      await hasLedgerEvent("break_glass.revoked", findingId, before),
    ).toBe(true);
    void sub;

    // After revoke, the raw read fails closed — the revoked grant is filtered
    // out of the lookup, so it reads as "no active grant".
    const readBefore = await ledgerHeadSeq();
    const read = await requester.get(`/api/admin/findings/${findingId}/raw`);
    expect(read.status).toBe(403);
    const readBody = (await read.json()) as { break_glass_required?: boolean };
    expect(readBody.break_glass_required).toBe(true);
    expect(
      await hasLedgerEvent(
        "break_glass.raw_phi_accessed",
        findingId,
        readBefore,
      ),
    ).toBe(false);

    // And a second analyst can no longer approve the now-revoked grant — the
    // dedicated 410 "grant revoked" branch fires.
    const { c: approver } = await authedClient(`appr-${uniq()}`);
    const approve = await approver.post(
      `/api/admin/break-glass/grants/${grantId}/approve`,
      { approval_note: "attempting to approve a route-revoked grant" },
    );
    expect(approve.status).toBe(410);
    const approveBody = (await approve.json()) as { error?: string };
    expect(approveBody.error).toMatch(/revoked/);
  });

  it("revoking an already-revoked grant returns 409, and an expired grant 410", async () => {
    // Already-revoked → 409 conflict.
    const findingA = await createCriticalFinding();
    const { c: reqA } = await authedClient(`req-${uniq()}`);
    const grantA = await createPendingGrant(reqA, findingA);
    const first = await reqA.post(
      `/api/admin/break-glass/grants/${grantA}/revoke`,
      {},
    );
    expect(first.status).toBe(200);
    const second = await reqA.post(
      `/api/admin/break-glass/grants/${grantA}/revoke`,
      {},
    );
    expect(second.status).toBe(409);
    const secondBody = (await second.json()) as { error?: string };
    expect(secondBody.error).toMatch(/already revoked/);

    // Expired (terminal) → 410 gone.
    const findingB = await createCriticalFinding();
    const { c: reqB } = await authedClient(`req-${uniq()}`);
    const grantB = await createPendingGrant(reqB, findingB);
    await expireGrant(grantB);
    const revokeExpired = await reqB.post(
      `/api/admin/break-glass/grants/${grantB}/revoke`,
      {},
    );
    expect(revokeExpired.status).toBe(410);
    const expiredBody = (await revokeExpired.json()) as { error?: string };
    expect(expiredBody.error).toMatch(/expired/);
  });
});
