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
// Route-level (HTTP) coverage for reopening a finding that was closed in error
// (POST /admin/findings/:id/reopen).
//
// Guarantees asserted, over the real session + step-up cookie flow:
//   - A resolved / false_positive finding transitions back to "open".
//   - The transition is ledgered `finding.reopened` under the human actor.
//   - Reopening does NOT auto-revoke break-glass grants (the inverse of
//     resolve): an active grant for the finding stays active afterwards.
//   - Reopening an already-open finding is an idempotent no-op (transitioned
//     false, no new ledger entry).
//   - Reopening an unknown finding returns 404.
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
  return `10.41.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

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
    reason: "route test reopen finding",
  });
  expect(stepUp.status).toBe(200);
  return { c, sub: loginBody.sub };
}

/** Insert a HIGH-severity finding (so a grant is active immediately — no
 *  two-person approval) with an inline raw-evidence payload. */
async function createHighFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      status: "open",
      source: `fixture:reopen:${uniq()}`,
      fingerprint: `phi:ssn:reopen:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

async function createActiveGrant(
  requester: Client,
  findingId: string,
): Promise<string> {
  const grantRes = await requester.post("/api/admin/break-glass/grants", {
    finding_id: findingId,
    justification: "route test reopen active grant",
    ttl_seconds: 600,
  });
  expect(grantRes.status).toBe(201);
  const grant = (await grantRes.json()) as {
    id: string;
    requires_second_approval: boolean;
    active: boolean;
  };
  expect(grant.requires_second_approval).toBe(false);
  expect(grant.active).toBe(true);
  return grant.id;
}

async function ledgerHeadSeq(): Promise<number> {
  const res = await db.execute(
    sql`SELECT COALESCE(MAX(seq), 0)::int AS head FROM ledger_entries`,
  );
  return Number((res.rows[0] as { head?: number }).head ?? 0);
}

async function latestLedgerEvent(
  eventType: string,
  findingId: string,
  sinceSeq: number,
): Promise<
  | {
      actor: { kind: string; id: string };
      payload: Record<string, unknown>;
    }
  | undefined
> {
  const rows = await db
    .select({
      actor: ledgerEntriesTable.actor,
      payload: ledgerEntriesTable.payload,
    })
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
  const row = rows[0];
  if (!row) return undefined;
  return {
    actor: row.actor as { kind: string; id: string },
    payload: row.payload as Record<string, unknown>,
  };
}

async function findingStatus(findingId: string): Promise<string | undefined> {
  const rows = await withTenant(TENANT, async (tx) =>
    tx
      .select({ status: findingsTable.status })
      .from(findingsTable)
      .where(eq(findingsTable.id, findingId))
      .limit(1),
  );
  return rows[0]?.status;
}

async function grantIsActive(grantId: string): Promise<boolean> {
  const rows = await db
    .select({ revokedAt: breakGlassGrantsTable.revokedAt })
    .from(breakGlassGrantsTable)
    .where(eq(breakGlassGrantsTable.id, grantId))
    .limit(1);
  return rows[0]?.revokedAt == null;
}

describe("reopen finding (HTTP)", () => {
  it("reopens a resolved finding, ledgers finding.reopened, and does NOT revoke grants", async () => {
    const findingId = await createHighFinding();
    const { c: requester, sub } = await authedClient(`req-${uniq()}`);
    const grantId = await createActiveGrant(requester, findingId);

    // Close the finding first (this auto-revokes... but we want a grant to
    // survive reopen, so create a fresh grant AFTER reopen). Here we just need
    // a closed finding to reopen, so resolve it.
    const resolve = await requester.post(
      `/api/admin/findings/${findingId}/resolve`,
      { status: "resolved" },
    );
    expect(resolve.status).toBe(200);
    expect(await findingStatus(findingId)).toBe("resolved");
    // The resolve auto-revoked the original grant.
    expect(await grantIsActive(grantId)).toBe(false);

    // Reopen the finding.
    const before = await ledgerHeadSeq();
    const reopen = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      {},
    );
    expect(reopen.status).toBe(200);
    const reopenBody = (await reopen.json()) as {
      finding_id: string;
      status: string;
      transitioned: boolean;
    };
    expect(reopenBody.transitioned).toBe(true);
    expect(reopenBody.status).toBe("open");
    expect(await findingStatus(findingId)).toBe("open");

    // The reopen is ledgered under the human actor.
    const reopened = await latestLedgerEvent(
      "finding.reopened",
      findingId,
      before,
    );
    expect(reopened).toBeDefined();
    expect(reopened!.actor.kind).toBe("human");
    expect(reopened!.actor.id).toBe(sub);
    expect(reopened!.payload["status"]).toBe("open");
  });

  it("reopening does not touch an active break-glass grant", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    // Manually mark the finding resolved at the DB layer (no auto-revoke path),
    // then grant break-glass while it is closed, then reopen and confirm the
    // grant is untouched.
    await withTenant(TENANT, async (tx) => {
      await tx
        .update(findingsTable)
        .set({ status: "false_positive" })
        .where(eq(findingsTable.id, findingId));
    });

    const grantId = await createActiveGrant(requester, findingId);
    expect(await grantIsActive(grantId)).toBe(true);

    const reopen = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      {},
    );
    expect(reopen.status).toBe(200);
    expect(((await reopen.json()) as { transitioned: boolean }).transitioned).toBe(
      true,
    );

    // The grant is still active — reopen must not revoke.
    expect(await grantIsActive(grantId)).toBe(true);
  });

  it("re-reopening an already-open finding is an idempotent no-op", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    await requester.post(`/api/admin/findings/${findingId}/resolve`, {
      status: "resolved",
    });

    const first = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      {},
    );
    expect(first.status).toBe(200);
    expect(((await first.json()) as { transitioned: boolean }).transitioned).toBe(
      true,
    );

    // Second reopen to the same state: no transition, no new ledger entry.
    const before = await ledgerHeadSeq();
    const second = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      {},
    );
    expect(second.status).toBe(200);
    expect(((await second.json()) as { transitioned: boolean }).transitioned).toBe(
      false,
    );
    expect(
      await latestLedgerEvent("finding.reopened", findingId, before),
    ).toBeUndefined();
  });

  it("reopening an unknown finding returns 404", async () => {
    const { c } = await authedClient(`req-${uniq()}`);
    const res = await c.post(
      `/api/admin/findings/does-not-exist-${uniq()}/reopen`,
      {},
    );
    expect(res.status).toBe(404);
  });

  it("records an optional free-text reason in the finding.reopened ledger payload", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    await requester.post(`/api/admin/findings/${findingId}/resolve`, {
      status: "resolved",
    });

    const before = await ledgerHeadSeq();
    const reason = "Closed by mistake during triage; still under investigation.";
    const reopen = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      { reason },
    );
    expect(reopen.status).toBe(200);
    expect(
      ((await reopen.json()) as { transitioned: boolean }).transitioned,
    ).toBe(true);

    const reopened = await latestLedgerEvent(
      "finding.reopened",
      findingId,
      before,
    );
    expect(reopened).toBeDefined();
    expect(reopened!.payload["reason"]).toBe(reason);
  });

  it("rejects a reason that scans as PHI/secrets and ledgers the refusal", async () => {
    const findingId = await createHighFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    await requester.post(`/api/admin/findings/${findingId}/resolve`, {
      status: "resolved",
    });

    const before = await ledgerHeadSeq();
    // An SSN in the reason must be refused before it can land in the ledger.
    const res = await requester.post(
      `/api/admin/findings/${findingId}/reopen`,
      { reason: "patient ssn is 123-45-6789" },
    );
    expect(res.status).toBe(400);

    // The finding stays closed — the rejected reopen did not transition it.
    expect(await findingStatus(findingId)).toBe("resolved");

    // No finding.reopened entry, but the refusal is ledgered.
    expect(
      await latestLedgerEvent("finding.reopened", findingId, before),
    ).toBeUndefined();
    const rejected = await latestLedgerEvent(
      "policy.text_field_rejected",
      findingId,
      before,
    );
    expect(rejected).toBeDefined();
    expect(rejected!.payload["field"]).toBe("reason");
  });
});
