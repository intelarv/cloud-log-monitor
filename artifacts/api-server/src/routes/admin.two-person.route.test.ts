import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, desc, eq, gt, sql } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the TWO-PERSON break-glass rule on
// `critical`-severity findings — the strongest insider-threat control in the
// system (threat model §EoP "Insider threat (rogue analyst)").
//
// The approval logic is unit-/integration-tested elsewhere, but until now the
// full multi-user flow over real cookies was not exercised end-to-end. These
// tests drive the real Express app over HTTP (same Node http + fetch cookie-jar
// harness as admin.raw-evidence.route.test.ts) so a regression in the route
// wiring — pending-grant gating, second-approver path, self-approval refusal,
// or the ledger trail — can't slip through silently.
//
// Flow under test:
//   1. requester logs in + steps up + creates a grant on a CRITICAL finding
//      -> grant is born pending (`pending_approval: true`); a raw read returns
//         403 `approval_required`.
//   2. a SECOND user in the same tenant logs in + steps up + approves the
//      grant -> the requester's raw read then succeeds and ledgers
//      `break_glass.raw_phi_accessed`.
//   3. self-approval by the requester is refused (403) and ledgers
//      `break_glass.approval_denied_self_approval`.
// ---------------------------------------------------------------------------

const TENANT = "default";
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
  return `10.10.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
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
    reason: "route test two-person break-glass",
  });
  expect(stepUp.status).toBe(200);
  return { c, sub: loginBody.sub };
}

/** Insert a CRITICAL finding (so the grant flow requires two-person approval),
 *  with an inline raw-evidence payload so the post-approval read can return it. */
async function createCriticalFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "critical",
      source: `fixture:twopersontest:${uniq()}`,
      fingerprint: `phi:ssn:twoperson:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
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

/** Count ledger entries of `eventType` for `findingId` after `sinceSeq`. */
async function countLedgerEvents(
  eventType: string,
  findingId: string,
  sinceSeq: number,
): Promise<number> {
  const res = await db.execute(
    sql`SELECT COUNT(*)::int AS n FROM ledger_entries
        WHERE seq > ${sinceSeq}
          AND event_type = ${eventType}
          AND subject_id = ${findingId}`,
  );
  return Number((res.rows[0] as { n?: number }).n ?? 0);
}

describe("two-person break-glass on critical findings (HTTP)", () => {
  it("pending grant blocks raw read until a second user approves", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    // 1. Create the grant — born pending for a critical finding.
    const grantRes = await requester.post("/api/admin/break-glass/grants", {
      finding_id: findingId,
      justification: "route test two-person critical break-glass",
    });
    expect(grantRes.status).toBe(201);
    const grant = (await grantRes.json()) as {
      id: string;
      pending_approval: boolean;
      requires_second_approval: boolean;
      active: boolean;
    };
    expect(grant.requires_second_approval).toBe(true);
    expect(grant.pending_approval).toBe(true);
    expect(grant.active).toBe(false);

    // Raw read is blocked while pending.
    const blocked = await requester.get(`/api/admin/findings/${findingId}/raw`);
    expect(blocked.status).toBe(403);
    const blockedBody = (await blocked.json()) as {
      approval_required?: boolean;
      grant_id?: string;
    };
    expect(blockedBody.approval_required).toBe(true);
    expect(blockedBody.grant_id).toBe(grant.id);

    // 2. A second user in the same tenant approves the grant.
    const { c: approver } = await authedClient(`appr-${uniq()}`);

    // The approver sees the grant in their pending-approvals queue.
    const pending = await approver.get(
      "/api/admin/break-glass/pending-approvals",
    );
    expect(pending.status).toBe(200);
    const pendingList = (await pending.json()) as Array<{ id: string }>;
    expect(pendingList.some((g) => g.id === grant.id)).toBe(true);

    const approveRes = await approver.post(
      `/api/admin/break-glass/grants/${grant.id}/approve`,
      { approval_note: "second analyst sign-off for critical break-glass" },
    );
    expect(approveRes.status).toBe(200);
    const approved = (await approveRes.json()) as {
      pending_approval: boolean;
      active: boolean;
      approver_user_id: string | null;
    };
    expect(approved.pending_approval).toBe(false);
    expect(approved.active).toBe(true);
    expect(approved.approver_user_id).not.toBeNull();

    // 3. The requester's raw read now succeeds and is ledgered.
    const before = await ledgerHeadSeq();
    const readRes = await requester.get(
      `/api/admin/findings/${findingId}/raw`,
    );
    expect(readRes.status).toBe(200);
    const readBody = (await readRes.json()) as {
      raw_evidence: unknown;
      two_person_approved: boolean;
      approver_user_id: string | null;
    };
    expect(readBody.raw_evidence).not.toBeNull();
    expect(readBody.two_person_approved).toBe(true);
    expect(readBody.approver_user_id).not.toBeNull();

    expect(
      await hasLedgerEvent(
        "break_glass.raw_phi_accessed",
        findingId,
        before,
      ),
    ).toBe(true);
  });

  it("refuses self-approval by the requester and ledgers the attempt", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    const grantRes = await requester.post("/api/admin/break-glass/grants", {
      finding_id: findingId,
      justification: "route test self-approval refusal",
    });
    expect(grantRes.status).toBe(201);
    const grant = (await grantRes.json()) as { id: string };

    const before = await ledgerHeadSeq();
    const selfApprove = await requester.post(
      `/api/admin/break-glass/grants/${grant.id}/approve`,
      { approval_note: "attempting to approve my own critical grant" },
    );
    expect(selfApprove.status).toBe(403);
    const selfBody = (await selfApprove.json()) as { error?: string };
    expect(selfBody.error).toMatch(/self-approval/);

    expect(
      await hasLedgerEvent(
        "break_glass.approval_denied_self_approval",
        findingId,
        before,
      ),
    ).toBe(true);

    // And the raw read is still blocked (grant never became approved).
    const stillBlocked = await requester.get(
      `/api/admin/findings/${findingId}/raw`,
    );
    expect(stillBlocked.status).toBe(403);
    const stillBody = (await stillBlocked.json()) as {
      approval_required?: boolean;
    };
    expect(stillBody.approval_required).toBe(true);
  });

  it("two simultaneous approvers race: exactly one 200, one 409, one ledger entry", async () => {
    const findingId = await createCriticalFinding();
    const { c: requester } = await authedClient(`req-${uniq()}`);

    // Requester creates the pending critical grant.
    const grantRes = await requester.post("/api/admin/break-glass/grants", {
      finding_id: findingId,
      justification: "route test concurrent double-approve race",
    });
    expect(grantRes.status).toBe(201);
    const grant = (await grantRes.json()) as { id: string };

    // Two DISTINCT second-users in the same tenant, each fully stepped up.
    const { c: approverA } = await authedClient(`apprA-${uniq()}`);
    const { c: approverB } = await authedClient(`apprB-${uniq()}`);

    const before = await ledgerHeadSeq();

    // Fire both approvals concurrently at the SAME pending grant. The
    // compare-and-swap on `approver_user_id IS NULL` must let exactly one win.
    const [resA, resB] = await Promise.all([
      approverA.post(`/api/admin/break-glass/grants/${grant.id}/approve`, {
        approval_note: "concurrent approver A sign-off",
      }),
      approverB.post(`/api/admin/break-glass/grants/${grant.id}/approve`, {
        approval_note: "concurrent approver B sign-off",
      }),
    ]);

    const statuses = [resA.status, resB.status].sort((a, b) => a - b);
    // Exactly one winner (200) and one loser (409). No 5xx, no double-200.
    expect(statuses).toEqual([200, 409]);

    const loser = resA.status === 409 ? resA : resB;
    const loserBody = (await loser.json()) as { error?: string };
    expect(loserBody.error).toMatch(/already approved/);

    // Exactly ONE `break_glass.approved` ledger entry for this grant's finding.
    expect(
      await countLedgerEvents("break_glass.approved", findingId, before),
    ).toBe(1);

    // And the grant is now durably approved by exactly one of the two.
    const winner = resA.status === 200 ? resA : resB;
    const winnerBody = (await winner.json()) as {
      pending_approval: boolean;
      active: boolean;
      approver_user_id: string | null;
    };
    expect(winnerBody.pending_approval).toBe(false);
    expect(winnerBody.active).toBe(true);
    expect(winnerBody.approver_user_id).not.toBeNull();
  });
});
