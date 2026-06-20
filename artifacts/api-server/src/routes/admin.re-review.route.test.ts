import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { and, desc, eq, gt } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the operator-initiated re-review (replay)
// endpoint (POST /admin/findings/:id/re-review).
//
// Guarantees asserted, over the real session cookie flow:
//   - A finding whose review has completed/failed/skipped is reset to "pending"
//     and the replay is ledgered `agent.re_review_requested` under the human
//     actor (carrying who + previous_status).
//   - The agent_review_attempt counter is NOT reset by the endpoint (the
//     supervisor's acquireFinding CAS bumps it when the queued review runs).
//   - An optional free-text reason is recorded in the ledger payload.
//   - A reason that scans as PHI/secrets is refused (400) + ledgered, and the
//     finding's review status is left untouched.
//   - A finding whose review is in_progress is refused with 409 (a replay must
//     not clobber a run mid-flight).
//   - Re-reviewing an unknown finding returns 404.
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
}

let ipCounter = 0;
function nextClientIp(): string {
  ipCounter += 1;
  return `10.43.${(ipCounter >> 8) & 0xff}.${ipCounter & 0xff}`;
}

async function authedClient(user: string): Promise<{ c: Client; sub: string }> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  const loginBody = (await login.json()) as { sub: string };
  return { c, sub: loginBody.sub };
}

/** Insert a finding with the given agent_review_status (default "completed"),
 *  starting from a non-zero attempt so we can assert the endpoint leaves the
 *  attempt counter alone. */
async function createReviewedFinding(
  status = "completed",
  attempt = 2,
): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      status: "open",
      source: `fixture:re-review:${uniq()}`,
      fingerprint: `phi:ssn:re-review:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
      agentReviewStatus: status,
      agentReviewAttempt: attempt,
    });
  });
  return id;
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

async function reviewState(
  findingId: string,
): Promise<{ status: string; attempt: number } | undefined> {
  const rows = await withTenant(TENANT, async (tx) =>
    tx
      .select({
        status: findingsTable.agentReviewStatus,
        attempt: findingsTable.agentReviewAttempt,
      })
      .from(findingsTable)
      .where(eq(findingsTable.id, findingId))
      .limit(1),
  );
  const row = rows[0];
  return row ? { status: row.status, attempt: row.attempt } : undefined;
}

describe("re-review finding (HTTP)", () => {
  it("resets a completed review to pending, ledgers the replay, and leaves the attempt counter alone", async () => {
    const findingId = await createReviewedFinding("completed", 2);
    const { c, sub } = await authedClient(`op-${uniq()}`);

    const before = await ledgerHeadSeq();
    const res = await c.post(`/api/admin/findings/${findingId}/re-review`, {});
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      finding_id: string;
      agent_review_status: string;
      enqueued: boolean;
    };
    expect(body.finding_id).toBe(findingId);
    expect(body.agent_review_status).toBe("pending");
    expect(body.enqueued).toBe(true);

    // Status reset to pending; the endpoint must NOT reset the attempt counter
    // (the supervisor CAS bumps it when the queued review actually runs).
    const state = await reviewState(findingId);
    expect(state?.status).toBe("pending");
    expect(state?.attempt).toBe(2);

    const led = await latestLedgerEvent(
      "agent.re_review_requested",
      findingId,
      before,
    );
    expect(led).toBeDefined();
    expect(led!.actor.kind).toBe("human");
    expect(led!.actor.id).toBe(sub);
    expect(led!.payload["requested_by"]).toBe(sub);
    expect(led!.payload["previous_status"]).toBe("completed");
  });

  it("records an optional free-text reason in the ledger payload", async () => {
    const findingId = await createReviewedFinding("failed", 1);
    const { c } = await authedClient(`op-${uniq()}`);

    const before = await ledgerHeadSeq();
    const reason = "Detector was updated; re-running analysis on this finding.";
    const res = await c.post(`/api/admin/findings/${findingId}/re-review`, {
      reason,
    });
    expect(res.status).toBe(200);

    const led = await latestLedgerEvent(
      "agent.re_review_requested",
      findingId,
      before,
    );
    expect(led).toBeDefined();
    expect(led!.payload["reason"]).toBe(reason);
  });

  it("rejects a reason that scans as PHI/secrets and leaves review status untouched", async () => {
    const findingId = await createReviewedFinding("completed", 1);
    const { c } = await authedClient(`op-${uniq()}`);

    const before = await ledgerHeadSeq();
    const res = await c.post(`/api/admin/findings/${findingId}/re-review`, {
      reason: "patient ssn is 123-45-6789",
    });
    expect(res.status).toBe(400);

    // The finding's review state is untouched — the rejected replay did not
    // reset it to pending.
    expect((await reviewState(findingId))?.status).toBe("completed");

    // No replay event, but the refusal is ledgered.
    expect(
      await latestLedgerEvent("agent.re_review_requested", findingId, before),
    ).toBeUndefined();
    const rejected = await latestLedgerEvent(
      "policy.text_field_rejected",
      findingId,
      before,
    );
    expect(rejected).toBeDefined();
    expect(rejected!.payload["field"]).toBe("reason");
  });

  it("refuses with 409 when a review is already in progress", async () => {
    const findingId = await createReviewedFinding("in_progress", 1);
    const { c } = await authedClient(`op-${uniq()}`);

    const res = await c.post(`/api/admin/findings/${findingId}/re-review`, {});
    expect(res.status).toBe(409);

    // Unchanged — the in-flight run is not clobbered.
    expect((await reviewState(findingId))?.status).toBe("in_progress");
  });

  it("re-reviewing an unknown finding returns 404", async () => {
    const { c } = await authedClient(`op-${uniq()}`);
    const res = await c.post(
      `/api/admin/findings/does-not-exist-${uniq()}/re-review`,
      {},
    );
    expect(res.status).toBe(404);
  });

  // #97: per-user + per-finding rate limit. Each replay re-runs the
  // Triage->Verifier LLM pipeline (real token cost), so a single analyst
  // hammering replay on one finding is throttled at 5/min BEFORE it reaches
  // the per-tenant budget breaker. The key is user+finding, so the throttle is
  // surgical: a burst on finding A must never starve a legitimate replay of
  // finding B, and a different analyst must not inherit A's counter.
  it("rate-limits a single analyst hammering replay on ONE finding (5/min)", async () => {
    const findingId = await createReviewedFinding("completed", 1);
    const { c } = await authedClient(`op-${uniq()}`);

    // The endpoint resets to "pending" and re-enqueues; a "pending" finding is
    // still replayable (only "in_progress" is refused), so the first 5 calls
    // all succeed and exercise the limiter's allowance.
    for (let i = 0; i < 5; i++) {
      const ok = await c.post(`/api/admin/findings/${findingId}/re-review`, {});
      expect(ok.status).toBe(200);
    }
    const limited = await c.post(
      `/api/admin/findings/${findingId}/re-review`,
      {},
    );
    expect(limited.status).toBe(429);
  });

  it("scopes the re-review limit per finding — a burst on one finding does not throttle another", async () => {
    const findingA = await createReviewedFinding("completed", 1);
    const findingB = await createReviewedFinding("completed", 1);
    const { c } = await authedClient(`op-${uniq()}`);

    // Exhaust the allowance for finding A.
    for (let i = 0; i < 5; i++) {
      await c.post(`/api/admin/findings/${findingA}/re-review`, {});
    }
    expect(
      (await c.post(`/api/admin/findings/${findingA}/re-review`, {})).status,
    ).toBe(429);

    // The SAME analyst can still replay a DIFFERENT finding — the counter is
    // keyed by user+finding, not user alone.
    expect(
      (await c.post(`/api/admin/findings/${findingB}/re-review`, {})).status,
    ).toBe(200);
  });

  it("scopes the re-review limit per analyst — one analyst's burst does not throttle another", async () => {
    const findingId = await createReviewedFinding("completed", 1);
    const { c: c1 } = await authedClient(`op-${uniq()}`);
    const { c: c2 } = await authedClient(`op-${uniq()}`);

    for (let i = 0; i < 5; i++) {
      await c1.post(`/api/admin/findings/${findingId}/re-review`, {});
    }
    expect(
      (await c1.post(`/api/admin/findings/${findingId}/re-review`, {})).status,
    ).toBe(429);

    // A different analyst replaying the SAME finding has their own allowance.
    expect(
      (await c2.post(`/api/admin/findings/${findingId}/re-review`, {})).status,
    ).toBe(200);
  });
});
