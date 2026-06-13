import { describe, it, expect, beforeAll } from "vitest";
import { createServer, type Server } from "node:http";
import { findingsTable, bootstrap } from "@workspace/db";
import app from "../app";
import { withTenant } from "../lib/db-context";
import { appendLedger } from "../lib/ledger";
import { uniq } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// Route-level (HTTP) coverage for the agent review re-run history endpoint
// (GET /findings/:id/review-history) that backs the finding detail view's
// "reviewed N times" timeline.
//
// Guarantees asserted, over the real session cookie flow:
//   - Groups triage/verifier ledger entries into numbered attempts, parsing the
//     attempt number out of each entry's `{workflowId}:attempt:N:step` key.
//   - Returns attempts most-recent-first with the latest attempt's verdicts, so
//     a verdict change across a fix-and-replay is visible.
//   - Derives a per-attempt outcome (completed / skipped / failed / incomplete).
//   - Scopes to the requested finding only.
//   - Unauthenticated requests are refused (401).
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
  async get(path: string, withCookie = true): Promise<Response> {
    const res = await fetch(`${baseUrl}${path}`, {
      headers: {
        "x-forwarded-for": this.ip,
        ...(withCookie && this.jar.size ? { cookie: this.cookieHeader() } : {}),
      },
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

async function authedClient(user: string): Promise<Client> {
  const c = new Client(nextClientIp());
  const login = await c.post("/api/auth/login", {
    username: user,
    tenant_id: TENANT,
  });
  expect(login.status).toBe(200);
  return c;
}

async function createFinding(): Promise<string> {
  const id = `f_${uniq()}`;
  await withTenant(TENANT, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId: TENANT,
      classification: "phi",
      subclass: "ssn",
      severity: "high",
      status: "open",
      source: `fixture:review-history:${uniq()}`,
      fingerprint: `phi:ssn:rh:${uniq()}:v1`,
      redactedEvidence: { snippet: "x=[REDACTED:ssn]", redactions: ["ssn"] },
      rawEvidence: { snippet: "ssn=123-45-6789" },
      rawEvidenceRef: null,
      detectorVersion: "stage1@m3",
    });
  });
  return id;
}

// Write the triage + verifier `*_complete` ledger entries for one review attempt
// with the same idempotency-key shape the orchestration uses
// (`{workflowId}:attempt:N:step`), so the endpoint can recover the attempt N.
async function seedAttempt(
  findingId: string,
  attempt: number,
  triageSeverity: string,
  verifierVerdict: string,
  agrees: boolean,
): Promise<void> {
  const wf = `wf_${findingId}`;
  await appendLedger({
    tenantId: TENANT,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.triage_complete",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      verdict: {
        recommended_severity: triageSeverity,
        recommended_action: "human_review",
        rationale: `triage attempt ${attempt}`,
        confidence: 0.8,
        prompt_injection_suspected: false,
      },
    },
    idempotencyKey: `${wf}:attempt:${attempt}:triage`,
  });
  await appendLedger({
    tenantId: TENANT,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.verifier_complete",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      verdict: {
        verdict: verifierVerdict,
        rationale: `verifier attempt ${attempt}`,
        confidence: 0.9,
        prompt_injection_suspected: false,
        agrees_with_triage: agrees,
      },
    },
    idempotencyKey: `${wf}:attempt:${attempt}:verifier`,
  });
}

type ReviewAttempt = {
  attempt: number;
  outcome: string;
  triage_verdict: { recommended_severity: string } | null;
  verifier_verdict: { verdict: string; agrees_with_triage: boolean } | null;
  triage_at: string | null;
  verifier_at: string | null;
  note: string | null;
  last_event_seq: number;
};
type ReviewHistory = { current_attempt: number; attempts: ReviewAttempt[] };

describe("finding review history (HTTP)", () => {
  it("groups attempts most-recent-first with per-attempt verdicts", async () => {
    const findingId = await createFinding();
    const c = await authedClient(`rh-${uniq()}`);

    await seedAttempt(findingId, 1, "high", "true_positive", true);
    await seedAttempt(findingId, 2, "medium", "likely_false_positive", false);

    const res = await c.get(`/api/findings/${findingId}/review-history`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as ReviewHistory;

    expect(body.current_attempt).toBe(2);
    expect(body.attempts.map((a) => a.attempt)).toEqual([2, 1]);

    const latest = body.attempts[0]!;
    expect(latest.attempt).toBe(2);
    expect(latest.outcome).toBe("completed");
    expect(latest.triage_verdict?.recommended_severity).toBe("medium");
    expect(latest.verifier_verdict?.verdict).toBe("likely_false_positive");
    expect(latest.verifier_verdict?.agrees_with_triage).toBe(false);
    expect(typeof latest.verifier_at).toBe("string");
    expect(latest.last_event_seq).toBeGreaterThan(0);

    const prior = body.attempts[1]!;
    expect(prior.triage_verdict?.recommended_severity).toBe("high");
    expect(prior.verifier_verdict?.verdict).toBe("true_positive");
  });

  it("derives skipped and failed outcomes from budget/failure events", async () => {
    const findingId = await createFinding();
    const c = await authedClient(`rh-${uniq()}`);
    const wf = `wf_${findingId}`;

    // Attempt 1: triage ran, then budget skip after triage.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.triage_complete",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        verdict: {
          recommended_severity: "low",
          recommended_action: "auto_resolve",
          rationale: "t",
          confidence: 0.5,
          prompt_injection_suspected: false,
        },
      },
      idempotencyKey: `${wf}:attempt:1:triage`,
    });
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.review_skipped_budget",
      subjectType: "finding",
      subjectId: findingId,
      payload: { finding_id: findingId, reason: "daily_token_budget_exceeded_after_triage" },
      idempotencyKey: `${wf}:attempt:1:skipped_after_triage`,
    });
    // Attempt 2: failure.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.review_failed",
      subjectType: "finding",
      subjectId: findingId,
      payload: { finding_id: findingId, error: "llm timeout" },
      idempotencyKey: `${wf}:attempt:2:review_failed`,
    });

    const res = await c.get(`/api/findings/${findingId}/review-history`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as ReviewHistory;

    expect(body.current_attempt).toBe(2);
    const failed = body.attempts.find((a) => a.attempt === 2)!;
    expect(failed.outcome).toBe("failed");
    expect(failed.note).toBe("llm timeout");
    const skipped = body.attempts.find((a) => a.attempt === 1)!;
    expect(skipped.outcome).toBe("skipped");
    expect(skipped.note).toBe("daily_token_budget_exceeded_after_triage");
  });

  it("scopes attempts to the requested finding only", async () => {
    const a = await createFinding();
    const b = await createFinding();
    const c = await authedClient(`rh-${uniq()}`);

    await seedAttempt(a, 1, "high", "true_positive", true);
    await seedAttempt(b, 1, "low", "likely_false_positive", true);

    const res = await c.get(`/api/findings/${a}/review-history`);
    const body = (await res.json()) as ReviewHistory;
    expect(body.attempts.length).toBe(1);
    expect(body.attempts[0]!.triage_verdict?.recommended_severity).toBe("high");
  });

  it("returns an empty history for a finding with no reviews", async () => {
    const findingId = await createFinding();
    const c = await authedClient(`rh-${uniq()}`);
    const res = await c.get(`/api/findings/${findingId}/review-history`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as ReviewHistory;
    expect(body.current_attempt).toBe(0);
    expect(body.attempts).toEqual([]);
  });

  it("requires an authenticated session", async () => {
    const findingId = await createFinding();
    const c = new Client(nextClientIp());
    const res = await c.get(`/api/findings/${findingId}/review-history`, false);
    expect(res.status).toBe(401);
  });
});
