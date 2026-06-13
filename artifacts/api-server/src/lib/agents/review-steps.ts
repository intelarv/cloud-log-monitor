// Activity implementations for the per-finding review orchestration.
//
// These are the side-effecting units the pure orchestration (review-orchestration.ts)
// calls through the `ReviewActivities` seam. They do real I/O — DB CAS, LLM
// invoke via the AgentInvoker, PHI scan, ledger writes, budget charge — so they
// run in a normal Node context: the in-process engine calls them directly, and
// the Temporal worker registers THIS object as its activity set (activities run
// in the worker process, never inside the deterministic workflow sandbox).
//
// Every ledger event type emitted here is unchanged from the original reviewOne
// (agent.triage_complete / agent.verifier_complete / agent.output_phi_detected /
// agent.review_skipped_budget / agent.review_failed), so no new alert-coverage
// entries are needed and the eval gate stays byte-identical on the default path.

import { and, eq, sql } from "drizzle-orm";
import {
  db,
  findingsTable,
  findingSafeColumns,
  type FindingSafe,
} from "@workspace/db";
import { withTenant } from "../db-context";
import {
  appendLedger,
  appendLedgerWithStatus,
  getLedgerEntryByIdempotencyKey,
} from "../ledger";
import { scanForPhi } from "../redact";
import { getAgentInvoker } from "../a2a";
import { workflowIdFor } from "./workflow-id";
import { triageAgentIdentity, type TriageVerdict } from "./triage";
import { verifierAgentIdentity, type VerifierVerdict } from "./verifier";
import {
  budgetExceeded,
  chargeBudget,
  DAILY_TOKEN_BUDGET,
  tokensUsedToday,
} from "./agent-budget";
import type {
  BudgetCheck,
  ReviewActivities,
  ReviewJob,
  TriageStepResult,
  VerifierStepResult,
} from "./review-orchestration";

const REDACTED_RATIONALE = "<REDACTED: agent output contained PHI/secrets>";

// Stable per-step idempotency key = the workflow id (a hash of
// {tenantId, findingId}) + the review ATTEMPT number + a `:step` suffix. Two
// invariants ride on the attempt segment:
//   - Within ONE review execution every step shares the same attempt (captured
//     once by acquireFinding's CAS), so a transient activity auto-retry that
//     already landed its entry is deduped by the ledger's `idempotency_key`
//     unique index instead of writing a duplicate audit record / re-calling the
//     LLM — this is what makes auto-retry safe (REVIEW_ACTIVITY_OPTIONS).
//   - A manual operator replay (reset status to 'pending' + re-enqueue) takes a
//     FRESH attempt via the CAS increment, so its keys no longer collide with
//     the prior attempt's entries and the agents re-run from scratch.
function stepKey(job: ReviewJob, step: string, attempt: number): string {
  return `${workflowIdFor(job.tenantId, job.findingId)}:attempt:${attempt}:${step}`;
}

// CAS: pending -> in_progress, atomically bumping the per-finding attempt
// counter so each (re)start gets a distinct attempt the steps key off of.
// Returns the row (with the freshly-incremented `agentReviewAttempt`) or null
// if the work was already taken. Because the bump rides the same CAS, a
// transient retry of a LATER step never re-runs this — the attempt stays fixed
// for the whole execution — while a manual replay re-enters here and increments.
async function acquireFinding(job: ReviewJob): Promise<FindingSafe | null> {
  const { tenantId, findingId } = job;
  return withTenant(tenantId, async (tx) => {
    const updated = await tx
      .update(findingsTable)
      .set({
        agentReviewStatus: "in_progress",
        agentReviewAttempt: sql`${findingsTable.agentReviewAttempt} + 1`,
      })
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, tenantId),
          eq(findingsTable.agentReviewStatus, "pending"),
        ),
      )
      .returning(findingSafeColumns);
    return updated[0] ?? null;
  });
}

async function persistStatus(
  tenantId: string,
  findingId: string,
  status: "completed" | "failed" | "skipped",
  triage: TriageVerdict | null,
  verifier: VerifierVerdict | null,
): Promise<void> {
  await withTenant(tenantId, async (tx) => {
    await tx
      .update(findingsTable)
      .set({
        agentReviewStatus: status,
        triageVerdict: triage,
        verifierVerdict: verifier,
        lastAgentReviewAt: new Date(),
      })
      .where(
        and(eq(findingsTable.id, findingId), eq(findingsTable.tenantId, tenantId)),
      );
  });
}

async function checkBudgetPre(job: ReviewJob): Promise<BudgetCheck> {
  return {
    exceeded: budgetExceeded(job.tenantId),
    tokensUsedToday: tokensUsedToday(job.tenantId),
  };
}

async function persistSkippedPreBudget(
  job: ReviewJob,
  attempt: number,
  tokens: number,
): Promise<void> {
  const { tenantId, findingId } = job;
  await persistStatus(tenantId, findingId, "skipped", null, null);
  await appendLedger({
    tenantId,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.review_skipped_budget",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      reason: "daily_token_budget_exceeded",
      tokens_used_today: tokens,
      daily_budget: DAILY_TOKEN_BUDGET,
    },
    idempotencyKey: stepKey(job, "skipped_pre_budget", attempt),
  });
}

async function triageStep(
  job: ReviewJob,
  finding: FindingSafe,
): Promise<TriageStepResult> {
  const { tenantId, findingId } = job;
  const attempt = finding.agentReviewAttempt;
  const completeKey = stepKey(job, "triage", attempt);

  // Idempotency gate: if this step already landed its agent.triage_complete
  // entry on a prior attempt, recover the (possibly PHI-redacted) verdict from
  // that entry and return WITHOUT re-calling the LLM, re-charging the budget,
  // or re-writing the ledger. Under Temporal auto-retry this turns a step that
  // crashed AFTER its complete-ledger write into an exactly-once no-op. The
  // budget reads are recomputed live (they are reads, not side effects).
  const existing = await getLedgerEntryByIdempotencyKey(completeKey);
  if (existing) {
    const triage = (existing.payload as { verdict: TriageVerdict }).verdict;
    return {
      triage,
      budgetExceededAfter: budgetExceeded(tenantId),
      tokensUsedToday: tokensUsedToday(tenantId),
    };
  }

  const invoker = getAgentInvoker();
  const t = await invoker.triage(finding);
  let triage = t.verdict;

  // PHI scan on agent rationale MUST happen BEFORE the rationale lands in the
  // append-only ledger (the ledger is immutable). Scan and, if hit, replace the
  // rationale before the agent.triage_complete write that includes it.
  const hits = scanForPhi(triage.rationale);
  if (hits.length > 0) {
    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.output_phi_detected",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        stage: "triage",
        detectors: Array.from(new Set(hits.map((h) => h.detector))),
        agent_identity: triageAgentIdentity(t.modelId),
      },
      idempotencyKey: stepKey(job, "triage:phi", attempt),
    });
    triage = { ...triage, rationale: REDACTED_RATIONALE };
  }

  const { deduped } = await appendLedgerWithStatus({
    tenantId,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.triage_complete",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      agent_identity: triageAgentIdentity(t.modelId),
      verdict: triage,
      approx_output_tokens: t.approxOutputTokens,
    },
    idempotencyKey: completeKey,
  });

  // Charge AFTER, and ONLY IF, this call performed the complete-ledger INSERT
  // (the dedupe gate). The advisory lock serializes the write, so when two
  // attempts run concurrently exactly one observes `deduped===false` and
  // charges — the other skips, giving exactly-once charging even under
  // overlapping duplicate executions. A retry that finds the entry already
  // present short-circuits at the top of the step and never reaches here. The
  // only residual is a rare single-step undercount if the activity crashes in
  // the narrow window between the write and this line — acceptable for the
  // per-process best-effort budget; it is never a double-charge.
  if (!deduped) chargeBudget(tenantId, t.approxOutputTokens);

  return {
    triage,
    budgetExceededAfter: budgetExceeded(tenantId),
    tokensUsedToday: tokensUsedToday(tenantId),
  };
}

async function persistSkippedAfterTriage(
  job: ReviewJob,
  attempt: number,
  triage: TriageVerdict,
  tokens: number,
): Promise<void> {
  const { tenantId, findingId } = job;
  await persistStatus(tenantId, findingId, "skipped", triage, null);
  await appendLedger({
    tenantId,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.review_skipped_budget",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      reason: "daily_token_budget_exceeded_after_triage",
      tokens_used_today: tokens,
      daily_budget: DAILY_TOKEN_BUDGET,
    },
    idempotencyKey: stepKey(job, "skipped_after_triage", attempt),
  });
}

async function verifierStep(
  job: ReviewJob,
  finding: FindingSafe,
  triage: TriageVerdict,
): Promise<VerifierStepResult> {
  const { tenantId, findingId } = job;
  const attempt = finding.agentReviewAttempt;
  const completeKey = stepKey(job, "verifier", attempt);

  // Same idempotency gate as triageStep: recover the recorded verdict from a
  // prior attempt's agent.verifier_complete entry and short-circuit so a retry
  // does not re-call the LLM, re-charge, or duplicate the audit entry.
  const existing = await getLedgerEntryByIdempotencyKey(completeKey);
  if (existing) {
    const verifier = (existing.payload as { verdict: VerifierVerdict }).verdict;
    return { verifier };
  }

  const invoker = getAgentInvoker();
  const v = await invoker.verify(finding, triage);
  let verifier = v.verdict;

  const hits = scanForPhi(verifier.rationale);
  if (hits.length > 0) {
    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.output_phi_detected",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        stage: "verifier",
        detectors: Array.from(new Set(hits.map((h) => h.detector))),
        agent_identity: verifierAgentIdentity(v.modelId),
      },
      idempotencyKey: stepKey(job, "verifier:phi", attempt),
    });
    verifier = { ...verifier, rationale: REDACTED_RATIONALE };
  }

  const { deduped } = await appendLedgerWithStatus({
    tenantId,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.verifier_complete",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      agent_identity: verifierAgentIdentity(v.modelId),
      verdict: verifier,
      approx_output_tokens: v.approxOutputTokens,
    },
    idempotencyKey: completeKey,
  });

  // Charge after, and only if, this call performed the dedupe-gate INSERT — see
  // triageStep for the exactly-once-under-concurrency reasoning.
  if (!deduped) chargeBudget(tenantId, v.approxOutputTokens);

  return { verifier };
}

async function persistCompleted(
  job: ReviewJob,
  triage: TriageVerdict,
  verifier: VerifierVerdict,
): Promise<void> {
  await persistStatus(job.tenantId, job.findingId, "completed", triage, verifier);
}

async function persistFailed(
  job: ReviewJob,
  attempt: number,
  triage: TriageVerdict | null,
  verifier: VerifierVerdict | null,
  errorMessage: string,
): Promise<void> {
  const { tenantId, findingId } = job;
  await persistStatus(tenantId, findingId, "failed", triage, verifier);
  await appendLedger({
    tenantId,
    actor: { kind: "system", id: "supervisor" },
    eventType: "agent.review_failed",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      error: errorMessage,
      had_triage: triage !== null,
      had_verifier: verifier !== null,
    },
    idempotencyKey: stepKey(job, "review_failed", attempt),
  });
}

/** The concrete activity set. Shared by the in-process engine (called directly)
 *  and the Temporal worker (registered as its activities). */
export const inProcessReviewActivities: ReviewActivities = {
  acquireFinding,
  checkBudgetPre,
  persistSkippedPreBudget,
  triageStep,
  persistSkippedAfterTriage,
  verifierStep,
  persistCompleted,
  persistFailed,
};
