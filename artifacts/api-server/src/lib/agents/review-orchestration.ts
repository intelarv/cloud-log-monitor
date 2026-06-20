// Engine-agnostic, replayable per-finding review orchestration.
//
// This module is PURE: it imports ONLY types and the `ReviewActivities` seam.
// It performs no I/O itself — every side effect (DB CAS, LLM invoke, PHI scan,
// ledger write, budget charge, persist) lives behind an activity. That is what
// lets the SAME orchestration run two ways with identical semantics:
//
//   - In-process engine: activities are direct function calls (review-steps.ts).
//   - Temporal engine:    activities are `proxyActivities` stubs invoked from a
//                         deterministic workflow (temporal-workflows.ts). The
//                         workflow may import THIS file because it is free of
//                         non-deterministic top-level code and side-effecting
//                         imports — a hard requirement of the Temporal sandbox.
//
// CRITICAL invariants preserved from the original `reviewOne`:
//   - PHI-scan-before-ledger ordering (enforced inside the triage/verifier
//     step activities, which scan rationale BEFORE the agent.*_complete write).
//   - Per-tenant budget breaker with an inter-step recheck between triage and
//     verifier (the recheck result rides back on the triage step result).
//   - Partial-verdict failure handling: on any step throw, persist 'failed'
//     with whatever partial verdicts exist + ledger agent.review_failed.
//   - CAS exactly-once acquire (pending -> in_progress); a re-entry is a no-op.

import type { FindingSafe } from "@workspace/db";
import type { TriageVerdict } from "./triage";
import type { VerifierVerdict } from "./verifier";
import type { ContextVerdict } from "./context";
import type { NotifierDraft } from "./notifier";

export interface ReviewJob {
  findingId: string;
  tenantId: string;
  /** M23: when true (AGENT_PIPELINE_EXTENDED), run Context + Notifier after the
   *  Triage→Verifier core. Undefined/false ⇒ orchestration byte-identical to the
   *  default two-agent path; the extra steps are never invoked. */
  extendedPipeline?: boolean;
}

export interface BudgetCheck {
  exceeded: boolean;
  tokensUsedToday: number;
}

export interface TriageStepResult {
  /** PHI-sanitized triage verdict (the rationale is replaced if PHI was hit). */
  triage: TriageVerdict;
  /** Budget recheck AFTER charging the triage call — drives the inter-step skip. */
  budgetExceededAfter: boolean;
  tokensUsedToday: number;
}

export interface VerifierStepResult {
  /** PHI-sanitized verifier verdict. */
  verifier: VerifierVerdict;
}

export interface ContextStepResult {
  /** PHI-sanitized context verdict. */
  context: ContextVerdict;
}

export interface NotifierStepResult {
  /** PHI-sanitized notification draft. */
  notifier: NotifierDraft;
}

/** The replayable units the orchestration depends on. Both engines provide an
 *  implementation; Temporal activity args/results must be JSON-serializable,
 *  which `FindingSafe` and the verdict objects are (the agents only consume the
 *  redacted projection fields). */
export interface ReviewActivities {
  /** CAS pending -> in_progress. Returns the redacted finding or null if the
   *  work was already taken (idempotency win). */
  acquireFinding(job: ReviewJob): Promise<FindingSafe | null>;
  /** Pre-flight budget read (before any LLM call). */
  checkBudgetPre(job: ReviewJob): Promise<BudgetCheck>;
  /** Persist status='skipped' (no verdicts) + ledger review_skipped_budget. The
   *  `attempt` (from the acquired finding) keys the ledger write per replay. */
  persistSkippedPreBudget(
    job: ReviewJob,
    attempt: number,
    tokensUsedToday: number,
  ): Promise<void>;
  /** Triage LLM call + charge + PHI-scan + ledger agent.triage_complete. Keys
   *  its ledger writes off `finding.agentReviewAttempt`. */
  triageStep(job: ReviewJob, finding: FindingSafe): Promise<TriageStepResult>;
  /** Persist status='skipped' (triage only) + ledger review_skipped_budget. */
  persistSkippedAfterTriage(
    job: ReviewJob,
    attempt: number,
    triage: TriageVerdict,
    tokensUsedToday: number,
  ): Promise<void>;
  /** Verifier LLM call + charge + PHI-scan + ledger agent.verifier_complete. */
  verifierStep(
    job: ReviewJob,
    finding: FindingSafe,
    triage: TriageVerdict,
  ): Promise<VerifierStepResult>;
  /** Persist status='completed' with both verdicts (no ledger event — the
   *  agent.*_complete events were already written by the steps). */
  persistCompleted(
    job: ReviewJob,
    triage: TriageVerdict,
    verifier: VerifierVerdict,
  ): Promise<void>;
  /** M23 (extended pipeline only): Context LLM call + charge + PHI-scan + ledger
   *  agent.context_complete. Optional on the seam so the default two-agent path
   *  needs no implementation; present only via inProcessReviewActivities. */
  contextStep?(
    job: ReviewJob,
    finding: FindingSafe,
  ): Promise<ContextStepResult>;
  /** M23 (extended pipeline only): Notifier LLM call + charge + PHI-scan + ledger
   *  agent.notify_drafted. DRAFTS only — never sends. */
  notifierStep?(
    job: ReviewJob,
    finding: FindingSafe,
    triage: TriageVerdict,
    verifier: VerifierVerdict,
    context: ContextVerdict,
  ): Promise<NotifierStepResult>;
  /** Persist status='failed' with partial verdicts + ledger review_failed. */
  persistFailed(
    job: ReviewJob,
    attempt: number,
    triage: TriageVerdict | null,
    verifier: VerifierVerdict | null,
    errorMessage: string,
  ): Promise<void>;
}

/** Temporal `proxyActivities` options for the review workflow. Kept HERE (this
 *  module is pure + SDK-free) so the policy is unit-testable without the
 *  `@temporalio/*` packages installed, and so the workflow module stays a thin
 *  shim.
 *
 *  **Bounded automatic retry is enabled** so transient activity failures (LLM
 *  timeout, A2A blip, DB hiccup) self-heal instead of dropping a finding into
 *  `failed` for manual replay. This is safe because each side-effecting step is
 *  now idempotent: the activities (review-steps.ts) derive a per-step key from
 *  `workflowIdFor(tenantId, findingId)` + the step name and pass it as
 *  `appendLedger`'s `idempotencyKey`. `appendLedger` dedupes on the ledger's
 *  `ledger_idempotency_key_uniq` index inside its advisory-locked txn, so a
 *  retried step that already wrote its `agent.*_complete` entry is a no-op (the
 *  recorded verdict is recovered from that entry; no LLM re-call, no duplicate
 *  audit row, no post-commit re-fan-out). The per-tenant budget charge is
 *  ordered AFTER the dedupe-gate ledger write, so a crash-then-retry charges
 *  exactly once (the only residual is a rare single-step undercount if a crash
 *  lands in the tiny window between the ledger write and the charge — acceptable
 *  for the per-process best-effort budget). Exactly-once-per-finding is still
 *  additionally guarded by `acquireFinding`'s CAS + Temporal's workflow-id
 *  idempotency, and worker failover still resumes from COMPLETED activities via
 *  history replay. The in-process engine never retries, so its dedupe check
 *  always misses and its behavior — and the credential-free eval gate — stay
 *  byte-identical. */
export const REVIEW_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "2 minutes",
  retry: {
    maximumAttempts: 5,
    initialInterval: "1 second",
    backoffCoefficient: 2,
    maximumInterval: "30 seconds",
  },
} as const;

function errorMessage(err: unknown): string {
  return (err as Error)?.message?.slice(0, 500) ?? "unknown";
}

/** The single source of truth for the per-finding review sequence. Mirrors the
 *  original `reviewOne` step-for-step; only the I/O is behind the seam. */
export async function runReviewOrchestration(
  job: ReviewJob,
  act: ReviewActivities,
): Promise<void> {
  const finding = await act.acquireFinding(job);
  if (!finding) {
    // Already reviewed or in progress. Idempotency win — no ledger write for
    // this silent-skip because the original finding.created already exists in
    // the ledger as the audit anchor.
    return;
  }
  // The attempt number was bumped by acquireFinding's CAS and is now fixed for
  // this whole execution. Capturing it once here (and passing it to the skip/
  // fail steps; the triage/verifier steps read it off `finding`) keeps every
  // per-step ledger key consistent within the attempt, so transient retries
  // dedupe while a manual replay (which re-acquired with a higher attempt) is a
  // clean re-run.
  const attempt = finding.agentReviewAttempt;

  // Cost-budget circuit breaker (pre-flight). Skip cleanly, mark
  // status='skipped' so the dashboard can surface it, and ledger the skip.
  const pre = await act.checkBudgetPre(job);
  if (pre.exceeded) {
    await act.persistSkippedPreBudget(job, attempt, pre.tokensUsedToday);
    return;
  }

  let triage: TriageVerdict | null = null;
  let verifier: VerifierVerdict | null = null;
  try {
    const t = await act.triageStep(job, finding);
    triage = t.triage;

    // Re-check the budget BETWEEN triage and verifier. With CONCURRENCY>1,
    // multiple jobs can each pass the pre-check then both run LLM calls before
    // any charges land — overshooting the cap. Re-checking halves the overshoot
    // window. The triage verdict is already persisted via the skip path below.
    if (t.budgetExceededAfter) {
      await act.persistSkippedAfterTriage(job, attempt, triage, t.tokensUsedToday);
      return;
    }

    const v = await act.verifierStep(job, finding, triage);
    verifier = v.verifier;

    // M23 extended pipeline (AGENT_PIPELINE_EXTENDED only): Context then Notifier
    // run AFTER the core Triage→Verifier verdicts are settled. Guarded so the
    // default path is byte-identical — when the flag is off (or the activities
    // are absent on the seam) this whole block is skipped and we fall straight
    // through to persistCompleted with the two core verdicts. The Notifier only
    // DRAFTS (never sends); HITL is preserved. A throw here routes to the same
    // catch→persistFailed as the core steps, persisting partial verdicts.
    if (job.extendedPipeline && act.contextStep && act.notifierStep) {
      const c = await act.contextStep(job, finding);
      const n = await act.notifierStep(job, finding, triage, verifier, c.context);
      // The Context/Notifier verdicts are recorded via their own ledger events
      // inside the steps; the finding row persists only triage+verifier (the
      // schema's verdict columns), so persistCompleted is unchanged.
      void n;
    }

    await act.persistCompleted(job, triage, verifier);
  } catch (err) {
    // Mark failed (NOT back to pending — avoid infinite retry loops on a
    // permanently malformed finding) and ledger the failure with the last-good
    // partial verdicts if any. Operators replay manually after fixing root
    // cause. Under Temporal, each activity is now auto-retried with bounded
    // backoff (see REVIEW_ACTIVITY_OPTIONS) because the steps are per-step
    // idempotent, so this catch fires only on a PERMANENT failure (retries
    // exhausted); the in-process engine never retries, so it reaches here on the
    // first step failure — both end in the same idempotent persistFailed write.
    await act.persistFailed(job, attempt, triage, verifier, errorMessage(err));
  }
}
