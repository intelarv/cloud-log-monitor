// Engine-agnostic remediation-execution cycle (Task: executing remediation
// worker on the WorkflowEngine seam).
//
// PURE module: imports ONLY the `RemediationExecutionActivities` seam type — no
// DB, no ledger, no executor, no @temporalio SDK, no top-level side effects.
// That is what lets the Temporal workflow module (temporal-workflows.ts) import
// it inside the deterministic workflow sandbox, exactly like
// review-orchestration.ts / notarizer-workflow.ts / chain-verifier-workflow.ts,
// while the real I/O (remediation-worker.runRemediationExecutionTick — leader
// lock + DB + executor + ledger) lives in the activity the worker registers and
// runs outside the sandbox.
//
// Both engines run the SAME cycle: the in-process engine calls
// runRemediationExecutionOnce directly on a setInterval; the Temporal engine
// runs `remediationExecutionWorkflow` (which calls this orchestration) on a cron
// schedule, so the worker gains the same single-execution + crash-resume
// guarantees on top of its own leader lock + per-row CAS.

export interface RemediationExecutionActivities {
  /** One confirmed→executing→executed|failed sweep across all tenants. The
   *  implementation (remediation-worker.runRemediationExecutionTick) is
   *  leader-locked, CAS-guarded, idempotent (executed rows are never re-acted),
   *  and default-inert when REMEDIATION_EXECUTOR is unset, so it is safe to
   *  re-run every cadence. */
  runCycle(): Promise<void>;
}

/** Temporal `proxyActivities` options. `maximumAttempts: 1` = no automatic
 *  activity retry, by design, mirroring NOTARIZER_ACTIVITY_OPTIONS: the sweep is
 *  self-contained + leader-locked, claimed rows that fail land in
 *  `execution_failed` (a terminal, audited state), and the next cron tick is the
 *  retry. A worker crash resumes via Temporal history replay. */
export const REMEDIATION_EXECUTION_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "5 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** Single source of truth for one execution tick. Trivial today (one activity)
 *  but kept behind the seam so the deterministic Temporal workflow stays free of
 *  DB/ledger/executor imports and the cycle can grow steps later. */
export async function runRemediationExecutionCycle(
  act: RemediationExecutionActivities,
): Promise<void> {
  await act.runCycle();
}
