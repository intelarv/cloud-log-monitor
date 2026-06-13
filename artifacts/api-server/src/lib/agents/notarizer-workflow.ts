// Engine-agnostic notarizer maintenance cycle (Task: extend the WorkflowEngine
// seam beyond the supervisor review path to a periodic, durable job).
//
// PURE module: it imports ONLY the `NotarizerActivities` seam type — no DB, no
// ledger, no @temporalio SDK, no top-level side effects. That is what lets the
// Temporal workflow module (temporal-workflows.ts) import it INSIDE the
// deterministic workflow sandbox, exactly like review-orchestration.ts, while
// the real I/O (chain-verifier.runCheckpointOnce — leader lock + DB + ledger)
// lives in the activity the worker registers and runs outside the sandbox.
//
// Both engines run the SAME cycle: the in-process engine calls runCheckpointOnce
// directly on a setInterval; the Temporal engine runs `notarizationWorkflow`
// (which calls this orchestration) on a cron schedule, so the notarizer gains
// the same single-execution + crash-resume guarantees as the review workflow.

export interface NotarizerActivities {
  /** One create-checkpoint + verify-checkpoints cycle. The implementation
   *  (chain-verifier.runCheckpointOnce) is leader-locked, dedupe-guarded, and
   *  internally error-isolated, so it is designed to be re-run every cadence. */
  runCycle(): Promise<void>;
}

/** Temporal `proxyActivities` options for the notarizer cycle. Kept here (this
 *  module is pure + SDK-free) so the policy is unit-testable without the
 *  optional `@temporalio/*` packages installed.
 *
 *  `maximumAttempts: 1` = **no automatic activity retries, by design**, mirroring
 *  REVIEW_ACTIVITY_OPTIONS. The cycle appends `ledger.checkpoint_created` /
 *  `ledger.checkpoint_mismatch`; those appends are dedupe-guarded (and
 *  createCheckpoint is a no-op when the head is unchanged), but disabling retry
 *  keeps the Temporal path at-most-once-per-tick — byte-identical to the
 *  in-process setInterval, which never retries a tick. The next cron tick IS the
 *  retry, and a worker crash resumes from the last completed activity via
 *  Temporal history replay. */
export const NOTARIZER_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "5 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** The single source of truth for one notarizer tick. Trivial today (one
 *  activity) but kept behind the seam so the deterministic Temporal workflow
 *  stays free of DB/ledger imports and the cycle can grow more steps later. */
export async function runNotarizerCycle(act: NotarizerActivities): Promise<void> {
  await act.runCycle();
}
