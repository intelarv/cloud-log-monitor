// Engine-agnostic ledger chain-verifier cycles (Task: extend the WorkflowEngine
// seam beyond the supervisor review path to the periodic integrity walks).
//
// PURE module: it imports ONLY the `ChainVerifierActivities` seam type — no DB,
// no ledger, no @temporalio SDK, no top-level side effects. That is what lets
// the Temporal workflow module (temporal-workflows.ts) import it INSIDE the
// deterministic workflow sandbox, exactly like review-orchestration.ts and
// notarizer-workflow.ts, while the real I/O (chain-verifier.runRollingWalkOnce /
// runFullWalkOnce — leader lock + chain walk + ledger) lives in the activities
// the worker registers and runs outside the sandbox.
//
// Both engines run the SAME walks: the in-process engine calls the run-once
// helpers directly on a setInterval; the Temporal engine runs
// `chainVerifyRollingWorkflow` / `chainVerifyFullWorkflow` (which call this
// orchestration) on cron schedules, so the integrity walks gain the same
// single-execution + crash-resume guarantees as the review + notarizer paths.

export interface ChainVerifierActivities {
  /** One rolling 24h-window chain walk. The implementation
   *  (chain-verifier.runRollingWalkOnce) is leader-locked, dedupe-guarded, and
   *  internally error-isolated, so it is designed to be re-run every cadence. */
  runRollingWalk(): Promise<void>;
  /** One full-chain walk. Same leader-lock + dedupe + error-isolation posture. */
  runFullWalk(): Promise<void>;
}

/** Temporal `proxyActivities` options for the chain-verifier walks. Kept here
 *  (this module is pure + SDK-free) so the policy is unit-testable without the
 *  optional `@temporalio/*` packages installed.
 *
 *  `maximumAttempts: 1` = **no automatic activity retries, by design**, mirroring
 *  NOTARIZER_ACTIVITY_OPTIONS / REVIEW_ACTIVITY_OPTIONS. A walk appends at most a
 *  single dedupe-guarded `ledger.chain_invalid` per stable corruption signature;
 *  disabling retry keeps the Temporal path at-most-once-per-tick — byte-identical
 *  to the in-process setInterval, which never retries a tick. The next cron tick
 *  IS the retry, and a worker crash resumes from the last completed activity via
 *  Temporal history replay. */
export const CHAIN_VERIFIER_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "5 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** One rolling-window verifier tick. Kept behind the seam so the deterministic
 *  Temporal workflow stays free of DB/ledger imports. */
export async function runChainVerifierRolling(
  act: ChainVerifierActivities,
): Promise<void> {
  await act.runRollingWalk();
}

/** One full-chain verifier tick. */
export async function runChainVerifierFull(
  act: ChainVerifierActivities,
): Promise<void> {
  await act.runFullWalk();
}
