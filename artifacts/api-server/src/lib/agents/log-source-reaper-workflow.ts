// Engine-agnostic log-source stuck-cursor reaper cycle (O2: extend the
// WorkflowEngine seam to the M8 reaper, the last standalone setInterval job).
//
// PURE module: it imports ONLY the `LogSourceReaperActivities` seam type — no
// DB, no ledger, no @temporalio SDK, no top-level side effects. That is what
// lets the Temporal workflow module (temporal-workflows.ts) import it INSIDE the
// deterministic workflow sandbox, exactly like notarizer-workflow.ts, while the
// real I/O (log-source-reaper.runReapCycleFromEnv — leader lock + DB + ledger)
// lives in the activity the worker registers and runs outside the sandbox.
//
// Both engines run the SAME cycle: the in-process engine calls runReapOnce
// directly on a setInterval; the Temporal engine runs `logSourceReaperWorkflow`
// (which calls this orchestration) on a cron schedule, so the reaper gains the
// same single-execution + crash-resume guarantees as the notarizer + review
// paths. Default-INERT either way: the activity reads the opt-in env config and
// no-ops when `INGEST_SOURCE_STALL_AFTER_MS` is unset.

export interface LogSourceReaperActivities {
  /** One stall-scan cycle. The implementation
   *  (log-source-reaper.runReapCycleFromEnv) is leader-locked, edge-triggered,
   *  and internally error-isolated, and no-ops when the reaper is disabled, so
   *  it is designed to be re-run every cadence. */
  runCycle(): Promise<void>;
}

/** Temporal `proxyActivities` options for the reaper cycle. Kept here (this
 *  module is pure + SDK-free) so the policy is unit-testable without the
 *  optional `@temporalio/*` packages installed.
 *
 *  `maximumAttempts: 1` = **no automatic activity retries, by design**, mirroring
 *  NOTARIZER_ACTIVITY_OPTIONS. The cycle is edge-triggered and only latches a
 *  source AFTER a successful `ingest.source_stalled` append, so a failed append
 *  is retried by the NEXT cron tick (at-least-once, the correct posture for a
 *  missed-PHI signal); disabling activity retry keeps the Temporal path
 *  byte-identical to the in-process setInterval, which never retries a tick. */
export const LOG_SOURCE_REAPER_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "5 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** The single source of truth for one reaper tick. Trivial today (one activity)
 *  but kept behind the seam so the deterministic Temporal workflow stays free of
 *  DB/ledger imports and the cycle can grow more steps later. */
export async function runLogSourceReaperCycle(
  act: LogSourceReaperActivities,
): Promise<void> {
  await act.runCycle();
}
