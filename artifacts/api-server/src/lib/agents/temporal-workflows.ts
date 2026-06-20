// Temporal workflow module (loaded ONLY by the Temporal worker's own bundler,
// never by the main app's tsc graph or esbuild entry-import graph).
//
// IMPORTANT — why this file is special:
//   - It statically imports `@temporalio/workflow` (the `proxyActivities`
//     helper is a runtime function, not a type). That package is an OPTIONAL
//     dependency, so this file is EXCLUDED from `tsconfig.json` (`exclude`) to
//     keep `tsc --noEmit` clean on an offline install, and `@temporalio/*` is
//     marked external in `build.mjs` so esbuild leaves the import for the
//     operator's installed SDK to resolve at runtime.
//   - It imports ONLY the PURE orchestration (review-orchestration.ts) — no DB,
//     no ledger, no budget state, no top-level side effects. The Temporal
//     workflow sandbox forbids non-deterministic imports; the actual I/O lives
//     in the activities (review-steps.ts), which the worker registers and which
//     run outside the sandbox.
//
// The orchestration body is shared with the in-process engine, so both backends
// run the identical Triage -> PHI-scan/ledger -> Verifier -> PHI-scan/ledger ->
// persist sequence with the same budget breaker and failure handling.

import { proxyActivities } from "@temporalio/workflow";
import {
  runReviewOrchestration,
  REVIEW_ACTIVITY_OPTIONS,
  type ReviewActivities,
  type ReviewJob,
} from "./review-orchestration";
import {
  runNotarizerCycle,
  NOTARIZER_ACTIVITY_OPTIONS,
  type NotarizerActivities,
} from "./notarizer-workflow";
import {
  runChainVerifierRolling,
  runChainVerifierFull,
  CHAIN_VERIFIER_ACTIVITY_OPTIONS,
  type ChainVerifierActivities,
} from "./chain-verifier-workflow";
import {
  runRemediationExecutionCycle,
  REMEDIATION_EXECUTION_ACTIVITY_OPTIONS,
  type RemediationExecutionActivities,
} from "./remediation-execution-workflow";
import {
  runLogSourceReaperCycle,
  LOG_SOURCE_REAPER_ACTIVITY_OPTIONS,
  type LogSourceReaperActivities,
} from "./log-source-reaper-workflow";
import {
  runSearchReindexCycle,
  SEARCH_REINDEX_ACTIVITY_OPTIONS,
  type SearchReindexActivities,
} from "./search-reindex-workflow";
import {
  runIngestReplayCycle,
  INGEST_REPLAY_ACTIVITY_OPTIONS,
  type IngestReplayActivities,
} from "./ingest-replay-workflow";

// Activity options (incl. the bounded auto-retry policy) live in
// review-orchestration.ts so they are pure + unit-testable without the optional
// @temporalio SDK installed. Auto-retry with bounded backoff is enabled and safe
// because each side-effecting step is per-step idempotent (per-step
// idempotencyKey → ledger dedupe; budget charged after the dedupe-gate write).
// See REVIEW_ACTIVITY_OPTIONS for the full rationale.
const activities = proxyActivities<ReviewActivities>(REVIEW_ACTIVITY_OPTIONS);
const notarizerActivities = proxyActivities<NotarizerActivities>(
  NOTARIZER_ACTIVITY_OPTIONS,
);
const chainVerifierActivities = proxyActivities<ChainVerifierActivities>(
  CHAIN_VERIFIER_ACTIVITY_OPTIONS,
);
const remediationExecutionActivities =
  proxyActivities<RemediationExecutionActivities>(
    REMEDIATION_EXECUTION_ACTIVITY_OPTIONS,
  );
const logSourceReaperActivities = proxyActivities<LogSourceReaperActivities>(
  LOG_SOURCE_REAPER_ACTIVITY_OPTIONS,
);
const searchReindexActivities = proxyActivities<SearchReindexActivities>(
  SEARCH_REINDEX_ACTIVITY_OPTIONS,
);
const ingestReplayActivities = proxyActivities<IngestReplayActivities>(
  INGEST_REPLAY_ACTIVITY_OPTIONS,
);

export async function reviewFindingWorkflow(job: ReviewJob): Promise<void> {
  await runReviewOrchestration(job, activities);
}

// Periodic notarizer cycle, run on a Temporal cron schedule (see
// TemporalWorkflowEngine.schedulePeriodic). Each cron tick is a fresh workflow
// execution sharing the same fixed workflow id, so the durable backend gives the
// notarizer single-execution + crash-resume on top of its own leader lock.
export async function notarizationWorkflow(): Promise<void> {
  await runNotarizerCycle(notarizerActivities);
}

// Periodic ledger chain-integrity walks, run on Temporal cron schedules (see
// startChainVerifier -> TemporalWorkflowEngine.schedulePeriodic). Each cron tick
// is a fresh workflow execution sharing the same fixed workflow id, so the
// durable backend gives the integrity walks single-execution + crash-resume on
// top of their own per-scope leader locks. Two distinct workflow types because
// the rolling-window and full-chain walks run on independent cadences.
export async function chainVerifyRollingWorkflow(): Promise<void> {
  await runChainVerifierRolling(chainVerifierActivities);
}

export async function chainVerifyFullWorkflow(): Promise<void> {
  await runChainVerifierFull(chainVerifierActivities);
}

// Periodic executing-remediation sweep, run on a Temporal cron schedule (see
// startRemediationWorker -> TemporalWorkflowEngine.schedulePeriodic). Each cron
// tick is a fresh workflow execution sharing the same fixed workflow id, so the
// durable backend gives the worker single-execution + crash-resume on top of its
// own leader lock + per-row CAS. Inert unless REMEDIATION_EXECUTOR is set (the
// activity rebuilds the executor from env and no-ops when unset).
export async function remediationExecutionWorkflow(): Promise<void> {
  await runRemediationExecutionCycle(remediationExecutionActivities);
}

// Periodic log-source stuck-cursor reaper, run on a Temporal cron schedule (see
// startLogSourceReaper -> TemporalWorkflowEngine.schedulePeriodic). Each cron
// tick is a fresh workflow execution sharing the same fixed workflow id, so the
// durable backend gives the reaper single-execution + crash-resume on top of its
// own leader lock. Inert unless INGEST_SOURCE_STALL_AFTER_MS is set (the
// activity rebuilds the config from env and no-ops when unset).
export async function logSourceReaperWorkflow(): Promise<void> {
  await runLogSourceReaperCycle(logSourceReaperActivities);
}

// One-shot search-index reconcile, EXECUTED once (no cron) via
// TemporalWorkflowEngine.executeOneShot and AWAITED for its result. Unlike the
// cron workflows above, this returns the reconcile counts so the boot caller can
// log them exactly like the in-process inline path. The reconcile is idempotent
// and a no-op for the Postgres provider, so re-runs are safe.
export async function searchReindexWorkflow() {
  return runSearchReindexCycle(searchReindexActivities);
}

// One-shot fixture ingest replay, EXECUTED once via executeOneShot and AWAITED
// for its result. Returns the replay counts so the dev replay route can surface
// them to the caller. Dev/demo affordance (synthetic fixture only).
export async function ingestReplayWorkflow() {
  return runIngestReplayCycle(ingestReplayActivities);
}
