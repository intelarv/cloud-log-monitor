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
