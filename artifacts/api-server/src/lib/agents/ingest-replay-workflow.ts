// Engine-agnostic one-shot fixture ingest-replay cycle (mirrors
// search-reindex-workflow.ts).
//
// PURE module: it imports ONLY the `IngestReplayActivities` seam type (and the
// replay result type, a type-only import that erases at runtime) — no log bus,
// no ingest pipeline, no @temporalio SDK, no top-level side effects. That lets
// the Temporal workflow module import it INSIDE the deterministic workflow
// sandbox, while the real I/O (ingest-replay.replayFixtureOnce — publishes to
// the process-wide log bus → ingest pipeline) lives in the activity the worker
// registers and runs outside the sandbox (ingest-replay-steps.ts).
//
// Both engines run the SAME cycle: the in-process engine calls replayFixtureOnce
// directly inline (executeOneShot); the Temporal engine executes
// `ingestReplayWorkflow` once (no cron) and awaits its result. This is a
// dev/demo affordance (synthetic fixture only) — production replaces it with a
// brokered consumer — so dev boot + the offline eval gate are byte-identical.

import type { ReplayResult } from "../ingest-replay";

export interface IngestReplayActivities {
  /** One fixture-replay cycle. The implementation
   *  (ingest-replay.replayFixtureOnce) publishes the static fixture through the
   *  process-wide bus; ingest dedupes by fingerprint so a re-run creates no
   *  duplicate findings. */
  runCycle(): Promise<ReplayResult>;
}

/** Temporal `proxyActivities` options for the replay cycle. Kept here (this
 *  module is pure + SDK-free) so the policy is unit-testable without the
 *  optional `@temporalio/*` packages installed. `maximumAttempts: 1` mirrors the
 *  other one-shot/periodic cycles — the in-process inline path never retries. */
export const INGEST_REPLAY_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "5 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** The single source of truth for one replay cycle. Trivial today (one
 *  activity) but kept behind the seam so the deterministic Temporal workflow
 *  stays free of bus/ingest imports. */
export async function runIngestReplayCycle(
  act: IngestReplayActivities,
): Promise<ReplayResult> {
  return act.runCycle();
}
