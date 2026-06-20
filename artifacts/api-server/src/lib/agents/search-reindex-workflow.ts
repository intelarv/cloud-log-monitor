// Engine-agnostic one-shot search-index reconcile cycle (mirrors
// log-source-reaper-workflow.ts, but for a ONE-SHOT job rather than a periodic
// one).
//
// PURE module: it imports ONLY the `SearchReindexActivities` seam type (and the
// reconcile result type, which is a type-only import that erases at runtime) —
// no DB, no search client, no @temporalio SDK, no top-level side effects. That
// is what lets the Temporal workflow module (temporal-workflows.ts) import it
// INSIDE the deterministic workflow sandbox, while the real I/O
// (search.reconcileSearchIndex) lives in the activity the worker registers and
// runs outside the sandbox (search-reindex-steps.ts).
//
// Both engines run the SAME cycle: the in-process engine calls
// reconcileSearchIndex directly inline (executeOneShot); the Temporal engine
// executes `searchReindexWorkflow` once (no cron) and awaits its result. The
// reconcile is idempotent and a no-op for the Postgres provider, so dev boot +
// the offline eval gate are byte-identical either way.

import type { ReconcileResult } from "../search";

export interface SearchReindexActivities {
  /** One reconcile cycle. The implementation (search.reconcileSearchIndex) is
   *  idempotent and a no-op for the Postgres dev provider. */
  runCycle(): Promise<ReconcileResult>;
}

/** Temporal `proxyActivities` options for the reconcile cycle. Kept here (this
 *  module is pure + SDK-free) so the policy is unit-testable without the
 *  optional `@temporalio/*` packages installed.
 *
 *  `maximumAttempts: 1` = no automatic activity retries, mirroring the reaper +
 *  notarizer options: the in-process inline path never retries, and a failed
 *  boot reconcile is already best-effort (hybrid search degrades to the vector
 *  leg until the next restart reconciles). The 30-minute timeout accommodates a
 *  large external (OpenSearch) bulk mirror. */
export const SEARCH_REINDEX_ACTIVITY_OPTIONS = {
  startToCloseTimeout: "30 minutes",
  retry: { maximumAttempts: 1 },
} as const;

/** The single source of truth for one reconcile cycle. Trivial today (one
 *  activity) but kept behind the seam so the deterministic Temporal workflow
 *  stays free of DB/search imports and the cycle can grow more steps later. */
export async function runSearchReindexCycle(
  act: SearchReindexActivities,
): Promise<ReconcileResult> {
  return act.runCycle();
}
