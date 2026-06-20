// Concrete search-reindex activity set. The side-effecting unit
// (search.reconcileSearchIndex — external lexical index bulk mirror) is bound to
// the `SearchReindexActivities` seam so both engines run identical work:
//   - the in-process engine calls reconcileSearchIndex directly inline
//     (WorkflowEngine.executeOneShot);
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox).
//
// No new ledger event types are introduced — the reconcile emits none — so the
// alert-coverage scan and the offline eval gate stay byte-identical.

import { reconcileSearchIndex } from "../search";
import type { SearchReindexActivities } from "./search-reindex-workflow";

export const inProcessSearchReindexActivities: SearchReindexActivities = {
  runCycle: () => reconcileSearchIndex(),
};
