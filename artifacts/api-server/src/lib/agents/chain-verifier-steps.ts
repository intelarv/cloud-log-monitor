// Concrete chain-verifier activity set. The side-effecting units (leader lock +
// chain walk + ledger) live in chain-verifier.runRollingWalkOnce /
// runFullWalkOnce; this binds them to the `ChainVerifierActivities` seam so both
// engines run identical work:
//   - the in-process engine schedules the run-once helpers directly on a timer;
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox).
//
// No new ledger event types are introduced — the walks still emit the existing
// ledger.chain_invalid on mismatch — so the alert-coverage scan and the offline
// eval gate stay byte-identical.

import { runRollingWalkOnce, runFullWalkOnce } from "../chain-verifier";
import type { ChainVerifierActivities } from "./chain-verifier-workflow";

export const inProcessChainVerifierActivities: ChainVerifierActivities = {
  runRollingWalk: runRollingWalkOnce,
  runFullWalk: runFullWalkOnce,
};
