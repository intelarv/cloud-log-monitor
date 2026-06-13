// Concrete notarizer activity set. The side-effecting unit (leader lock + DB +
// ledger) lives in chain-verifier.runCheckpointOnce; this binds it to the
// `NotarizerActivities` seam so both engines run identical work:
//   - the in-process engine schedules runCheckpointOnce directly on a timer;
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox).
//
// No new ledger event types are introduced — runCheckpointOnce still emits the
// existing ledger.checkpoint_created / ledger.checkpoint_mismatch — so the
// alert-coverage scan and the offline eval gate stay byte-identical.

import { runCheckpointOnce } from "../chain-verifier";
import type { NotarizerActivities } from "./notarizer-workflow";

export const inProcessNotarizerActivities: NotarizerActivities = {
  runCycle: runCheckpointOnce,
};
