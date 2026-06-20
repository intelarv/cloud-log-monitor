// Concrete log-source reaper activity set. The side-effecting unit (leader lock
// + DB scan + ledger) lives in log-source-reaper.runReapCycleFromEnv; this binds
// it to the `LogSourceReaperActivities` seam so both engines run identical work:
//   - the in-process engine schedules runReapOnce directly on a timer (with the
//     config captured in startLogSourceReaper's closure);
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox). The activity re-reads the opt-in env
//     config itself and no-ops when the reaper is disabled.
//
// No new ledger event types are introduced — the cycle still emits the existing
// ingest.source_stalled event — so the alert-coverage scan and the offline eval
// gate stay byte-identical.

import { runReapCycleFromEnv } from "../log-source-reaper";
import type { LogSourceReaperActivities } from "./log-source-reaper-workflow";

export const inProcessLogSourceReaperActivities: LogSourceReaperActivities = {
  runCycle: runReapCycleFromEnv,
};
