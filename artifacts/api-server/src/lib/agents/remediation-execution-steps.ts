// Concrete remediation-execution activity set. The side-effecting unit (leader
// lock + cross-tenant CAS + executor + ledger) lives in
// remediation-worker.runRemediationExecutionTick; this binds it to the
// `RemediationExecutionActivities` seam so both engines run identical work:
//   - the in-process engine schedules runRemediationExecutionOnce directly on a
//     timer (with the live executor);
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox), and the tick rebuilds the executor from
//     env so the durable path is configured identically.
//
// runRemediationExecutionTick is default-inert when REMEDIATION_EXECUTOR is
// unset/none, so registering this activity never changes behavior on its own.

import { runRemediationExecutionTick } from "../remediation-worker";
import type { RemediationExecutionActivities } from "./remediation-execution-workflow";

export const inProcessRemediationExecutionActivities: RemediationExecutionActivities =
  {
    runCycle: runRemediationExecutionTick,
  };
