// Concrete ingest-replay activity set. The side-effecting unit
// (ingest-replay.replayFixtureOnce — publishes the static fixture through the
// process-wide log bus → ingest pipeline) is bound to the `IngestReplayActivities`
// seam so both engines run identical work:
//   - the in-process engine calls replayFixtureOnce directly inline
//     (WorkflowEngine.executeOneShot);
//   - the Temporal worker registers THIS object as part of its activity set
//     (activities run in the worker's normal Node context, never inside the
//     deterministic workflow sandbox).
//
// No new ledger event types are introduced — the replay produces only the
// existing finding.created / ingest events through the normal pipeline — so the
// alert-coverage scan and the offline eval gate stay byte-identical.

import { replayFixtureOnce } from "../ingest-replay";
import type { IngestReplayActivities } from "./ingest-replay-workflow";

export const inProcessIngestReplayActivities: IngestReplayActivities = {
  runCycle: () => replayFixtureOnce(),
};
