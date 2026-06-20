// Shared fixture-replay unit (extracted from routes/ingest.ts so both the dev
// replay route and the Temporal ingestReplayWorkflow activity run identical
// work). Replays the static fixture log source once through the process-wide log
// bus → ingest pipeline; the registered ingest handler produces findings +
// ledger entries through the normal path.
//
// This is a dev/demo affordance — production replaces both the route and the
// fixture with a brokered consumer fed by real source adapters (see
// routes/ingest.ts header). No PHI leaves through it (synthetic fixture only).

import { type PublishResult } from "./log-bus";
import { getLogBus } from "./log-bus-config";
import { StaticFixtureLogSource } from "./log-source";

/** Replay-cycle counts surfaced to the route caller (and the Temporal workflow
 *  result). `replayed` = records published; `delivered` = ingest handlers that
 *  completed without throwing; `errors` = handler failures. */
export interface ReplayResult {
  replayed: number;
  delivered: number;
  errors: number;
}

/** Replay the static fixture once. Collects per-record delivery results so the
 *  caller can see if any ingest handler failed (a previous version returned
 *  success even if every handler threw). Reads no env and no opt-in flags — the
 *  fixture is always available — so it is safe to bind as a Temporal activity
 *  that re-runs the cycle in the worker process. */
export async function replayFixtureOnce(): Promise<ReplayResult> {
  const results: PublishResult[] = [];
  const bus = getLogBus();
  const src = new StaticFixtureLogSource(async (r) => {
    const out = await bus.publish("raw.logs", r);
    results.push(out);
  });
  const out = await src.replayOnce();
  const errors = results.reduce((n, r) => n + r.errors.length, 0);
  const delivered = results.reduce((n, r) => n + r.delivered, 0);
  return { replayed: out.published, delivered, errors };
}
