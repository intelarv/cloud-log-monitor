// M3: dev/demo route that replays the static fixture log source through the
// in-memory bus → ingest pipeline. Session-gated (any analyst can trigger;
// no step-up — this is a dev affordance, no PHI leaves through it).
//
// The replay publishes synthetic records to `logBus`; the registered ingest
// handler picks them up and produces findings + ledger entries through the
// normal path. Useful for demos and for re-seeding ingest findings after a
// wipe without restarting the process.
//
// Production replaces both the route and the fixture with a brokered
// consumer fed by real source adapters.

import { Router, type IRouter } from "express";
import { requireSession } from "../lib/auth";
import { type PublishResult } from "../lib/log-bus";
import { getLogBus } from "../lib/log-bus-config";
import { StaticFixtureLogSource } from "../lib/log-source";

const router: IRouter = Router();

router.post(
  "/admin/ingest/replay",
  requireSession,
  async (_req, res, next) => {
    try {
      // Collect per-record delivery results so the caller can see if any
      // ingest handler failed (architect-flagged: previous version returned
      // success even if every handler threw).
      const results: PublishResult[] = [];
      const bus = getLogBus();
      const src = new StaticFixtureLogSource(async (r) => {
        const out = await bus.publish("raw.logs", r);
        results.push(out);
      });
      const out = await src.replayOnce();
      const totalErrors = results.reduce((n, r) => n + r.errors.length, 0);
      const totalDelivered = results.reduce((n, r) => n + r.delivered, 0);
      res.json({
        replayed: out.published,
        delivered: totalDelivered,
        errors: totalErrors,
      });
    } catch (err) {
      next(err);
    }
  },
);

export default router;
