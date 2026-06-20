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
import { replayFixtureOnce } from "../lib/ingest-replay";
import { getWorkflowEngine } from "../lib/agents/workflow-engine";

const router: IRouter = Router();

router.post(
  "/admin/ingest/replay",
  requireSession,
  async (_req, res, next) => {
    try {
      // Routed through the WorkflowEngine seam: in-process runs replayFixtureOnce
      // inline (byte-identical response shape {replayed,delivered,errors}); under
      // WORKFLOW_ENGINE=temporal this becomes a durable one-shot workflow whose
      // result is awaited and returned to the caller.
      const out = await getWorkflowEngine().executeOneShot({
        name: "ingest-replay",
        workflowType: "ingestReplayWorkflow",
        run: () => replayFixtureOnce(),
      });
      res.json(out);
    } catch (err) {
      next(err);
    }
  },
);

export default router;
