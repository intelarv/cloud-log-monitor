import { Router, type IRouter } from "express";
import { UI_HTML } from "../lib/ui";

const router: IRouter = Router();

// Serve the dashboard at the artifact root path. The proxy routes /api/* to
// this service, so the UI is reachable at /api/ in dev preview.
router.get("/", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(UI_HTML);
});

export default router;
