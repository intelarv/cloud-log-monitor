import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import findingsRouter from "./findings";
import chatRouter from "./chat";
import ledgerRouter from "./ledger";
import toolsRouter from "./tools";
import uiRouter from "./ui";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(findingsRouter);
router.use(chatRouter);
router.use(ledgerRouter);
router.use(toolsRouter);
// UI must be mounted last (root path "/") so it doesn't shadow API routes.
router.use(uiRouter);

export default router;
