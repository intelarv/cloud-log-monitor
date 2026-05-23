import { Router, type IRouter } from "express";
import healthRouter from "./health";
import authRouter from "./auth";
import findingsRouter from "./findings";
import chatRouter from "./chat";
import ledgerRouter from "./ledger";
import toolsRouter from "./tools";
import adminRouter from "./admin";
import ingestRouter from "./ingest";

const router: IRouter = Router();

router.use(healthRouter);
router.use(authRouter);
router.use(findingsRouter);
router.use(chatRouter);
router.use(ledgerRouter);
router.use(toolsRouter);
router.use(adminRouter);
router.use(ingestRouter);

export default router;
