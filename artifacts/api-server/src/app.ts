import express, { type Express } from "express";
import type { Request } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import pinoHttp from "pino-http";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";
import router from "./routes";
import { logger } from "./lib/logger";
import { sessionMiddleware } from "./lib/auth";

const app: Express = express();
app.set("trust proxy", 1);

app.use(
  pinoHttp({
    logger,
    serializers: {
      req(req) {
        return {
          id: req.id,
          method: req.method,
          url: req.url?.split("?")[0],
        };
      },
      res(res) {
        return {
          statusCode: res.statusCode,
        };
      },
    },
  }),
);
app.use(cors({ credentials: true }));
app.use(express.json({ limit: "256kb" }));
app.use(express.urlencoded({ extended: true, limit: "256kb" }));
app.use(cookieParser());
app.use(sessionMiddleware);

// Threat model §DoS — rate limits.
//
// Login + step-up endpoints are per-IP (no stable user identity exists yet
// or, in the step-up case, the user IS proving identity — using session.sub
// as the key would let an attacker tunnel attempts through a session they
// already control). The chat and tool endpoints key on session.sub so that
// one greedy analyst can't burn the budget for a whole tenant — and fall
// back to IP (via the IPv6-safe `ipKeyGenerator`) for unauthenticated
// requests, which `requireSession` will then reject with 401.
const ipKey = (req: Request): string =>
  ipKeyGenerator(req.ip ?? "0.0.0.0");

const userOrIpKey = (req: Request): string =>
  req.session?.sub ? `u:${req.session.sub}` : `ip:${ipKey(req)}`;

const loginLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: ipKey,
});
// Tight cap on step-up — brute-forcing the second factor is the bypass we
// most need to block. 5 attempts per minute per IP is generous for honest
// fat-finger but punishing for automation.
const stepUpLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: ipKey,
});
const chatLimiter = rateLimit({
  windowMs: 60_000,
  limit: 30,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: userOrIpKey,
});
const toolLimiter = rateLimit({
  windowMs: 60_000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: userOrIpKey,
});
// Break-glass issuance is intentionally rare. A burst is itself suspicious;
// the cap doubles as a defense against an attacker using a stolen step-up
// cookie to mint dozens of grants before detection.
const breakGlassLimiter = rateLimit({
  windowMs: 60_000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: userOrIpKey,
});
// M3: replay is a dev/demo affordance that mints findings + ledger entries.
// A scripted loop would balloon both. 5/min is enough for analyst-driven
// "show me this works" clicks but kills runaway automation.
const ingestReplayLimiter = rateLimit({
  windowMs: 60_000,
  limit: 5,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  keyGenerator: userOrIpKey,
});
app.use("/api/auth/login", loginLimiter);
app.use("/api/auth/step-up", stepUpLimiter);
app.use("/api/chat", chatLimiter);
app.use("/api/tools", toolLimiter);
app.use("/api/admin/break-glass/grants", breakGlassLimiter);
app.use("/api/admin/ingest/replay", ingestReplayLimiter);

app.use("/api", router);

export default app;
