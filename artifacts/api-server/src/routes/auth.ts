import { z } from "zod";
import { Router, type IRouter } from "express";
import { LoginBody as LoginInput, LoginResponse as SessionSchema } from "@workspace/api-zod";
import {
  clearCookie,
  issueCookie,
  issueStepUpCookie,
  requireSession,
  STEP_UP_TTL_SECONDS,
  verifyStepUpToken,
} from "../lib/auth";
import { appendLedger } from "../lib/ledger";

const router: IRouter = Router();

router.post("/auth/login", async (req, res): Promise<void> => {
  const parsed = LoginInput.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.message });
    return;
  }
  const tenantId = parsed.data.tenant_id ?? "default";
  const session = issueCookie(res, { sub: parsed.data.username, tenant_id: tenantId });
  req.log.info({ sub: session.sub, tenant_id: session.tenant_id }, "login");
  res.json(SessionSchema.parse(session));
});

router.post("/auth/logout", async (_req, res): Promise<void> => {
  clearCookie(res);
  res.sendStatus(204);
});

router.get("/me", async (req, res): Promise<void> => {
  if (!req.session) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  res.json(SessionSchema.parse(req.session));
});

// M1.6: step-up auth.
//
// The client posts a token (in dev: STEP_UP_DEV_TOKEN; in production: TOTP
// code, WebAuthn assertion, etc.) plus the reason they're elevating. We
// return a short-lived cookie (5 min) that the break-glass grant-issuance
// endpoint requires. The reason field lands in the ledger entry below so an
// auditor can correlate the elevation with the subsequent grant.
//
// Threat model §AuthN: step-up MUST be rate-limited (anti-brute-force on the
// second factor). The express-rate-limit middleware mounted on this path
// (app.ts) is the implementation of that requirement.
const StepUpBody = z.object({
  token: z.string().min(1).max(256),
  reason: z.string().min(3).max(200),
});

router.post(
  "/auth/step-up",
  requireSession,
  async (req, res): Promise<void> => {
    const parsed = StepUpBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    if (!verifyStepUpToken(parsed.data.token)) {
      // Log the failure ledger entry but DO NOT include the supplied token
      // value — only the fact + the reason. Brute-force attempts must be
      // forensically reconstructable but must not themselves leak secrets.
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "auth.step_up_failed",
        payload: { reason_hash_prefix: parsed.data.reason.slice(0, 40) },
      });
      res.status(401).json({ error: "invalid step-up token" });
      return;
    }
    const step = issueStepUpCookie(res, {
      sub: req.session!.sub,
      tenant_id: req.session!.tenant_id,
      reason: parsed.data.reason,
    });
    const led = await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_granted",
      payload: {
        ttl_seconds: STEP_UP_TTL_SECONDS,
        reason: parsed.data.reason,
      },
    });
    req.log.info(
      { sub: step.sub, seq: led.seq, reason: parsed.data.reason },
      "step-up granted",
    );
    res.json({
      ok: true,
      expires_at: new Date(step.exp * 1000).toISOString(),
      ttl_seconds: STEP_UP_TTL_SECONDS,
    });
  },
);

export default router;
