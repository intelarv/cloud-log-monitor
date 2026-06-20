import { z } from "zod";
import { Router, type IRouter } from "express";
import { LoginBody as LoginInput, LoginResponse as SessionSchema } from "@workspace/api-zod";
import {
  clearCookie,
  issueCookie,
  issueStepUpCookie,
  requireSession,
  STEP_UP_TTL_SECONDS,
} from "../lib/auth";
import {
  confirmTotpEnrollment,
  getFactorStatus,
  getStepUpVerifier,
  provisionTotpSecret,
  stepUpProvider,
} from "../lib/step-up-verifier";
import { appendLedger } from "../lib/ledger";
import { validateLedgerSafeText } from "../lib/text-policy";

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
    // The step-up reason lands in the ledger payload AND is later copied
    // into the break-glass.granted payload via the step-up cookie. Boundary
    // scan to keep PHI/secrets out of the immutable chain.
    const rv = validateLedgerSafeText(parsed.data.reason);
    if (!rv.ok) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "policy.text_field_rejected",
        payload: {
          endpoint: "POST /auth/step-up",
          field: "reason",
          reason: rv.reason,
          detectors: rv.detectors,
        },
      });
      res.status(400).json({
        error: "reason rejected by content policy",
        reason: rv.reason,
      });
      return;
    }
    const ok = await getStepUpVerifier().verify({
      tenantId: req.session!.tenant_id,
      sub: req.session!.sub,
      token: parsed.data.token,
    });
    if (!ok) {
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

// --- TOTP enrollment (STEP_UP_PROVIDER=totp only) --------------------------
//
// These endpoints provision + confirm a user's authenticator-app second
// factor. They are session-gated (the analyst is already logged in) but do NOT
// require an existing step-up — enrollment is how a user *obtains* the ability
// to step up. When the dev provider is active they 404 (there is nothing to
// enroll: the dev path uses a shared token), keeping the dev/eval-gate surface
// unchanged.

function totpEnabledOr404(res: import("express").Response): boolean {
  if (stepUpProvider() !== "totp") {
    res.status(404).json({ error: "TOTP step-up is not enabled" });
    return false;
  }
  return true;
}

// Status for the dashboard: which provider is active and, for TOTP, whether the
// caller has a verified factor. Always available (also under the dev provider)
// so the UI can decide whether to show the authenticator-setup panel and which
// step-up prompt to render.
router.get(
  "/auth/step-up/status",
  requireSession,
  async (req, res): Promise<void> => {
    const provider = stepUpProvider();
    if (provider !== "totp") {
      res.json({ provider, enrolled: false, verified: false });
      return;
    }
    const status = await getFactorStatus(
      req.session!.tenant_id,
      req.session!.sub,
    );
    res.json({ provider, ...status });
  },
);

// Begin (or restart) enrollment: provisions a fresh secret and returns the
// otpauth URI + base32 secret for the QR / manual entry. The secret is the
// user's own factor, returned once over the authenticated TLS channel; it is
// stored encrypted at rest and never logged. The factor is UNVERIFIED until
// confirmed below.
router.post(
  "/auth/step-up/enroll",
  requireSession,
  async (req, res): Promise<void> => {
    if (!totpEnabledOr404(res)) return;
    const result = await provisionTotpSecret(
      req.session!.tenant_id,
      req.session!.sub,
    );
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enroll_started",
      payload: { factor: "totp" },
    });
    req.log.info({ sub: req.session!.sub }, "step-up TOTP enrollment started");
    res.json({ otpauth_uri: result.otpauthUri, secret: result.secret });
  },
);

const EnrollVerifyBody = z.object({
  code: z.string().regex(/^\d{6}$/),
});

// Confirm enrollment with a live code. On success the factor becomes usable for
// step-up and the used step is recorded (the enrollment code cannot be replayed
// as a step-up).
router.post(
  "/auth/step-up/enroll/verify",
  requireSession,
  async (req, res): Promise<void> => {
    if (!totpEnabledOr404(res)) return;
    const parsed = EnrollVerifyBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const verified = await confirmTotpEnrollment(
      req.session!.tenant_id,
      req.session!.sub,
      parsed.data.code,
    );
    if (!verified) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "auth.step_up_enroll_failed",
        payload: { factor: "totp" },
      });
      res.status(400).json({ error: "invalid code" });
      return;
    }
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enrolled",
      payload: { factor: "totp" },
    });
    req.log.info({ sub: req.session!.sub }, "step-up TOTP enrollment confirmed");
    res.json({ verified: true });
  },
);

export default router;
