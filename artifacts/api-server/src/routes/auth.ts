import { z } from "zod";
import { Router, type IRouter } from "express";
import { LoginBody as LoginInput, LoginResponse as SessionSchema } from "@workspace/api-zod";
import {
  clearCookie,
  issueCookie,
  issueStepUpCookie,
  requireSession,
  requireStepUp,
  STEP_UP_TTL_SECONDS,
} from "../lib/auth";
import {
  beginOidcRegistration,
  beginOidcStepUp,
  beginWebauthnRegistration,
  beginWebauthnStepUp,
  confirmTotpEnrollment,
  consumeRecoveryCode,
  finishOidcRegistration,
  finishWebauthnRegistration,
  generateRecoveryCodes,
  getFactorStatus,
  getStepUpVerifier,
  provisionTotpSecret,
  recoveryStatus,
  removeFactor,
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
// `token` is the second-factor proof: in dev a shared token, for TOTP a 6-digit
// code, for WebAuthn a JSON-encoded assertion ({credentialId, clientDataJSON,
// authenticatorData, signature}, all base64url). The WebAuthn form is larger
// than a code/token, so the cap is generous (still bounded against abuse).
const StepUpBody = z.object({
  token: z.string().min(1).max(8192),
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

function webauthnEnabledOr404(res: import("express").Response): boolean {
  if (stepUpProvider() !== "webauthn") {
    res.status(404).json({ error: "WebAuthn step-up is not enabled" });
    return false;
  }
  return true;
}

function oidcEnabledOr404(res: import("express").Response): boolean {
  if (stepUpProvider() !== "oidc") {
    res.status(404).json({ error: "OIDC step-up is not enabled" });
    return false;
  }
  return true;
}

// Status for the dashboard: which provider is active and, for an enrollable
// provider (TOTP / WebAuthn), whether the caller has a verified factor. Always
// available (also under the dev provider) so the UI can decide whether to show
// the authenticator-setup panel and which step-up prompt to render.
router.get(
  "/auth/step-up/status",
  requireSession,
  async (req, res): Promise<void> => {
    const provider = stepUpProvider();
    if (provider === "dev") {
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

// --- WebAuthn enrollment + step-up challenge (STEP_UP_PROVIDER=webauthn) ----
//
// Mirrors the TOTP enrollment pair: register/begin issues a creation challenge
// (navigator.credentials.create options), register/finish verifies the
// attestation ceremony and marks the credential VERIFIED. The challenge for an
// actual step-up is issued by /auth/step-up/challenge; the resulting assertion
// is then POSTed to /auth/step-up as the `token`. All 404 under the dev/TOTP
// providers, keeping that surface unchanged.

// Begin registration: returns the public-key creation options. The challenge is
// stored (encrypted) server-side and is single-use.
router.post(
  "/auth/step-up/webauthn/register/begin",
  requireSession,
  async (req, res): Promise<void> => {
    if (!webauthnEnabledOr404(res)) return;
    const options = await beginWebauthnRegistration(
      req.session!.tenant_id,
      req.session!.sub,
    );
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enroll_started",
      payload: { factor: "webauthn" },
    });
    req.log.info(
      { sub: req.session!.sub },
      "step-up WebAuthn registration started",
    );
    res.json(options);
  },
);

const WebauthnRegisterFinishBody = z.object({
  attestationObject: z.string().min(1).max(16384),
  clientDataJSON: z.string().min(1).max(8192),
});

// Finish registration: verify the attestation against the pending challenge.
router.post(
  "/auth/step-up/webauthn/register/finish",
  requireSession,
  async (req, res): Promise<void> => {
    if (!webauthnEnabledOr404(res)) return;
    const parsed = WebauthnRegisterFinishBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const verified = await finishWebauthnRegistration(
      req.session!.tenant_id,
      req.session!.sub,
      parsed.data,
    );
    if (!verified) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "auth.step_up_enroll_failed",
        payload: { factor: "webauthn" },
      });
      res.status(400).json({ error: "registration verification failed" });
      return;
    }
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enrolled",
      payload: { factor: "webauthn" },
    });
    req.log.info(
      { sub: req.session!.sub },
      "step-up WebAuthn registration confirmed",
    );
    res.json({ verified: true });
  },
);

// Issue a single-use assertion challenge for an enrolled credential. The
// resulting assertion is submitted to /auth/step-up as the `token`. Returns 400
// if the caller has no verified credential.
router.post(
  "/auth/step-up/webauthn/challenge",
  requireSession,
  async (req, res): Promise<void> => {
    if (!webauthnEnabledOr404(res)) return;
    const options = await beginWebauthnStepUp(
      req.session!.tenant_id,
      req.session!.sub,
    );
    if (!options) {
      res.status(400).json({ error: "no verified WebAuthn credential" });
      return;
    }
    res.json(options);
  },
);

// --- OIDC (IdP-federated) enrollment + step-up (STEP_UP_PROVIDER=oidc) ------
//
// Unlike TOTP/WebAuthn, the OIDC second factor is a browser redirect round-trip
// to the user's identity provider. register/begin and challenge both return an
// authorization_url the dashboard opens in a popup; the IdP redirects back to
// our callback page, which postMessages {code, state} to the opener. For
// enrollment the dashboard posts that to register/finish (links the federated
// identity); for an actual step-up it posts JSON {code,state} to /auth/step-up
// as the `token`. All 404 under the dev/TOTP/WebAuthn providers.

router.post(
  "/auth/step-up/oidc/register/begin",
  requireSession,
  async (req, res): Promise<void> => {
    if (!oidcEnabledOr404(res)) return;
    const options = await beginOidcRegistration(
      req.session!.tenant_id,
      req.session!.sub,
    );
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enroll_started",
      payload: { factor: "oidc" },
    });
    req.log.info({ sub: req.session!.sub }, "step-up OIDC enrollment started");
    res.json({ authorization_url: options.authorizationUrl });
  },
);

const OidcRegisterFinishBody = z.object({
  code: z.string().min(1).max(8192),
  state: z.string().min(1).max(2048),
});

router.post(
  "/auth/step-up/oidc/register/finish",
  requireSession,
  async (req, res): Promise<void> => {
    if (!oidcEnabledOr404(res)) return;
    const parsed = OidcRegisterFinishBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const verified = await finishOidcRegistration(
      req.session!.tenant_id,
      req.session!.sub,
      parsed.data,
    );
    if (!verified) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "auth.step_up_enroll_failed",
        payload: { factor: "oidc" },
      });
      res.status(400).json({ error: "registration verification failed" });
      return;
    }
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_enrolled",
      payload: { factor: "oidc" },
    });
    req.log.info({ sub: req.session!.sub }, "step-up OIDC enrollment confirmed");
    res.json({ verified: true });
  },
);

// Issue a fresh authorization URL for an enrolled federated identity. The
// resulting {code,state} is submitted to /auth/step-up as the `token`. Returns
// 400 if the caller has no verified federated identity.
router.post(
  "/auth/step-up/oidc/challenge",
  requireSession,
  async (req, res): Promise<void> => {
    if (!oidcEnabledOr404(res)) return;
    const options = await beginOidcStepUp(
      req.session!.tenant_id,
      req.session!.sub,
    );
    if (!options) {
      res.status(400).json({ error: "no verified OIDC identity" });
      return;
    }
    res.json({ authorization_url: options.authorizationUrl });
  },
);

// --- Backup / recovery codes + factor management (M29) ---------------------
//
// Backup codes are the account-recovery path for any non-dev provider: if the
// analyst loses their authenticator / passkey / IdP access, a single-use backup
// code satisfies a step-up. The dev provider has no enrollable factor (it uses a
// shared token), so all of these 404 under it — keeping the dev/eval-gate
// surface unchanged.

function factorMgmtEnabledOr404(res: import("express").Response): boolean {
  if (stepUpProvider() === "dev") {
    res.status(404).json({ error: "step-up factor management is not enabled" });
    return false;
  }
  return true;
}

// Recovery-code status for the dashboard panel: whether a set exists and how
// many codes remain. Session-gated; 404 under the dev provider.
router.get(
  "/auth/step-up/recovery/status",
  requireSession,
  async (req, res): Promise<void> => {
    if (!factorMgmtEnabledOr404(res)) return;
    const status = await recoveryStatus(
      req.session!.tenant_id,
      req.session!.sub,
    );
    res.json(status);
  },
);

// Generate (or regenerate) a fresh set of backup codes. Requires an existing
// step-up (you must already hold a valid second factor to mint recovery codes)
// AND a verified factor. The plaintext codes are returned exactly once.
router.post(
  "/auth/step-up/recovery/generate",
  requireSession,
  requireStepUp,
  async (req, res): Promise<void> => {
    if (!factorMgmtEnabledOr404(res)) return;
    const result = await generateRecoveryCodes(
      req.session!.tenant_id,
      req.session!.sub,
    );
    if (!result) {
      res.status(400).json({ error: "no verified second factor to back up" });
      return;
    }
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_recovery_generated",
      payload: { count: result.codes.length },
    });
    req.log.info(
      { sub: req.session!.sub, count: result.codes.length },
      "step-up recovery codes generated",
    );
    res.json({ codes: result.codes });
  },
);

const RecoveryStepUpBody = z.object({
  token: z.string().min(1).max(64),
  reason: z.string().min(3).max(200),
});

// Redeem a backup code as a step-up. Mirrors /auth/step-up but the `token` is a
// single-use recovery code (consumed on success). Issues the same short-lived
// step-up cookie so downstream break-glass / remediation-confirm flows are
// satisfied identically. Session-gated; 404 under the dev provider.
router.post(
  "/auth/step-up/recovery",
  requireSession,
  async (req, res): Promise<void> => {
    if (!factorMgmtEnabledOr404(res)) return;
    const parsed = RecoveryStepUpBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    // Same boundary scan as /auth/step-up: the reason lands in the immutable
    // ledger and is copied into the step-up cookie.
    const rv = validateLedgerSafeText(parsed.data.reason);
    if (!rv.ok) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "policy.text_field_rejected",
        payload: {
          endpoint: "POST /auth/step-up/recovery",
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
    const ok = await consumeRecoveryCode(
      req.session!.tenant_id,
      req.session!.sub,
      parsed.data.token,
    );
    if (!ok) {
      await appendLedger({
        tenantId: req.session!.tenant_id,
        actor: { kind: "human", id: req.session!.sub },
        eventType: "auth.step_up_failed",
        payload: {
          factor: "recovery",
          reason_hash_prefix: parsed.data.reason.slice(0, 40),
        },
      });
      res.status(401).json({ error: "invalid recovery code" });
      return;
    }
    const step = issueStepUpCookie(res, {
      sub: req.session!.sub,
      tenant_id: req.session!.tenant_id,
      reason: parsed.data.reason,
    });
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_recovery_consumed",
      payload: { reason: parsed.data.reason },
    });
    const led = await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_granted",
      payload: {
        ttl_seconds: STEP_UP_TTL_SECONDS,
        reason: parsed.data.reason,
        factor: "recovery",
      },
    });
    req.log.info(
      { sub: step.sub, seq: led.seq, reason: parsed.data.reason, factor: "recovery" },
      "step-up granted via recovery code",
    );
    res.json({
      ok: true,
      expires_at: new Date(step.exp * 1000).toISOString(),
      ttl_seconds: STEP_UP_TTL_SECONDS,
    });
  },
);

// Remove the enrolled second factor (and its recovery codes) entirely — the
// "lost my device, start over" path. Requires an existing step-up so a hijacked
// session alone cannot strip the victim's factor. Session-gated; 404 under dev.
router.post(
  "/auth/step-up/factor/remove",
  requireSession,
  requireStepUp,
  async (req, res): Promise<void> => {
    if (!factorMgmtEnabledOr404(res)) return;
    const removed = await removeFactor(
      req.session!.tenant_id,
      req.session!.sub,
    );
    if (!removed) {
      res.status(404).json({ error: "no enrolled factor to remove" });
      return;
    }
    await appendLedger({
      tenantId: req.session!.tenant_id,
      actor: { kind: "human", id: req.session!.sub },
      eventType: "auth.step_up_factor_removed",
      payload: {},
    });
    req.log.info({ sub: req.session!.sub }, "step-up factor removed");
    res.json({ removed: true });
  },
);

export default router;
