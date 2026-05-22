import { createHmac, timingSafeEqual } from "node:crypto";
import type { Request, Response, NextFunction, RequestHandler } from "express";

const COOKIE_NAME = "phia_sess";
const STEP_UP_COOKIE_NAME = "phia_stepup";
const DEFAULT_TTL_SECONDS = 60 * 60 * 8; // 8 hours

// M1.6: step-up grant lifetime. Per threat_model §AuthN ("Step-up auth MUST
// require a second factor and produce a separate ledger entry per access"),
// the cookie is short-lived (5 minutes) so the analyst must re-prove
// possession of the second factor frequently — never a long-lived raw-PHI
// authorization.
export const STEP_UP_TTL_SECONDS = 5 * 60;

export interface Session {
  sub: string;
  tenant_id: string;
  exp: number;
}

export interface StepUpSession {
  sub: string;
  tenant_id: string;
  // Why this elevation was performed. Surfaced in the ledger entry that
  // accompanies break-glass grant issuance.
  reason: string;
  exp: number;
}

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      session?: Session;
      stepUp?: StepUpSession;
    }
  }
}

function secret(): string {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) {
    throw new Error(
      "SESSION_SECRET must be set and at least 16 characters long.",
    );
  }
  return s;
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

// Step-up signatures are domain-separated from session signatures by mixing in
// a constant tag. Otherwise a session-cookie value could be replayed as a
// step-up cookie and vice-versa (a "type confusion" if both used the same
// HMAC). Using a tag in the signing input is the standard fix.
function sign(payload: string, tag = "session"): string {
  return b64url(
    createHmac("sha256", secret()).update(`${tag}:${payload}`).digest(),
  );
}

function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export function issueCookie(res: Response, session: Omit<Session, "exp">): Session {
  const exp = Math.floor(Date.now() / 1000) + DEFAULT_TTL_SECONDS;
  const full: Session = { ...session, exp };
  const payload = b64url(Buffer.from(JSON.stringify(full)));
  const sig = sign(payload, "session");
  const value = `${payload}.${sig}`;
  res.cookie(COOKIE_NAME, value, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: DEFAULT_TTL_SECONDS * 1000,
    path: "/",
  });
  return full;
}

export function clearCookie(res: Response): void {
  res.clearCookie(COOKIE_NAME, { path: "/" });
  res.clearCookie(STEP_UP_COOKIE_NAME, { path: "/" });
}

export function parseCookie(raw: string | undefined): Session | null {
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!safeEqual(sig, sign(payload, "session"))) return null;
  try {
    const session = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as Session;
    if (typeof session.exp !== "number" || session.exp * 1000 < Date.now()) {
      return null;
    }
    if (!session.sub || !session.tenant_id) return null;
    return session;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Step-up auth (M1.6)
// ---------------------------------------------------------------------------
//
// Step-up = a second factor presented AFTER the regular session is already
// established. In production this is wired to a TOTP / WebAuthn check. In dev
// we accept a shared secret (STEP_UP_DEV_TOKEN env, default "dev-stepup")
// because there is no real second-factor infrastructure on Replit, and the
// goal of M1.6 is to exercise the *flow* (gate, time-box, per-access ledger)
// not the cryptographic strength of the dev token. The token IS held in env
// only; never compare-by-equals via `===` (timing-attack window — use
// `verifyStepUpToken`).
//
// Per threat model §Repudiation: every break-glass access (separate event
// from grant issuance) gets its own ledger entry. The step-up cookie's only
// job is to gate the grant-issuance endpoint; reading raw PHI uses the
// (separately ledgered) grant.

export function issueStepUpCookie(
  res: Response,
  s: Omit<StepUpSession, "exp">,
): StepUpSession {
  const exp = Math.floor(Date.now() / 1000) + STEP_UP_TTL_SECONDS;
  const full: StepUpSession = { ...s, exp };
  const payload = b64url(Buffer.from(JSON.stringify(full)));
  const sig = sign(payload, "stepup");
  res.cookie(STEP_UP_COOKIE_NAME, `${payload}.${sig}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    maxAge: STEP_UP_TTL_SECONDS * 1000,
    path: "/",
  });
  return full;
}

export function parseStepUpCookie(raw: string | undefined): StepUpSession | null {
  if (!raw) return null;
  const dot = raw.lastIndexOf(".");
  if (dot < 0) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!safeEqual(sig, sign(payload, "stepup"))) return null;
  try {
    const s = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8"),
    ) as StepUpSession;
    if (typeof s.exp !== "number" || s.exp * 1000 < Date.now()) return null;
    if (!s.sub || !s.tenant_id) return null;
    return s;
  } catch {
    return null;
  }
}

/**
 * Constant-time comparison of the supplied step-up token against the
 * configured dev token. Returns false on length mismatch (the timing-safe
 * compare requires equal lengths).
 */
export function verifyStepUpToken(supplied: string): boolean {
  const expected = process.env["STEP_UP_DEV_TOKEN"] ?? "dev-stepup";
  if (expected.length < 8) {
    throw new Error("STEP_UP_DEV_TOKEN must be at least 8 characters");
  }
  return safeEqual(supplied, expected);
}

export const sessionMiddleware: RequestHandler = (req, _res, next) => {
  const cookies = (req as Request & { cookies?: Record<string, string> })
    .cookies;
  const sess = parseCookie(cookies?.[COOKIE_NAME]);
  if (sess) req.session = sess;
  const step = parseStepUpCookie(cookies?.[STEP_UP_COOKIE_NAME]);
  // Bind the step-up cookie to the current session: even a stolen step-up
  // cookie is useless without the matching session, and vice-versa.
  if (step && sess && step.sub === sess.sub && step.tenant_id === sess.tenant_id) {
    req.stepUp = step;
  }
  next();
};

export function requireSession(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!req.session) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  next();
}

/**
 * Requires both a regular session AND an unexpired step-up cookie bound to
 * that session. Responds 401 `step_up_required: true` when the step-up is
 * missing so the client knows to redirect to the step-up flow rather than
 * the login flow.
 */
export function requireStepUp(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!req.session) {
    res.status(401).json({ error: "not authenticated" });
    return;
  }
  if (!req.stepUp) {
    res.status(401).json({
      error: "step-up authentication required",
      step_up_required: true,
    });
    return;
  }
  next();
}
