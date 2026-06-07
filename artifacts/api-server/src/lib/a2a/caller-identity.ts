// A2A caller identity + ABAC scope (threat_model §Spoofing — "A2A caller
// identity" / §Elevation of Privilege — "A2A authorization").
//
// The shared-secret bearer (auth.ts) answers "is this a known caller at all".
// This module answers the stronger questions the threat model requires of the
// agent plane:
//   1. WHO is calling?           — a signed JWT carries the caller's identity
//                                  (`sub`, e.g. "supervisor").
//   2. Are they allowed THIS?    — ABAC: the token's `scope` claim must contain
//                                  the skill the called agent is about to run,
//                                  and the token's `aud` must name that agent.
//
// This is genuine, spec-shaped JWT (HS256 via `jose`), not a hand-rolled token.
// In a multi-cluster / cross-cloud deployment the same `Authorization`-adjacent
// identity token rides over an mTLS channel (network-layer caller auth); see
// `A2A_REQUIRE_MTLS` note in server.ts. Loopback dev keeps the JWT but runs over
// plain loopback because there is no PKI in the dev sandbox.
//
// Key management mirrors auth.ts / notarization.ts: `A2A_JWT_SECRET` in shared
// deployments; a deterministic dev fallback derived from `SESSION_SECRET` with a
// one-time WARN otherwise, so the offline credential-free eval gate still runs.

import { createHmac } from "node:crypto";
import type { Request, RequestHandler } from "express";
import { SignJWT, jwtVerify, errors as joseErrors } from "jose";
import { logger } from "../logger";

export const A2A_CALLER_IDENTITY_HEADER = "x-a2a-caller-identity";

/** The single trusted caller of the specialist agents in this deployment. */
export const SUPERVISOR_CALLER_ID = "supervisor";

/** Per-agent audience + the skill each agent is allowed to run. The audience is
 *  what the caller addresses and what the executor checks against, so a token
 *  minted for one agent cannot be replayed against another. */
export const TRIAGE_AUDIENCE = "a2a:triage";
export const VERIFY_AUDIENCE = "a2a:verify";
export const TRIAGE_SKILL = "triage_finding";
export const VERIFY_SKILL = "verify_finding";

const ISSUER = "phi-audit/supervisor";
const TOKEN_TTL_SECONDS = 60; // short-lived: minted per call over loopback.

let cachedKey: Uint8Array | undefined;
let warned = false;

function getSigningKey(): Uint8Array {
  if (cachedKey !== undefined) return cachedKey;
  const fromEnv = process.env["A2A_JWT_SECRET"];
  if (fromEnv !== undefined && fromEnv.length > 0) {
    cachedKey = new TextEncoder().encode(fromEnv);
    return cachedKey;
  }
  const sessionSecret = process.env["SESSION_SECRET"] ?? "dev-insecure-session-secret";
  // Domain-separated from the shared bearer secret and the session cookie key.
  const derivedHex = createHmac("sha256", sessionSecret)
    .update("a2a-caller-identity/v1")
    .digest("hex");
  cachedKey = new TextEncoder().encode(derivedHex);
  if (!warned) {
    warned = true;
    logger.warn(
      "A2A_JWT_SECRET not set; deriving the A2A caller-identity signing key from SESSION_SECRET (dev fallback). Set A2A_JWT_SECRET in any shared/production deployment.",
    );
  }
  return cachedKey;
}

/** Reset cached state — test-only. */
export function __resetCallerIdentityForTest(): void {
  cachedKey = undefined;
  warned = false;
}

export interface MintCallerTokenOpts {
  /** Caller identity (`sub`). */
  subject: string;
  /** Target agent (`aud`). */
  audience: string;
  /** Skill ids the caller is authorized to invoke on that agent. */
  scope: string[];
}

/** Mint a short-lived signed caller-identity token for one outbound A2A call. */
export async function mintCallerToken(opts: MintCallerTokenOpts): Promise<string> {
  return new SignJWT({ scope: opts.scope })
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuer(ISSUER)
    .setSubject(opts.subject)
    .setAudience(opts.audience)
    .setIssuedAt()
    .setExpirationTime(`${TOKEN_TTL_SECONDS}s`)
    .sign(getSigningKey());
}

export interface VerifiedCaller {
  subject: string;
  scope: string[];
}

export class CallerIdentityError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "CallerIdentityError";
  }
}

/** Verify a caller-identity token for a specific agent + skill. Throws
 *  `CallerIdentityError` (401 missing/invalid, 403 out-of-scope). */
export async function verifyCallerToken(
  token: string | undefined,
  expect: { audience: string; requiredSkill: string },
): Promise<VerifiedCaller> {
  if (token === undefined || token.length === 0) {
    throw new CallerIdentityError("missing caller-identity token", 401);
  }
  let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
  try {
    ({ payload } = await jwtVerify(token, getSigningKey(), {
      issuer: ISSUER,
      audience: expect.audience,
    }));
  } catch (err) {
    if (
      err instanceof joseErrors.JWTExpired ||
      err instanceof joseErrors.JWTClaimValidationFailed ||
      err instanceof joseErrors.JWSSignatureVerificationFailed ||
      err instanceof joseErrors.JWSInvalid ||
      err instanceof joseErrors.JWTInvalid
    ) {
      throw new CallerIdentityError(`invalid caller-identity token: ${err.code}`, 401);
    }
    throw err;
  }
  const scope = Array.isArray(payload["scope"])
    ? (payload["scope"] as unknown[]).filter((s): s is string => typeof s === "string")
    : [];
  if (!scope.includes(expect.requiredSkill)) {
    throw new CallerIdentityError(
      `caller not authorized for skill ${expect.requiredSkill}`,
      403,
    );
  }
  return { subject: payload.sub ?? "unknown", scope };
}

/** Express middleware enforcing caller identity + ABAC scope on an agent's
 *  JSON-RPC endpoint. Runs AFTER the shared-secret bearer middleware. */
export function a2aScopeMiddleware(expect: {
  audience: string;
  requiredSkill: string;
}): RequestHandler {
  return (req, res, next) => {
    const token = req.header(A2A_CALLER_IDENTITY_HEADER) ?? undefined;
    verifyCallerToken(token, expect)
      .then((caller) => {
        (req as Request & { a2aCaller?: VerifiedCaller }).a2aCaller = caller;
        next();
      })
      .catch((err: unknown) => {
        if (err instanceof CallerIdentityError) {
          res.status(err.status).json({ error: err.message });
          return;
        }
        next(err as Error);
      });
  };
}
