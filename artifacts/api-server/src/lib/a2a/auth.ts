// A2A caller authentication (threat_model §Spoofing — "A2A caller identity").
//
// The agent endpoints are loopback-only (not in the shared proxy path table),
// but defense-in-depth still requires the called agent to verify the caller.
// We use a shared bearer secret with a constant-time compare. The secret comes
// from `A2A_SHARED_SECRET`; when unset we derive a deterministic dev fallback
// from `SESSION_SECRET` and WARN once at first use — the same posture as the
// notarization key (`lib/notarization.ts`).

import { createHmac, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler } from "express";
import { logger } from "../logger";

let cachedSecret: string | undefined;
let warned = false;

export function getA2ASharedSecret(): string {
  if (cachedSecret !== undefined) return cachedSecret;
  const fromEnv = process.env["A2A_SHARED_SECRET"];
  if (fromEnv !== undefined && fromEnv.length > 0) {
    cachedSecret = fromEnv;
    return cachedSecret;
  }
  const sessionSecret = process.env["SESSION_SECRET"] ?? "dev-insecure-session-secret";
  cachedSecret = createHmac("sha256", sessionSecret)
    .update("a2a-shared-secret/v1")
    .digest("hex");
  if (!warned) {
    warned = true;
    logger.warn(
      "A2A_SHARED_SECRET not set; using a dev fallback derived from SESSION_SECRET. Set A2A_SHARED_SECRET in any shared/production deployment.",
    );
  }
  return cachedSecret;
}

/** Reset cached state — test-only. */
export function __resetA2ASecretForTest(): void {
  cachedSecret = undefined;
  warned = false;
}

function authHeaderMatches(got: string): boolean {
  const expected = `Bearer ${getA2ASharedSecret()}`;
  const gotBuf = Buffer.from(got);
  const expectedBuf = Buffer.from(expected);
  // timingSafeEqual throws on length mismatch; guard first (length is not secret).
  if (gotBuf.length !== expectedBuf.length) return false;
  return timingSafeEqual(gotBuf, expectedBuf);
}

/** Express middleware guarding the A2A agent routes. */
export const a2aAuthMiddleware: RequestHandler = (req, res, next) => {
  const got = req.header("authorization") ?? "";
  if (!authHeaderMatches(got)) {
    res.status(401).json({ error: "unauthorized" });
    return;
  }
  next();
};

/** A `fetch` implementation that injects the shared-secret bearer header on
 *  every A2A client request (card fetch + message/send). */
export function buildA2AClientFetch(): typeof fetch {
  const authorization = `Bearer ${getA2ASharedSecret()}`;
  return ((input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
    const headers = new Headers(init?.headers);
    headers.set("authorization", authorization);
    return fetch(input, { ...init, headers });
  }) as typeof fetch;
}

/** Absolute base URL of this process's own A2A endpoints. Both the served
 *  Agent Card `url` and the loopback client resolve through this helper so they
 *  always agree. */
export function getA2ABaseUrl(): string {
  const explicit = process.env["A2A_BASE_URL"];
  if (explicit !== undefined && explicit.length > 0) {
    return explicit.replace(/\/+$/, "");
  }
  const port = process.env["PORT"] ?? "8080";
  return `http://127.0.0.1:${port}`;
}

// Re-export the Request type so other a2a modules don't each import express.
export type { Request };
