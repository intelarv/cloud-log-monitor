// Hand-rolled, vendor-neutral OpenID Connect relying-party helpers for the
// IdP-federated step-up provider (STEP_UP_PROVIDER=oidc).
//
// Posture mirrors `lib/webauthn.ts` and the self-hosted Presidio NER backend:
// NO SDK and NO cloud account — `node:crypto` + the global `fetch` only. This
// module is lazy-imported exclusively on the oidc code path (never at module
// top level), so the default dev provider, the TOTP/WebAuthn providers, and the
// credential-free offline eval gate never even parse it.
//
// It implements the authorization-code + PKCE flow against any standards-
// compliant IdP (Okta, Auth0, Microsoft Entra ID, Google, Keycloak, …):
//   1. discover()              — OIDC discovery document (cached)
//   2. pkcePair()              — RFC 7636 S256 verifier/challenge
//   3. buildAuthorizationUrl() — the authorize redirect (state, nonce, PKCE,
//                                prompt=login + max_age=0 to force fresh auth)
//   4. exchangeCode()          — authorization_code → token response (id_token)
//   5. verifyIdToken()         — JWKS-backed RS/ES signature + claim validation
//
// PHI/secret posture: the IdP only ever sees the redirect parameters; no log
// content or finding data is ever sent. Only the verified `sub` claim is
// persisted (see step-up-verifier.ts). Nothing here is ledgered with token or
// claim values.

import {
  createHash,
  createPublicKey,
  randomBytes,
  verify as cryptoVerify,
  timingSafeEqual,
} from "node:crypto";

export interface OidcPolicy {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  /** Requested scopes; always includes `openid`. */
  scopes: string[];
  /** ID-token claim that identifies the user (default `sub`). */
  subjectClaim: string;
}

export interface OidcDiscovery {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
}

/** A JSON Web Key as it appears in a JWKS document. We only ever pass it
 *  straight to `createPublicKey({ key, format: "jwk" })`, so a permissive shape
 *  (plus the optional `kid`) is sufficient — avoids depending on the DOM lib's
 *  `JsonWebKey`, which isn't in the server tsconfig's lib set. */
type Jwk = Record<string, unknown> & { kid?: string };

export interface IdTokenClaims {
  iss?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  nonce?: string;
  sub?: string;
  [claim: string]: unknown;
}

function httpTimeoutMs(): number {
  const raw = process.env.STEP_UP_OIDC_HTTP_TIMEOUT_MS;
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) && n > 0 ? n : 5000;
}

async function fetchJson(url: string): Promise<unknown> {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), httpTimeoutMs());
  try {
    const res = await fetch(url, {
      signal: ac.signal,
      headers: { accept: "application/json" },
    });
    if (!res.ok) {
      // Status only — never echo the response body, which can reflect
      // request-derived values (see memory: external-client error PHI leak).
      throw new Error(`OIDC request to ${url} failed with status ${res.status}`);
    }
    return (await res.json()) as unknown;
  } finally {
    clearTimeout(timer);
  }
}

// --- discovery (cached) ----------------------------------------------------

interface CacheEntry<T> {
  value: T;
  exp: number;
}
const DISCOVERY_TTL_MS = 10 * 60 * 1000;
const discoveryCache = new Map<string, CacheEntry<OidcDiscovery>>();

/** Fetch (and cache) the IdP's OIDC discovery document. The issuer is the
 *  configured `STEP_UP_OIDC_ISSUER`; the well-known path is appended per the
 *  OIDC Discovery spec. */
export async function discover(issuer: string): Promise<OidcDiscovery> {
  const now = Date.now();
  const cached = discoveryCache.get(issuer);
  if (cached && cached.exp > now) return cached.value;
  const base = issuer.replace(/\/$/, "");
  const doc = (await fetchJson(
    `${base}/.well-known/openid-configuration`,
  )) as Record<string, unknown>;
  const authorizationEndpoint = doc.authorization_endpoint;
  const tokenEndpoint = doc.token_endpoint;
  const jwksUri = doc.jwks_uri;
  const docIssuer = (doc.issuer as string | undefined) ?? issuer;
  if (
    typeof authorizationEndpoint !== "string" ||
    typeof tokenEndpoint !== "string" ||
    typeof jwksUri !== "string"
  ) {
    throw new Error("OIDC discovery document is missing required endpoints");
  }
  const value: OidcDiscovery = {
    issuer: docIssuer,
    authorizationEndpoint,
    tokenEndpoint,
    jwksUri,
  };
  discoveryCache.set(issuer, { value, exp: now + DISCOVERY_TTL_MS });
  return value;
}

// --- PKCE + random tokens --------------------------------------------------

/** A cryptographically-random base64url token (default 32 bytes of entropy).
 *  Used for the `state` and `nonce` parameters. */
export function randomUrlToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** RFC 7636 PKCE pair: a high-entropy verifier and its S256 challenge. */
export function pkcePair(): PkcePair {
  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

// --- authorization URL -----------------------------------------------------

/** Build the IdP authorize redirect for the authorization-code + PKCE flow.
 *  `prompt=login` + `max_age=0` force a fresh authentication every step-up so a
 *  lingering IdP session cannot silently satisfy the second factor. */
export function buildAuthorizationUrl(args: {
  discovery: OidcDiscovery;
  policy: OidcPolicy;
  state: string;
  nonce: string;
  codeChallenge: string;
}): string {
  const url = new URL(args.discovery.authorizationEndpoint);
  const params = url.searchParams;
  params.set("response_type", "code");
  params.set("client_id", args.policy.clientId);
  params.set("redirect_uri", args.policy.redirectUri);
  params.set("scope", args.policy.scopes.join(" "));
  params.set("state", args.state);
  params.set("nonce", args.nonce);
  params.set("code_challenge", args.codeChallenge);
  params.set("code_challenge_method", "S256");
  params.set("prompt", "login");
  params.set("max_age", "0");
  return url.toString();
}

// --- token exchange --------------------------------------------------------

/** Exchange an authorization code for tokens at the token endpoint. The client
 *  secret is sent via HTTP Basic auth (the most widely-supported client-auth
 *  method); the PKCE verifier binds the code to this client. Returns the raw
 *  id_token (a compact JWS) for verification by verifyIdToken(). */
export async function exchangeCode(args: {
  discovery: OidcDiscovery;
  policy: OidcPolicy;
  code: string;
  codeVerifier: string;
}): Promise<{ idToken: string }> {
  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", args.code);
  body.set("redirect_uri", args.policy.redirectUri);
  body.set("client_id", args.policy.clientId);
  body.set("code_verifier", args.codeVerifier);
  const basic = Buffer.from(
    `${encodeURIComponent(args.policy.clientId)}:${encodeURIComponent(
      args.policy.clientSecret,
    )}`,
  ).toString("base64");
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), httpTimeoutMs());
  let res: Response;
  try {
    res = await fetch(args.discovery.tokenEndpoint, {
      method: "POST",
      signal: ac.signal,
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
        authorization: `Basic ${basic}`,
      },
      body: body.toString(),
    });
  } finally {
    clearTimeout(timer);
  }
  if (!res.ok) {
    // Status only — the error body can reflect the supplied code/secret.
    throw new Error(`OIDC token exchange failed with status ${res.status}`);
  }
  const json = (await res.json()) as { id_token?: unknown };
  if (typeof json.id_token !== "string" || json.id_token.length === 0) {
    throw new Error("OIDC token response did not include an id_token");
  }
  return { idToken: json.id_token };
}

// --- ID-token verification (JWKS-backed) -----------------------------------

const JWKS_TTL_MS = 10 * 60 * 1000;
const jwksCache = new Map<string, CacheEntry<Jwk[]>>();

async function getJwks(jwksUri: string, forceRefresh = false): Promise<Jwk[]> {
  const now = Date.now();
  if (!forceRefresh) {
    const cached = jwksCache.get(jwksUri);
    if (cached && cached.exp > now) return cached.value;
  }
  const doc = (await fetchJson(jwksUri)) as { keys?: unknown };
  const keys = Array.isArray(doc.keys) ? (doc.keys as Jwk[]) : [];
  jwksCache.set(jwksUri, { value: keys, exp: now + JWKS_TTL_MS });
  return keys;
}

// Supported JOSE algs → node verify parameters. ECDSA JWS signatures are raw
// r||s (IEEE P1363), so node must be told not to expect DER.
function algParams(
  alg: string,
): { hash: string; ec: boolean } | null {
  switch (alg) {
    case "RS256":
      return { hash: "RSA-SHA256", ec: false };
    case "RS384":
      return { hash: "RSA-SHA384", ec: false };
    case "RS512":
      return { hash: "RSA-SHA512", ec: false };
    case "ES256":
      return { hash: "SHA256", ec: true };
    case "ES384":
      return { hash: "SHA384", ec: true };
    case "ES512":
      return { hash: "SHA512", ec: true };
    default:
      return null;
  }
}

function decodeSegment(seg: string): Buffer {
  return Buffer.from(seg, "base64url");
}

function constantTimeStrEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

/** Verify an ID token: JWKS-backed RS/ES signature, then iss/aud/exp/iat/nonce
 *  claim checks. Returns the validated claims, or throws on any failure (the
 *  caller treats a throw as "step-up refused"). Clock skew tolerance is small
 *  and fixed. */
export async function verifyIdToken(args: {
  idToken: string;
  discovery: OidcDiscovery;
  policy: OidcPolicy;
  nonce: string;
}): Promise<IdTokenClaims> {
  const parts = args.idToken.split(".");
  if (parts.length !== 3) throw new Error("malformed id_token");
  const [headerB64, payloadB64, sigB64] = parts;
  const header = JSON.parse(decodeSegment(headerB64).toString("utf8")) as {
    alg?: string;
    kid?: string;
  };
  if (!header.alg) throw new Error("id_token header missing alg");
  const params = algParams(header.alg);
  if (!params) throw new Error(`unsupported id_token alg: ${header.alg}`);

  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const signature = decodeSegment(sigB64);

  // Find the signing key by kid; on a miss refetch the JWKS once (keys rotate).
  const verifyWith = (keys: Jwk[]): boolean => {
    const candidates = keys.filter(
      (k) => !header.kid || (k as { kid?: string }).kid === header.kid,
    );
    const pool = candidates.length > 0 ? candidates : keys;
    for (const jwk of pool) {
      let keyObject;
      try {
        // node's typings want the DOM `JsonWebKey` here; our permissive `Jwk`
        // shape is structurally compatible at runtime.
        keyObject = createPublicKey({
          key: jwk as unknown as import("node:crypto").JsonWebKeyInput["key"],
          format: "jwk",
        });
      } catch {
        continue;
      }
      const ok = cryptoVerify(
        params.hash,
        signingInput,
        params.ec
          ? { key: keyObject, dsaEncoding: "ieee-p1363" }
          : keyObject,
        signature,
      );
      if (ok) return true;
    }
    return false;
  };

  let verified = verifyWith(await getJwks(args.discovery.jwksUri));
  if (!verified) {
    verified = verifyWith(await getJwks(args.discovery.jwksUri, true));
  }
  if (!verified) throw new Error("id_token signature verification failed");

  const claims = JSON.parse(
    decodeSegment(payloadB64).toString("utf8"),
  ) as IdTokenClaims;

  // iss MUST match the discovery issuer exactly.
  if (
    typeof claims.iss !== "string" ||
    !constantTimeStrEqual(claims.iss, args.discovery.issuer)
  ) {
    throw new Error("id_token iss mismatch");
  }
  // aud MUST include our client id.
  const auds = Array.isArray(claims.aud)
    ? claims.aud
    : typeof claims.aud === "string"
      ? [claims.aud]
      : [];
  if (!auds.some((a) => constantTimeStrEqual(a, args.policy.clientId))) {
    throw new Error("id_token aud mismatch");
  }
  // exp/iat with a small fixed skew tolerance.
  const nowSec = Math.floor(Date.now() / 1000);
  const SKEW = 60;
  if (typeof claims.exp !== "number" || claims.exp + SKEW < nowSec) {
    throw new Error("id_token expired");
  }
  if (typeof claims.iat !== "number" || claims.iat - SKEW > nowSec) {
    throw new Error("id_token iat in the future");
  }
  // nonce MUST match the one we issued (replay / token-injection guard).
  if (
    typeof claims.nonce !== "string" ||
    !constantTimeStrEqual(claims.nonce, args.nonce)
  ) {
    throw new Error("id_token nonce mismatch");
  }
  return claims;
}

// Exposed for unit tests of the pure helpers.
export const __testing = { algParams, constantTimeStrEqual };
