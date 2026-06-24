import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import {
  generateKeyPairSync,
  sign as cryptoSign,
  type KeyObject,
} from "node:crypto";
import { bootstrap } from "@workspace/db";
import {
  beginOidcRegistration,
  finishOidcRegistration,
  beginOidcStepUp,
  getFactorStatus,
  getStepUpVerifier,
} from "./step-up-verifier";
import { uniqueTenant } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// DB-backed coverage for the OIDC step-up verifier (STEP_UP_PROVIDER=oidc):
// enroll (link federated identity) → step-up → replay refusal → subject
// mismatch → tenant isolation, against the real step_up_factors table
// (RLS-scoped via withTenant) with the pending state/nonce/PKCE + linked subject
// encrypted at rest. Each test uses a fresh tenant id (uniqueTenant) so rows
// can't collide (M1.9).
//
// We never reach a real IdP. The global fetch is stubbed to serve a static
// discovery + JWKS and a token endpoint that returns whatever id_token the test
// has staged. We capture the state+nonce the begin step embeds in the authorize
// URL, then hand-sign an id_token with that nonce so the exchange + verify pass.
// ---------------------------------------------------------------------------

const ISSUER = "https://idp.test.local";
const CLIENT_ID = "phia-oidc-client";

const prev = {
  provider: process.env.STEP_UP_PROVIDER,
  issuer: process.env.STEP_UP_OIDC_ISSUER,
  clientId: process.env.STEP_UP_OIDC_CLIENT_ID,
  clientSecret: process.env.STEP_UP_OIDC_CLIENT_SECRET,
  redirectUri: process.env.STEP_UP_OIDC_REDIRECT_URI,
};

// One signing key for the whole suite; its public half is served as the JWKS.
let signingKey: KeyObject;
let jwk: Record<string, unknown>;

// The id_token the stubbed token endpoint will return on the next exchange.
let stagedIdToken = "";

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function signIdToken(claims: Record<string, unknown>): string {
  const header = { alg: "RS256", kid: "test-key", typ: "JWT" };
  const headerB64 = b64url(Buffer.from(JSON.stringify(header), "utf8"));
  const payloadB64 = b64url(Buffer.from(JSON.stringify(claims), "utf8"));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const sig = cryptoSign("RSA-SHA256", signingInput, signingKey);
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

function freshClaims(sub: string, nonce: string): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub,
    nonce,
    iat: now,
    exp: now + 300,
  };
}

/** Parse the state+nonce the begin step embedded in the authorize URL. */
function readStateNonce(authorizationUrl: string): { state: string; nonce: string } {
  const u = new URL(authorizationUrl);
  return {
    state: u.searchParams.get("state")!,
    nonce: u.searchParams.get("nonce")!,
  };
}

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  signingKey = privateKey;
  jwk = { ...publicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" };

  process.env.STEP_UP_PROVIDER = "oidc";
  process.env.STEP_UP_OIDC_ISSUER = ISSUER;
  process.env.STEP_UP_OIDC_CLIENT_ID = CLIENT_ID;
  process.env.STEP_UP_OIDC_CLIENT_SECRET = "test-secret";
  process.env.STEP_UP_OIDC_REDIRECT_URI = "https://app.test.local/oidc-callback";

  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      const json = (body: unknown, status = 200) =>
        ({
          ok: status >= 200 && status < 300,
          status,
          json: async () => body,
        }) as unknown as Response;
      if (url.includes("/.well-known/openid-configuration")) {
        return json({
          issuer: ISSUER,
          authorization_endpoint: `${ISSUER}/authorize`,
          token_endpoint: `${ISSUER}/token`,
          jwks_uri: `${ISSUER}/jwks`,
        });
      }
      if (url.includes("/jwks")) return json({ keys: [jwk] });
      if (url.includes("/token") && init?.method === "POST") {
        return json({ id_token: stagedIdToken, token_type: "Bearer" });
      }
      throw new Error(`unexpected fetch: ${url}`);
    }),
  );
});

afterAll(() => {
  vi.unstubAllGlobals();
  for (const [k, v] of [
    ["STEP_UP_PROVIDER", prev.provider],
    ["STEP_UP_OIDC_ISSUER", prev.issuer],
    ["STEP_UP_OIDC_CLIENT_ID", prev.clientId],
    ["STEP_UP_OIDC_CLIENT_SECRET", prev.clientSecret],
    ["STEP_UP_OIDC_REDIRECT_URI", prev.redirectUri],
  ] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

/** Run enrollment for (tenant,user) linking federated `sub`. */
async function enroll(tenant: string, user: string, sub: string) {
  const begin = await beginOidcRegistration(tenant, user);
  const { state, nonce } = readStateNonce(begin.authorizationUrl);
  stagedIdToken = signIdToken(freshClaims(sub, nonce));
  const ok = await finishOidcRegistration(tenant, user, { code: "auth-code", state });
  expect(ok).toBe(true);
}

describe("OIDC enrollment + step-up over the DB", () => {
  it("links a federated identity, then satisfies a step-up", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-1";
    const verifier = getStepUpVerifier();
    expect(verifier.kind).toBe("oidc");

    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: false,
      verified: false,
    });

    await enroll(tenant, user, "idp-subject-1");
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: true,
      verified: true,
    });

    // Step-up: fresh authorize URL → new state/nonce → matching id_token.
    const ch = await beginOidcStepUp(tenant, user);
    expect(ch).not.toBeNull();
    const { state, nonce } = readStateNonce(ch!.authorizationUrl);
    stagedIdToken = signIdToken(freshClaims("idp-subject-1", nonce));
    const token = JSON.stringify({ code: "step-code", state });
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(true);
  });

  it("refuses a replay of a consumed callback", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-2";
    await enroll(tenant, user, "idp-subject-2");
    const verifier = getStepUpVerifier();

    const ch = await beginOidcStepUp(tenant, user);
    const { state, nonce } = readStateNonce(ch!.authorizationUrl);
    stagedIdToken = signIdToken(freshClaims("idp-subject-2", nonce));
    const token = JSON.stringify({ code: "step-code", state });
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(true);
    // Same callback again (pending attempt already consumed) → refused.
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(false);
  });

  it("refuses a step-up whose federated subject differs from the linked one", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-3";
    await enroll(tenant, user, "idp-subject-3");
    const verifier = getStepUpVerifier();

    const ch = await beginOidcStepUp(tenant, user);
    const { state, nonce } = readStateNonce(ch!.authorizationUrl);
    // IdP returns a DIFFERENT subject than the one enrolled.
    stagedIdToken = signIdToken(freshClaims("someone-else", nonce));
    const token = JSON.stringify({ code: "step-code", state });
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(false);
  });

  it("refuses a callback whose state was never issued", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-4";
    await enroll(tenant, user, "idp-subject-4");
    const verifier = getStepUpVerifier();

    await beginOidcStepUp(tenant, user);
    // A state the server never issued.
    const token = JSON.stringify({ code: "step-code", state: "forged-state" });
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(false);
  });

  it("refuses a malformed (non-JSON) step-up token", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-5";
    await enroll(tenant, user, "idp-subject-5");
    const verifier = getStepUpVerifier();
    await beginOidcStepUp(tenant, user);
    expect(
      await verifier.verify({ tenantId: tenant, sub: user, token: "not-json" }),
    ).toBe(false);
  });

  it("refuses enrollment finish with a tampered state", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-6";
    const begin = await beginOidcRegistration(tenant, user);
    const { nonce } = readStateNonce(begin.authorizationUrl);
    stagedIdToken = signIdToken(freshClaims("idp-subject-6", nonce));
    // Wrong state → finish fails, factor stays unverified.
    const ok = await finishOidcRegistration(tenant, user, {
      code: "auth-code",
      state: "wrong-state",
    });
    expect(ok).toBe(false);
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: true,
      verified: false,
    });
  });

  it("admits only one of two concurrent verifies for the same callback (CAS)", async () => {
    const tenant = uniqueTenant("oidc");
    const user = "analyst-7";
    await enroll(tenant, user, "idp-subject-7");
    const verifier = getStepUpVerifier();
    const ch = await beginOidcStepUp(tenant, user);
    const { state, nonce } = readStateNonce(ch!.authorizationUrl);
    stagedIdToken = signIdToken(freshClaims("idp-subject-7", nonce));
    const token = JSON.stringify({ code: "step-code", state });
    const results = await Promise.all([
      verifier.verify({ tenantId: tenant, sub: user, token }),
      verifier.verify({ tenantId: tenant, sub: user, token }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("isolates linked identities by tenant (RLS) — no cross-tenant verify", async () => {
    const tenantA = uniqueTenant("oidc");
    const tenantB = uniqueTenant("oidc");
    const user = "shared-name";
    await enroll(tenantA, user, "idp-subject-shared");
    const verifier = getStepUpVerifier();

    expect(await getFactorStatus(tenantB, user)).toEqual({
      enrolled: false,
      verified: false,
    });
    // Tenant B has no linked identity → no authorize URL.
    expect(await beginOidcStepUp(tenantB, user)).toBeNull();

    // Even with tenant A's valid pending attempt, verifying under tenant B fails.
    const ch = await beginOidcStepUp(tenantA, user);
    const { state, nonce } = readStateNonce(ch!.authorizationUrl);
    stagedIdToken = signIdToken(freshClaims("idp-subject-shared", nonce));
    const token = JSON.stringify({ code: "step-code", state });
    expect(await verifier.verify({ tenantId: tenantB, sub: user, token })).toBe(false);
  });
});
