import { describe, it, expect, vi, afterEach } from "vitest";
import {
  generateKeyPairSync,
  sign as cryptoSign,
  createHash,
  type KeyObject,
} from "node:crypto";
import {
  discover,
  pkcePair,
  randomUrlToken,
  buildAuthorizationUrl,
  exchangeCode,
  verifyIdToken,
  __testing,
  type OidcDiscovery,
  type OidcPolicy,
} from "./oidc";

// ---------------------------------------------------------------------------
// Offline coverage for the hand-rolled OIDC relying-party helpers. No SDK, no
// network, no env: we generate keypairs in-process, hand-sign compact JWS ID
// tokens, serve a JWKS + discovery + token response via a stubbed global fetch,
// and exercise discovery, PKCE, the authorize URL, the token exchange, and
// ID-token verification end-to-end plus the negative paths (wrong iss/aud/nonce,
// expired, future iat, tampered signature, wrong key, unsupported alg).
// ---------------------------------------------------------------------------

const ISSUER = "https://idp.example.com";
const CLIENT_ID = "phia-client";

const DISCOVERY: OidcDiscovery = {
  issuer: ISSUER,
  authorizationEndpoint: `${ISSUER}/authorize`,
  tokenEndpoint: `${ISSUER}/token`,
  jwksUri: `${ISSUER}/jwks`,
};

const POLICY: OidcPolicy = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  clientSecret: "s3cr3t",
  redirectUri: "https://app.example.com/oidc-callback",
  scopes: ["openid", "profile", "email"],
  subjectClaim: "sub",
};

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

interface SigningKey {
  priv: KeyObject;
  jwk: Record<string, unknown>;
  alg: string;
  ec: boolean;
}

function rsaKey(kid = "rsa-1"): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" };
  return { priv: privateKey, jwk, alg: "RS256", ec: false };
}

function ecKey(kid = "ec-1"): SigningKey {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, alg: "ES256", use: "sig" };
  return { priv: privateKey, jwk, alg: "ES256", ec: false };
}

/** Hand-sign a compact JWS ID token with the given key + claims. */
function signIdToken(
  key: SigningKey,
  claims: Record<string, unknown>,
  opts: { alg?: string; kid?: string; tamper?: boolean } = {},
): string {
  const alg = opts.alg ?? key.alg;
  const header = { alg, kid: opts.kid ?? (key.jwk.kid as string), typ: "JWT" };
  const headerB64 = b64url(Buffer.from(JSON.stringify(header), "utf8"));
  const payloadB64 = b64url(Buffer.from(JSON.stringify(claims), "utf8"));
  const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
  const hash =
    alg === "ES256"
      ? "SHA256"
      : alg === "RS256"
        ? "RSA-SHA256"
        : "RSA-SHA256";
  const sig = key.alg === "ES256"
    ? cryptoSign(hash, signingInput, { key: key.priv, dsaEncoding: "ieee-p1363" })
    : cryptoSign(hash, signingInput, key.priv);
  if (opts.tamper) sig[sig.length - 1] ^= 0xff;
  return `${headerB64}.${payloadB64}.${b64url(sig)}`;
}

function freshClaims(over: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: ISSUER,
    aud: CLIENT_ID,
    sub: "user-123",
    nonce: "the-nonce",
    iat: now,
    exp: now + 300,
    ...over,
  };
}

// --- fetch stubbing --------------------------------------------------------

interface FetchRoutes {
  jwksKeys?: Record<string, unknown>[];
  discoveryDoc?: Record<string, unknown>;
  tokenResponse?: { status?: number; body?: unknown };
}

function stubFetch(routes: FetchRoutes) {
  const fn = vi.fn(async (input: string | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    const json = (body: unknown, status = 200) =>
      ({
        ok: status >= 200 && status < 300,
        status,
        json: async () => body,
      }) as unknown as Response;
    if (url.includes("/.well-known/openid-configuration")) {
      return json(
        routes.discoveryDoc ?? {
          issuer: ISSUER,
          authorization_endpoint: DISCOVERY.authorizationEndpoint,
          token_endpoint: DISCOVERY.tokenEndpoint,
          jwks_uri: DISCOVERY.jwksUri,
        },
      );
    }
    if (url.includes("/jwks")) {
      return json({ keys: routes.jwksKeys ?? [] });
    }
    if (url.includes("/token") && init?.method === "POST") {
      const r = routes.tokenResponse ?? {};
      return json(r.body ?? {}, r.status ?? 200);
    }
    throw new Error(`unexpected fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("oidc pure helpers", () => {
  it("pkcePair produces an S256 challenge of the verifier", () => {
    const { verifier, challenge } = pkcePair();
    expect(verifier.length).toBeGreaterThan(20);
    const expected = createHash("sha256").update(verifier).digest("base64url");
    expect(challenge).toBe(expected);
  });

  it("randomUrlToken is base64url with the requested entropy", () => {
    const t = randomUrlToken(32);
    expect(Buffer.from(t, "base64url").length).toBe(32);
    expect(t).not.toMatch(/[+/=]/);
  });

  it("buildAuthorizationUrl carries every required param", () => {
    const url = new URL(
      buildAuthorizationUrl({
        discovery: DISCOVERY,
        policy: POLICY,
        state: "st",
        nonce: "no",
        codeChallenge: "cc",
      }),
    );
    expect(url.origin + url.pathname).toBe(`${ISSUER}/authorize`);
    const p = url.searchParams;
    expect(p.get("response_type")).toBe("code");
    expect(p.get("client_id")).toBe(CLIENT_ID);
    expect(p.get("redirect_uri")).toBe(POLICY.redirectUri);
    expect(p.get("scope")).toBe("openid profile email");
    expect(p.get("state")).toBe("st");
    expect(p.get("nonce")).toBe("no");
    expect(p.get("code_challenge")).toBe("cc");
    expect(p.get("code_challenge_method")).toBe("S256");
    expect(p.get("prompt")).toBe("login");
    expect(p.get("max_age")).toBe("0");
  });

  it("algParams maps supported algs and rejects others", () => {
    expect(__testing.algParams("RS256")).toEqual({ hash: "RSA-SHA256", ec: false });
    expect(__testing.algParams("ES256")).toEqual({ hash: "SHA256", ec: true });
    expect(__testing.algParams("none")).toBeNull();
    expect(__testing.algParams("HS256")).toBeNull();
  });

  it("constantTimeStrEqual compares by value and rejects length mismatch", () => {
    expect(__testing.constantTimeStrEqual("abc", "abc")).toBe(true);
    expect(__testing.constantTimeStrEqual("abc", "abd")).toBe(false);
    expect(__testing.constantTimeStrEqual("abc", "abcd")).toBe(false);
  });
});

describe("oidc discovery", () => {
  it("fetches and normalizes the discovery document", async () => {
    stubFetch({});
    // Use a unique issuer to avoid the module-level discovery cache.
    const iss = `${ISSUER}/disc-${Math.random().toString(36).slice(2)}`;
    const fn = vi.fn(async () =>
      ({
        ok: true,
        status: 200,
        json: async () => ({
          issuer: iss,
          authorization_endpoint: `${iss}/authorize`,
          token_endpoint: `${iss}/token`,
          jwks_uri: `${iss}/jwks`,
        }),
      }) as unknown as Response,
    );
    vi.stubGlobal("fetch", fn);
    const d = await discover(iss);
    expect(d.issuer).toBe(iss);
    expect(d.tokenEndpoint).toBe(`${iss}/token`);
    expect(d.jwksUri).toBe(`${iss}/jwks`);
  });

  it("throws (status only) on a discovery document missing endpoints", async () => {
    const iss = `${ISSUER}/bad-${Math.random().toString(36).slice(2)}`;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        ({ ok: true, status: 200, json: async () => ({ issuer: iss }) }) as unknown as Response,
      ),
    );
    await expect(discover(iss)).rejects.toThrow(/missing required endpoints/);
  });
});

describe("oidc token exchange", () => {
  it("returns the id_token on a successful exchange", async () => {
    const key = rsaKey();
    const idToken = signIdToken(key, freshClaims());
    stubFetch({ tokenResponse: { body: { id_token: idToken } } });
    const res = await exchangeCode({
      discovery: DISCOVERY,
      policy: POLICY,
      code: "auth-code",
      codeVerifier: "verifier",
    });
    expect(res.idToken).toBe(idToken);
  });

  it("throws status-only when the token endpoint errors", async () => {
    stubFetch({ tokenResponse: { status: 400, body: { error: "invalid_grant" } } });
    await expect(
      exchangeCode({ discovery: DISCOVERY, policy: POLICY, code: "x", codeVerifier: "y" }),
    ).rejects.toThrow(/status 400/);
  });

  it("throws when the token response omits id_token", async () => {
    stubFetch({ tokenResponse: { body: { access_token: "a" } } });
    await expect(
      exchangeCode({ discovery: DISCOVERY, policy: POLICY, code: "x", codeVerifier: "y" }),
    ).rejects.toThrow(/did not include an id_token/);
  });
});

describe("oidc id-token verification", () => {
  for (const make of [rsaKey, ecKey]) {
    it(`verifies a well-formed ${make === rsaKey ? "RS256" : "ES256"} id_token`, async () => {
      const key = make();
      stubFetch({ jwksKeys: [key.jwk] });
      const idToken = signIdToken(key, freshClaims());
      const claims = await verifyIdToken({
        idToken,
        discovery: DISCOVERY,
        policy: POLICY,
        nonce: "the-nonce",
      });
      expect(claims.sub).toBe("user-123");
    });
  }

  it("rejects a token signed by a key not in the JWKS", async () => {
    const signer = rsaKey("rsa-signer");
    const other = rsaKey("rsa-other");
    stubFetch({ jwksKeys: [other.jwk] });
    const idToken = signIdToken(signer, freshClaims(), { kid: "rsa-other" });
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/signature verification failed/);
  });

  it("rejects a tampered signature", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const idToken = signIdToken(key, freshClaims(), { tamper: true });
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/signature verification failed/);
  });

  it("rejects an unsupported alg", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    // Forge an HS256 header but sign with RSA — alg gate trips before verify.
    const idToken = signIdToken(key, freshClaims(), { alg: "HS256" });
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/unsupported id_token alg/);
  });

  it("rejects a wrong issuer", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const idToken = signIdToken(key, freshClaims({ iss: "https://evil.example" }));
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/iss mismatch/);
  });

  it("rejects a wrong audience", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const idToken = signIdToken(key, freshClaims({ aud: "someone-else" }));
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/aud mismatch/);
  });

  it("accepts an array aud that includes the client id", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const idToken = signIdToken(key, freshClaims({ aud: ["other", CLIENT_ID] }));
    const claims = await verifyIdToken({
      idToken,
      discovery: DISCOVERY,
      policy: POLICY,
      nonce: "the-nonce",
    });
    expect(claims.sub).toBe("user-123");
  });

  it("rejects an expired token", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(key, freshClaims({ exp: now - 3600, iat: now - 7200 }));
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/expired/);
  });

  it("rejects an iat in the future", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const now = Math.floor(Date.now() / 1000);
    const idToken = signIdToken(key, freshClaims({ iat: now + 3600, exp: now + 7200 }));
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/iat in the future/);
  });

  it("rejects a nonce mismatch (replay guard)", async () => {
    const key = rsaKey();
    stubFetch({ jwksKeys: [key.jwk] });
    const idToken = signIdToken(key, freshClaims({ nonce: "different" }));
    await expect(
      verifyIdToken({ idToken, discovery: DISCOVERY, policy: POLICY, nonce: "the-nonce" }),
    ).rejects.toThrow(/nonce mismatch/);
  });

  it("rejects a malformed token", async () => {
    stubFetch({ jwksKeys: [] });
    await expect(
      verifyIdToken({
        idToken: "not.a.jwt.at.all",
        discovery: DISCOVERY,
        policy: POLICY,
        nonce: "the-nonce",
      }),
    ).rejects.toThrow(/malformed id_token/);
  });
});
