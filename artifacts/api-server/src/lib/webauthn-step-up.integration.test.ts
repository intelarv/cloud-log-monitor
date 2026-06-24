import { describe, it, expect, beforeAll, afterAll } from "vitest";
import {
  generateKeyPairSync,
  createHash,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { bootstrap } from "@workspace/db";
import {
  beginWebauthnRegistration,
  finishWebauthnRegistration,
  beginWebauthnStepUp,
  getFactorStatus,
  getStepUpVerifier,
} from "./step-up-verifier";
import { uniqueTenant } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// DB-backed coverage for the WebAuthn step-up verifier
// (STEP_UP_PROVIDER=webauthn): register → challenge → assert → replay refusal →
// tenant isolation, against the real step_up_factors table (RLS-scoped via
// withTenant) with the credential + pending challenge encrypted at rest. Each
// test uses a fresh tenant id (uniqueTenant) so rows can't collide (M1.9).
//
// We never run a real browser — instead we hand-build the ceremonies in-process
// with a tiny CBOR encoder and a generated EC P-256 key, exactly as the pure
// webauthn.test.ts does, then drive the DB-backed enrollment/verify functions.
// ---------------------------------------------------------------------------

const prev = {
  provider: process.env.STEP_UP_PROVIDER,
  rpId: process.env.WEBAUTHN_RP_ID,
  origin: process.env.WEBAUTHN_ORIGIN,
};
const RP_ID = "example.com";
const ORIGIN = "https://example.com";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  process.env.STEP_UP_PROVIDER = "webauthn";
  process.env.WEBAUTHN_RP_ID = RP_ID;
  process.env.WEBAUTHN_ORIGIN = ORIGIN;
});

afterAll(() => {
  for (const [k, v] of [
    ["STEP_UP_PROVIDER", prev.provider],
    ["WEBAUTHN_RP_ID", prev.rpId],
    ["WEBAUTHN_ORIGIN", prev.origin],
  ] as const) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
});

// --- minimal CBOR encoder (supported subset) -------------------------------

function cborUint(major: number, n: number): Buffer {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  if (n < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(n, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(n, 1);
  return b;
}

function cborEncode(value: unknown): Buffer {
  if (typeof value === "number") {
    return value < 0 ? cborUint(1, -1 - value) : cborUint(0, value);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([cborUint(2, value.length), value]);
  if (typeof value === "string") {
    const s = Buffer.from(value, "utf8");
    return Buffer.concat([cborUint(3, s.length), s]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborUint(4, value.length), ...value.map(cborEncode)]);
  }
  if (value instanceof Map) {
    const parts = [cborUint(5, value.size)];
    for (const [k, v] of value) parts.push(cborEncode(k), cborEncode(v));
    return Buffer.concat(parts);
  }
  throw new Error("cbor encode: unsupported");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function coseEc2(pub: KeyObject): Map<number, number | Buffer> {
  const jwk = pub.export({ format: "jwk" });
  return new Map<number, number | Buffer>([
    [1, 2],
    [3, -7],
    [-1, 1],
    [-2, Buffer.from(jwk.x as string, "base64url")],
    [-3, Buffer.from(jwk.y as string, "base64url")],
  ]);
}

function rpIdHash(rpId: string): Buffer {
  return createHash("sha256").update(Buffer.from(rpId, "utf8")).digest();
}

function clientDataJSON(type: string, challenge: string, origin: string): string {
  return b64url(Buffer.from(JSON.stringify({ type, challenge, origin }), "utf8"));
}

function regCeremony(pub: KeyObject, challenge: string, credentialId: Buffer) {
  const aaguid = Buffer.alloc(16);
  const credLen = Buffer.alloc(2);
  credLen.writeUInt16BE(credentialId.length);
  const sc = Buffer.alloc(4); // signCount 0
  const authData = Buffer.concat([
    rpIdHash(RP_ID),
    Buffer.from([0x41]), // UP + AT
    sc,
    aaguid,
    credLen,
    credentialId,
    cborEncode(coseEc2(pub)),
  ]);
  return {
    attestationObject: b64url(
      cborEncode(
        new Map<string, unknown>([
          ["fmt", "none"],
          ["attStmt", new Map()],
          ["authData", authData],
        ]),
      ),
    ),
    clientDataJSON: clientDataJSON("webauthn.create", challenge, ORIGIN),
  };
}

function assertCeremony(
  priv: KeyObject,
  challenge: string,
  credentialId: Buffer,
  signCount: number,
): string {
  const sc = Buffer.alloc(4);
  sc.writeUInt32BE(signCount);
  const authData = Buffer.concat([rpIdHash(RP_ID), Buffer.from([0x01]), sc]); // UP only
  const cdJSON = clientDataJSON("webauthn.get", challenge, ORIGIN);
  const cdHash = createHash("sha256").update(Buffer.from(cdJSON, "base64url")).digest();
  const signature = sign("sha256", Buffer.concat([authData, cdHash]), {
    key: priv,
    dsaEncoding: "der",
  });
  return JSON.stringify({
    credentialId: b64url(credentialId),
    clientDataJSON: cdJSON,
    authenticatorData: b64url(authData),
    signature: b64url(signature),
  });
}

function p256() {
  return generateKeyPairSync("ec", { namedCurve: "P-256" });
}

async function enroll(tenant: string, user: string) {
  const { publicKey, privateKey } = p256();
  const credentialId = randomBytes(16);
  const begin = await beginWebauthnRegistration(tenant, user);
  const cer = regCeremony(publicKey, begin.challenge, credentialId);
  const ok = await finishWebauthnRegistration(tenant, user, cer);
  expect(ok).toBe(true);
  return { privateKey, credentialId };
}

describe("WebAuthn enrollment + step-up over the DB", () => {
  it("registers a credential, then satisfies a step-up via a fresh challenge", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-1";
    const verifier = getStepUpVerifier();
    expect(verifier.kind).toBe("webauthn");

    // Unverified before registration finishes.
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: false,
      verified: false,
    });

    const { privateKey, credentialId } = await enroll(tenant, user);
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: true,
      verified: true,
    });

    // Step-up: get a challenge, sign it, verify.
    const ch = await beginWebauthnStepUp(tenant, user);
    expect(ch).not.toBeNull();
    expect(ch!.allowCredentials).toEqual([b64url(credentialId)]);
    const token = assertCeremony(privateKey, ch!.challenge, credentialId, 5);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(true);
  });

  it("refuses a replay of a consumed challenge", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-2";
    const { privateKey, credentialId } = await enroll(tenant, user);
    const verifier = getStepUpVerifier();

    const ch = await beginWebauthnStepUp(tenant, user);
    const token = assertCeremony(privateKey, ch!.challenge, credentialId, 5);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(true);
    // Same assertion again (challenge already consumed) → refused.
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(false);
  });

  it("refuses a step-up before any challenge is issued", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-3";
    const { privateKey, credentialId } = await enroll(tenant, user);
    const verifier = getStepUpVerifier();
    // Craft an assertion for a challenge the server never issued.
    const token = assertCeremony(privateKey, randomBytes(32).toString("base64url"), credentialId, 5);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token })).toBe(false);
  });

  it("enforces the signature-counter clone guard across step-ups", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-4";
    const { privateKey, credentialId } = await enroll(tenant, user);
    const verifier = getStepUpVerifier();

    const ch1 = await beginWebauthnStepUp(tenant, user);
    const t1 = assertCeremony(privateKey, ch1!.challenge, credentialId, 7);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token: t1 })).toBe(true);

    // Next step-up presents a NON-increasing counter → clone → refused.
    const ch2 = await beginWebauthnStepUp(tenant, user);
    const t2 = assertCeremony(privateKey, ch2!.challenge, credentialId, 7);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token: t2 })).toBe(false);

    // A strictly greater counter is accepted.
    const ch3 = await beginWebauthnStepUp(tenant, user);
    const t3 = assertCeremony(privateKey, ch3!.challenge, credentialId, 8);
    expect(await verifier.verify({ tenantId: tenant, sub: user, token: t3 })).toBe(true);
  });

  it("admits only one of two concurrent verifies for the same challenge (CAS)", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-5";
    const { privateKey, credentialId } = await enroll(tenant, user);
    const verifier = getStepUpVerifier();
    const ch = await beginWebauthnStepUp(tenant, user);
    const token = assertCeremony(privateKey, ch!.challenge, credentialId, 9);
    const results = await Promise.all([
      verifier.verify({ tenantId: tenant, sub: user, token }),
      verifier.verify({ tenantId: tenant, sub: user, token }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
  });

  it("isolates credentials by tenant (RLS) — no cross-tenant verify", async () => {
    const tenantA = uniqueTenant("wa");
    const tenantB = uniqueTenant("wa");
    const user = "shared-name";
    const { privateKey, credentialId } = await enroll(tenantA, user);
    const verifier = getStepUpVerifier();

    expect(await getFactorStatus(tenantB, user)).toEqual({
      enrolled: false,
      verified: false,
    });
    // Tenant B cannot get a challenge (no credential).
    expect(await beginWebauthnStepUp(tenantB, user)).toBeNull();

    // Even with tenant A's valid challenge, verifying under tenant B fails.
    const ch = await beginWebauthnStepUp(tenantA, user);
    const token = assertCeremony(privateKey, ch!.challenge, credentialId, 3);
    expect(await verifier.verify({ tenantId: tenantB, sub: user, token })).toBe(false);
  });

  it("refuses registration finish with a tampered challenge", async () => {
    const tenant = uniqueTenant("wa");
    const user = "analyst-6";
    const { publicKey } = p256();
    const credentialId = randomBytes(16);
    await beginWebauthnRegistration(tenant, user);
    // Use a challenge the server didn't issue.
    const cer = regCeremony(publicKey, randomBytes(32).toString("base64url"), credentialId);
    expect(await finishWebauthnRegistration(tenant, user, cer)).toBe(false);
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: true,
      verified: false,
    });
  });
});
