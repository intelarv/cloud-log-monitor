import { describe, it, expect } from "vitest";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  createHash,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import {
  randomChallenge,
  verifyRegistration,
  verifyAssertion,
  __testing,
  type WebauthnPolicy,
  type RegisteredCredential,
} from "./webauthn";

// ---------------------------------------------------------------------------
// Pure-crypto coverage for the hand-rolled WebAuthn verifier. No DB, no env, no
// SDK: we generate an EC P-256 key in-process, hand-build the COSE public key +
// authenticatorData + attestationObject (with a tiny CBOR ENCODER local to this
// file), and exercise both ceremonies end-to-end plus the negative paths
// (wrong challenge, wrong origin, wrong rpId, tampered signature, missing
// user-present flag, signature-counter clone detection).
// ---------------------------------------------------------------------------

const POLICY: WebauthnPolicy = {
  rpId: "example.com",
  origins: ["https://example.com"],
};

// --- minimal CBOR encoder (mirror of the decoder's supported subset) -------

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
    if (value < 0) return cborUint(1, -1 - value);
    return cborUint(0, value);
  }
  if (Buffer.isBuffer(value)) {
    return Buffer.concat([cborUint(2, value.length), value]);
  }
  if (typeof value === "string") {
    const s = Buffer.from(value, "utf8");
    return Buffer.concat([cborUint(3, s.length), s]);
  }
  if (Array.isArray(value)) {
    return Buffer.concat([cborUint(4, value.length), ...value.map(cborEncode)]);
  }
  if (value instanceof Map) {
    const parts = [cborUint(5, value.size)];
    for (const [k, v] of value) {
      parts.push(cborEncode(k), cborEncode(v));
    }
    return Buffer.concat(parts);
  }
  throw new Error("cbor encode: unsupported");
}

// --- helpers to build a credential + ceremonies ----------------------------

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

/** Build a COSE_Key map for an EC2 P-256 public key from a KeyObject. */
function coseEc2(pub: KeyObject, alg = -7): Map<number, number | Buffer> {
  const jwk = pub.export({ format: "jwk" });
  const x = Buffer.from(jwk.x as string, "base64url");
  const y = Buffer.from(jwk.y as string, "base64url");
  return new Map<number, number | Buffer>([
    [1, 2], // kty: EC2
    [3, alg], // alg
    [-1, 1], // crv: P-256
    [-2, x],
    [-3, y],
  ]);
}

function rpIdHash(rpId: string): Buffer {
  return createHash("sha256").update(Buffer.from(rpId, "utf8")).digest();
}

interface AuthDataOpts {
  rpId?: string;
  flags?: number;
  signCount?: number;
  credentialId?: Buffer;
  cose?: Map<number, number | Buffer>;
}

function buildAuthData(opts: AuthDataOpts): Buffer {
  const rpHash = rpIdHash(opts.rpId ?? POLICY.rpId);
  const flags = Buffer.from([opts.flags ?? 0x41]); // UP + AT by default
  const sc = Buffer.alloc(4);
  sc.writeUInt32BE(opts.signCount ?? 0);
  if (!opts.cose || !opts.credentialId) {
    return Buffer.concat([rpHash, flags, sc]);
  }
  const aaguid = Buffer.alloc(16);
  const credLen = Buffer.alloc(2);
  credLen.writeUInt16BE(opts.credentialId.length);
  return Buffer.concat([
    rpHash,
    flags,
    sc,
    aaguid,
    credLen,
    opts.credentialId,
    cborEncode(opts.cose),
  ]);
}

function clientDataJSON(type: string, challenge: string, origin: string): string {
  return b64url(
    Buffer.from(JSON.stringify({ type, challenge, origin }), "utf8"),
  );
}

function makeRegistration(
  pub: KeyObject,
  challenge: string,
  opts: { credentialId?: Buffer; flags?: number; rpId?: string; signCount?: number } = {},
) {
  const credentialId = opts.credentialId ?? randomBytes(16);
  const authData = buildAuthData({
    cose: coseEc2(pub),
    credentialId,
    flags: opts.flags,
    rpId: opts.rpId,
    signCount: opts.signCount,
  });
  const attestationObject = b64url(
    cborEncode(
      new Map<string, unknown>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authData],
      ]),
    ),
  );
  return {
    credentialId,
    attestationObject,
    clientDataJSON: clientDataJSON("webauthn.create", challenge, POLICY.origins[0]),
  };
}

function makeAssertion(
  priv: KeyObject,
  challenge: string,
  opts: { flags?: number; rpId?: string; signCount?: number; origin?: string } = {},
) {
  const authData = buildAuthData({
    flags: opts.flags ?? 0x01, // UP only, no AT
    rpId: opts.rpId,
    signCount: opts.signCount,
  });
  const cdJSON = clientDataJSON(
    "webauthn.get",
    challenge,
    opts.origin ?? POLICY.origins[0],
  );
  const cdHash = createHash("sha256")
    .update(Buffer.from(cdJSON, "base64url"))
    .digest();
  const signed = Buffer.concat([authData, cdHash]);
  const signature = sign("sha256", signed, { key: priv, dsaEncoding: "der" });
  return {
    clientDataJSON: cdJSON,
    authenticatorData: b64url(authData),
    signature: b64url(signature),
  };
}

function p256() {
  const { publicKey, privateKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
  });
  return { publicKey, privateKey };
}

describe("webauthn pure verifier — registration", () => {
  it("verifies a well-formed registration and extracts the credential", () => {
    const { publicKey } = p256();
    const challenge = randomChallenge();
    const reg = makeRegistration(publicKey, challenge);
    const cred = verifyRegistration(
      {
        attestationObject: reg.attestationObject,
        clientDataJSON: reg.clientDataJSON,
        expectedChallenge: challenge,
      },
      POLICY,
    );
    expect(cred).not.toBeNull();
    expect(cred!.alg).toBe(-7);
    expect(cred!.credentialId).toBe(b64url(reg.credentialId));
    // The extracted SPKI must equal the original key's SPKI.
    const expectedSpki = publicKey.export({ type: "spki", format: "der" }).toString("base64");
    expect(cred!.publicKeySpki).toBe(expectedSpki);
  });

  it("rejects a registration with the wrong challenge", () => {
    const { publicKey } = p256();
    const reg = makeRegistration(publicKey, randomChallenge());
    expect(
      verifyRegistration(
        { ...reg, expectedChallenge: randomChallenge() },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects a registration from a disallowed origin", () => {
    const { publicKey } = p256();
    const challenge = randomChallenge();
    const reg = makeRegistration(publicKey, challenge);
    const tampered = {
      attestationObject: reg.attestationObject,
      clientDataJSON: clientDataJSON("webauthn.create", challenge, "https://evil.example"),
      expectedChallenge: challenge,
    };
    expect(verifyRegistration(tampered, POLICY)).toBeNull();
  });

  it("rejects a registration for the wrong rpId", () => {
    const { publicKey } = p256();
    const challenge = randomChallenge();
    const reg = makeRegistration(publicKey, challenge, { rpId: "other.com" });
    expect(
      verifyRegistration(
        {
          attestationObject: reg.attestationObject,
          clientDataJSON: reg.clientDataJSON,
          expectedChallenge: challenge,
        },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects a registration without the user-present flag", () => {
    const { publicKey } = p256();
    const challenge = randomChallenge();
    const reg = makeRegistration(publicKey, challenge, { flags: 0x40 }); // AT, no UP
    expect(
      verifyRegistration(
        {
          attestationObject: reg.attestationObject,
          clientDataJSON: reg.clientDataJSON,
          expectedChallenge: challenge,
        },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects garbage input without throwing", () => {
    expect(
      verifyRegistration(
        {
          attestationObject: "not-cbor",
          clientDataJSON: "not-json",
          expectedChallenge: "x",
        },
        POLICY,
      ),
    ).toBeNull();
  });
});

describe("webauthn pure verifier — assertion", () => {
  function enroll(): {
    priv: KeyObject;
    cred: RegisteredCredential;
  } {
    const { publicKey, privateKey } = p256();
    const challenge = randomChallenge();
    const reg = makeRegistration(publicKey, challenge);
    const cred = verifyRegistration(
      {
        attestationObject: reg.attestationObject,
        clientDataJSON: reg.clientDataJSON,
        expectedChallenge: challenge,
      },
      POLICY,
    );
    expect(cred).not.toBeNull();
    return { priv: privateKey, cred: cred! };
  }

  it("verifies a well-formed assertion", () => {
    const { priv, cred } = enroll();
    const challenge = randomChallenge();
    const a = makeAssertion(priv, challenge, { signCount: 5 });
    const result = verifyAssertion(
      { ...a, expectedChallenge: challenge },
      { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
      POLICY,
    );
    expect(result).toEqual({ signCount: 5 });
  });

  it("rejects an assertion with the wrong challenge", () => {
    const { priv, cred } = enroll();
    const a = makeAssertion(priv, randomChallenge());
    expect(
      verifyAssertion(
        { ...a, expectedChallenge: randomChallenge() },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects an assertion signed by a different key", () => {
    const { cred } = enroll();
    const other = p256();
    const challenge = randomChallenge();
    const a = makeAssertion(other.privateKey, challenge);
    expect(
      verifyAssertion(
        { ...a, expectedChallenge: challenge },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects a tampered signature", () => {
    const { priv, cred } = enroll();
    const challenge = randomChallenge();
    const a = makeAssertion(priv, challenge);
    const sig = Buffer.from(a.signature, "base64url");
    sig[sig.length - 1] ^= 0xff;
    expect(
      verifyAssertion(
        { ...a, signature: sig.toString("base64url"), expectedChallenge: challenge },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
        POLICY,
      ),
    ).toBeNull();
  });

  it("rejects an assertion without the user-present flag", () => {
    const { priv, cred } = enroll();
    const challenge = randomChallenge();
    const a = makeAssertion(priv, challenge, { flags: 0x00 });
    expect(
      verifyAssertion(
        { ...a, expectedChallenge: challenge },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
        POLICY,
      ),
    ).toBeNull();
  });

  it("enforces the signature-counter clone guard (must strictly increase)", () => {
    const { priv, cred } = enroll();
    // Stored counter 10, presented 10 → clone → refused.
    const challenge = randomChallenge();
    const a = makeAssertion(priv, challenge, { signCount: 10 });
    expect(
      verifyAssertion(
        { ...a, expectedChallenge: challenge },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 10 },
        POLICY,
      ),
    ).toBeNull();
    // Presented 11 > stored 10 → accepted.
    const challenge2 = randomChallenge();
    const a2 = makeAssertion(priv, challenge2, { signCount: 11 });
    expect(
      verifyAssertion(
        { ...a2, expectedChallenge: challenge2 },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 10 },
        POLICY,
      ),
    ).toEqual({ signCount: 11 });
  });

  it("accepts a zero counter on both sides (authenticator without a counter)", () => {
    const { priv, cred } = enroll();
    const challenge = randomChallenge();
    const a = makeAssertion(priv, challenge, { signCount: 0 });
    expect(
      verifyAssertion(
        { ...a, expectedChallenge: challenge },
        { publicKeySpki: cred.publicKeySpki, alg: cred.alg, signCount: 0 },
        POLICY,
      ),
    ).toEqual({ signCount: 0 });
  });
});

describe("webauthn __testing internals", () => {
  it("round-trips a COSE EC2 key through decode → SPKI", () => {
    const { publicKey } = p256();
    const cose = coseEc2(publicKey);
    const encoded = cborEncode(cose);
    const [decoded] = __testing.decodeCbor(encoded, 0);
    const { spki, alg } = __testing.coseToPublicKeySpki(decoded as Map<unknown, unknown> as never);
    expect(alg).toBe(-7);
    // Re-import the SPKI and confirm it matches the original public key.
    const reimported = createPublicKey({
      key: Buffer.from(spki, "base64"),
      format: "der",
      type: "spki",
    });
    expect(reimported.export({ type: "spki", format: "der" }).toString("base64")).toBe(
      publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    );
  });

  it("randomChallenge is 32 bytes of base64url", () => {
    const c = randomChallenge();
    expect(Buffer.from(c, "base64url").length).toBe(32);
  });

  // Touch createPrivateKey import so lint stays happy if unused elsewhere.
  it("can build a private key object", () => {
    const { privateKey } = p256();
    const pem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
    expect(createPrivateKey(pem)).toBeDefined();
  });
});
