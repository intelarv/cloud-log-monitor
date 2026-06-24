import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";

// ---------------------------------------------------------------------------
// WebAuthn / FIDO2 step-up second factor (production, no SDK)
// ---------------------------------------------------------------------------
//
// Self-contained, in-process WebAuthn ceremony verification — exactly the same
// posture as the M24 TOTP factor (`lib/totp.ts`), the M23 local NER provider,
// and the dev FeatureHash embedder: pure `node:crypto`, no SDK, no network, no
// new dependency. This is the cryptographic core behind
// `STEP_UP_PROVIDER=webauthn`; the DB/enrollment glue lives in
// `step-up-verifier.ts` and the HTTP endpoints in `routes/auth.ts`.
//
// Scope (deliberately bounded, documented):
//   - Registration ("webauthn.create") and assertion ("webauthn.get") ceremony
//     verification: challenge match, origin allow-list, rpIdHash binding, the
//     User-Present flag, signature verification, and signature-counter clone
//     detection.
//   - Supported COSE algorithms: ES256/384/512 (EC2) and RS256 (RSA) — the set
//     every common platform/roaming authenticator (passkeys, Touch ID, Windows
//     Hello, YubiKey) negotiates by default.
//   - Attestation statements are NOT verified (we accept the credential public
//     key from the authenticator data regardless of `fmt`). The security
//     property we need for a *second factor* is "possession of the registered
//     key", not device provenance — the analyst is already session-authenticated
//     before enrolling. Attestation-cert chain validation is a documented
//     follow-up behind the same module.
//
// Every exported verifier returns `null` on ANY malformed input or verification
// failure (never throws to the caller) so the step-up path simply refuses.

const SUPPORTED_ALGS: Record<number, { hash: string; type: "ec" | "rsa" }> = {
  [-7]: { hash: "sha256", type: "ec" }, // ES256
  [-35]: { hash: "sha384", type: "ec" }, // ES384
  [-36]: { hash: "sha512", type: "ec" }, // ES512
  [-257]: { hash: "sha256", type: "rsa" }, // RS256
};

const FLAG_UP = 0x01; // User Present
const FLAG_AT = 0x40; // Attested credential data included

function sha256(buf: Buffer): Buffer {
  return createHash("sha256").update(buf).digest();
}

function b64urlToBuf(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

// --- minimal CBOR decoder (the subset WebAuthn uses) -----------------------
//
// Supports major types 0 (uint), 1 (negative int), 2 (byte string),
// 3 (text string), 4 (array), 5 (map). Returns [value, nextOffset]. Map keys
// may be ints (COSE keys) or strings (attestationObject), so maps decode to a
// JS Map. Anything outside this subset throws (caught upstream → refusal).

type CborValue = number | string | Buffer | CborValue[] | Map<CborValue, CborValue>;

function decodeCbor(buf: Buffer, start: number): [CborValue, number] {
  const first = buf[start];
  if (first === undefined) throw new Error("cbor: truncated");
  const major = first >> 5;
  const info = first & 0x1f;
  let offset = start + 1;
  let val: number;
  if (info < 24) {
    val = info;
  } else if (info === 24) {
    val = buf.readUInt8(offset);
    offset += 1;
  } else if (info === 25) {
    val = buf.readUInt16BE(offset);
    offset += 2;
  } else if (info === 26) {
    val = buf.readUInt32BE(offset);
    offset += 4;
  } else if (info === 27) {
    val = Number(buf.readBigUInt64BE(offset));
    offset += 8;
  } else {
    throw new Error("cbor: unsupported length encoding");
  }
  switch (major) {
    case 0:
      return [val, offset];
    case 1:
      return [-1 - val, offset];
    case 2: {
      const b = buf.subarray(offset, offset + val);
      if (b.length !== val) throw new Error("cbor: truncated byte string");
      return [Buffer.from(b), offset + val];
    }
    case 3: {
      const s = buf.subarray(offset, offset + val);
      if (s.length !== val) throw new Error("cbor: truncated text string");
      return [s.toString("utf8"), offset + val];
    }
    case 4: {
      const arr: CborValue[] = [];
      for (let i = 0; i < val; i++) {
        const [item, next] = decodeCbor(buf, offset);
        arr.push(item);
        offset = next;
      }
      return [arr, offset];
    }
    case 5: {
      const map = new Map<CborValue, CborValue>();
      for (let i = 0; i < val; i++) {
        const [k, kn] = decodeCbor(buf, offset);
        const [v, vn] = decodeCbor(buf, kn);
        map.set(k, v);
        offset = vn;
      }
      return [map, offset];
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

// --- authenticator data ----------------------------------------------------

interface AuthData {
  rpIdHash: Buffer;
  flags: number;
  signCount: number;
  credentialId?: Buffer;
  cosePublicKey?: Map<CborValue, CborValue>;
}

function parseAuthData(buf: Buffer): AuthData {
  if (buf.length < 37) throw new Error("authData: too short");
  const rpIdHash = buf.subarray(0, 32);
  const flags = buf.readUInt8(32);
  const signCount = buf.readUInt32BE(33);
  let offset = 37;
  let credentialId: Buffer | undefined;
  let cosePublicKey: Map<CborValue, CborValue> | undefined;
  if (flags & FLAG_AT) {
    // aaguid(16) || credIdLen(2) || credId || COSEPublicKey(CBOR)
    offset += 16;
    const credIdLen = buf.readUInt16BE(offset);
    offset += 2;
    credentialId = Buffer.from(buf.subarray(offset, offset + credIdLen));
    offset += credIdLen;
    const [cose, next] = decodeCbor(buf, offset);
    if (!(cose instanceof Map)) throw new Error("authData: bad COSE key");
    cosePublicKey = cose;
    offset = next;
  }
  return { rpIdHash, flags, signCount, credentialId, cosePublicKey };
}

function coseToPublicKeySpki(
  cose: Map<CborValue, CborValue>,
): { spki: string; alg: number } {
  const kty = cose.get(1);
  const alg = cose.get(3);
  if (typeof alg !== "number" || !SUPPORTED_ALGS[alg]) {
    throw new Error("cose: unsupported algorithm");
  }
  let key;
  if (kty === 2) {
    // EC2
    const crvId = cose.get(-1);
    const crv =
      crvId === 1 ? "P-256" : crvId === 2 ? "P-384" : crvId === 3 ? "P-521" : null;
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (!crv || !(x instanceof Buffer) || !(y instanceof Buffer)) {
      throw new Error("cose: bad EC key");
    }
    key = createPublicKey({
      key: {
        kty: "EC",
        crv,
        x: x.toString("base64url"),
        y: y.toString("base64url"),
      },
      format: "jwk",
    });
  } else if (kty === 3) {
    // RSA
    const n = cose.get(-1);
    const e = cose.get(-2);
    if (!(n instanceof Buffer) || !(e instanceof Buffer)) {
      throw new Error("cose: bad RSA key");
    }
    key = createPublicKey({
      key: { kty: "RSA", n: n.toString("base64url"), e: e.toString("base64url") },
      format: "jwk",
    });
  } else {
    throw new Error("cose: unsupported key type");
  }
  return { spki: key.export({ type: "spki", format: "der" }).toString("base64"), alg };
}

interface ClientData {
  type: string;
  challenge: string;
  origin: string;
}

function parseClientData(b64url: string): ClientData {
  const json = b64urlToBuf(b64url).toString("utf8");
  const parsed = JSON.parse(json) as Partial<ClientData>;
  if (
    typeof parsed.type !== "string" ||
    typeof parsed.challenge !== "string" ||
    typeof parsed.origin !== "string"
  ) {
    throw new Error("clientData: missing fields");
  }
  return { type: parsed.type, challenge: parsed.challenge, origin: parsed.origin };
}

// --- public types + verifiers ----------------------------------------------

export interface WebauthnPolicy {
  /** Relying-party id (the registrable domain, e.g. "example.com"). */
  rpId: string;
  /** Allowed client origins (e.g. ["https://example.com"]). */
  origins: string[];
}

export interface RegistrationInput {
  attestationObject: string; // base64url
  clientDataJSON: string; // base64url
  expectedChallenge: string; // base64url
}

export interface RegisteredCredential {
  credentialId: string; // base64url
  publicKeySpki: string; // base64 (DER SPKI)
  alg: number;
  signCount: number;
}

export interface AssertionInput {
  clientDataJSON: string; // base64url
  authenticatorData: string; // base64url
  signature: string; // base64url
  expectedChallenge: string; // base64url
}

export interface StoredCredential {
  publicKeySpki: string; // base64 (DER SPKI)
  alg: number;
  signCount: number;
}

/** A fresh 32-byte challenge, base64url-encoded (the form the browser echoes
 *  back inside clientDataJSON). */
export function randomChallenge(): string {
  return randomBytes(32).toString("base64url");
}

function clientDataChecksOk(
  cd: ClientData,
  expectedType: string,
  expectedChallenge: string,
  policy: WebauthnPolicy,
): boolean {
  if (cd.type !== expectedType) return false;
  // Constant-time-ish: the challenge is server-issued and single-use, but
  // compare as exact strings (both base64url of the same random bytes).
  if (cd.challenge !== expectedChallenge) return false;
  if (!policy.origins.includes(cd.origin)) return false;
  return true;
}

/** Verify a registration ("webauthn.create") ceremony and extract the credential
 *  to persist. Returns null on any failure. */
export function verifyRegistration(
  input: RegistrationInput,
  policy: WebauthnPolicy,
): RegisteredCredential | null {
  try {
    const cd = parseClientData(input.clientDataJSON);
    if (!clientDataChecksOk(cd, "webauthn.create", input.expectedChallenge, policy)) {
      return null;
    }
    const [obj] = decodeCbor(b64urlToBuf(input.attestationObject), 0);
    if (!(obj instanceof Map)) return null;
    const authDataRaw = obj.get("authData");
    if (!(authDataRaw instanceof Buffer)) return null;
    const ad = parseAuthData(authDataRaw);
    if (!(ad.flags & FLAG_UP)) return null; // user must be present
    if (!ad.rpIdHash.equals(sha256(Buffer.from(policy.rpId, "utf8")))) return null;
    if (!ad.credentialId || !ad.cosePublicKey) return null;
    const { spki, alg } = coseToPublicKeySpki(ad.cosePublicKey);
    return {
      credentialId: ad.credentialId.toString("base64url"),
      publicKeySpki: spki,
      alg,
      signCount: ad.signCount,
    };
  } catch {
    return null;
  }
}

/** Verify an assertion ("webauthn.get") ceremony against a stored credential.
 *  Returns the new signature counter on success, null on failure. The caller is
 *  responsible for persisting the counter (clone-detection replay guard) and for
 *  single-use of the challenge. */
export function verifyAssertion(
  input: AssertionInput,
  cred: StoredCredential,
  policy: WebauthnPolicy,
): { signCount: number } | null {
  try {
    const cd = parseClientData(input.clientDataJSON);
    if (!clientDataChecksOk(cd, "webauthn.get", input.expectedChallenge, policy)) {
      return null;
    }
    const authData = b64urlToBuf(input.authenticatorData);
    const ad = parseAuthData(authData);
    if (!(ad.flags & FLAG_UP)) return null;
    if (!ad.rpIdHash.equals(sha256(Buffer.from(policy.rpId, "utf8")))) return null;

    const algInfo = SUPPORTED_ALGS[cred.alg];
    if (!algInfo) return null;
    const signedData = Buffer.concat([authData, sha256(b64urlToBuf(input.clientDataJSON))]);
    const key = createPublicKey({
      key: Buffer.from(cred.publicKeySpki, "base64"),
      format: "der",
      type: "spki",
    });
    const sig = b64urlToBuf(input.signature);
    const ok =
      algInfo.type === "ec"
        ? verify(algInfo.hash, signedData, { key, dsaEncoding: "der" }, sig)
        : verify(algInfo.hash, signedData, key, sig);
    if (!ok) return null;

    // Clone-detection counter: if either side is 0 the authenticator does not
    // maintain a counter (common for platform passkeys) — accept and keep 0.
    // Otherwise the new counter MUST strictly exceed the stored one.
    if (ad.signCount !== 0 || cred.signCount !== 0) {
      if (ad.signCount <= cred.signCount) return null;
    }
    return { signCount: ad.signCount };
  } catch {
    return null;
  }
}

// Exposed for unit tests that craft fixtures.
export const __testing = { decodeCbor, parseAuthData, coseToPublicKeySpki, sha256 };
