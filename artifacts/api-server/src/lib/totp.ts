import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

// ---------------------------------------------------------------------------
// RFC 6238 TOTP (production step-up second factor)
// ---------------------------------------------------------------------------
//
// Self-contained, in-process TOTP — exactly the same posture as the M23
// local NER provider and the dev FeatureHash embedder: pure node:crypto, no
// SDK, no network, no new dependency. This is what makes `STEP_UP_PROVIDER=totp`
// runnable offline and keeps the credential-free eval gate honest (the gate
// never sets STEP_UP_PROVIDER, so the dev-token path stays the default and is
// byte-identical).
//
// HMAC-SHA1 is mandated by RFC 6238 / RFC 4226 (HOTP) and is what every
// authenticator app (Google Authenticator, 1Password, Authy, …) implements —
// the SHA1 here is an interoperability requirement of the standard, not a
// security choice about hashing.

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; // RFC 4648, no padding

const DEFAULT_STEP_SECONDS = 30;
const DEFAULT_DIGITS = 6;
const DEFAULT_SECRET_BYTES = 20; // 160-bit, the RFC 4226 recommendation

export interface TotpOptions {
  /** Unix time in milliseconds. Defaults to Date.now(). */
  nowMs?: number;
  /** Time step in seconds. Defaults to 30. */
  stepSeconds?: number;
  /** Number of code digits. Defaults to 6. */
  digits?: number;
}

/** Encode raw bytes as unpadded RFC 4648 base32 (the format authenticator
 *  apps expect in an otpauth:// `secret=`). */
export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return out;
}

/** Decode an unpadded (or padded) RFC 4648 base32 string back to bytes.
 *  Tolerant of lower-case and stray `=` padding / whitespace so a manually
 *  typed key still works. Throws on a non-alphabet character. */
export function base32Decode(input: string): Buffer {
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new Error("invalid base32 character");
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Generate a fresh random TOTP secret, returned as base32 for storage +
 *  display in the enrollment QR. */
export function generateSecret(bytes = DEFAULT_SECRET_BYTES): string {
  return base32Encode(randomBytes(bytes));
}

/** HOTP (RFC 4226): HMAC-SHA1 of the 8-byte big-endian counter, dynamically
 *  truncated to `digits` decimal digits (zero-padded). */
function hotp(secret: Buffer, counter: number, digits: number): string {
  const buf = Buffer.alloc(8);
  // Counters here are floor(unix_seconds / step) ≈ 5.9e7 today, well within
  // the 53-bit safe-integer range, so writeUInt32 of the low word is exact.
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const hmac = createHmac("sha1", secret).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return (bin % 10 ** digits).toString().padStart(digits, "0");
}

/** The current time-step counter for a given clock + step. */
export function counterFor(nowMs: number, stepSeconds: number): number {
  return Math.floor(nowMs / 1000 / stepSeconds);
}

/** Compute the TOTP code for a base32 secret at a point in time. */
export function totpCode(secretBase32: string, opts: TotpOptions = {}): string {
  const nowMs = opts.nowMs ?? Date.now();
  const stepSeconds = opts.stepSeconds ?? DEFAULT_STEP_SECONDS;
  const digits = opts.digits ?? DEFAULT_DIGITS;
  return hotp(base32Decode(secretBase32), counterFor(nowMs, stepSeconds), digits);
}

export interface TotpVerifyOptions extends TotpOptions {
  /** How many steps of clock skew to tolerate on each side. Default 1
   *  (±30s) — the standard authenticator-app allowance. */
  window?: number;
}

/** Verify a supplied code against the secret, tolerating ±`window` steps of
 *  clock skew. Returns the matched step counter (so the caller can persist it
 *  as a replay guard — a code is single-use per step) or null on no match.
 *  Constant-time per-candidate compare; non-numeric / wrong-length input
 *  returns null without leaking timing. */
export function verifyTotp(
  secretBase32: string,
  supplied: string,
  opts: TotpVerifyOptions = {},
): number | null {
  const stepSeconds = opts.stepSeconds ?? DEFAULT_STEP_SECONDS;
  const digits = opts.digits ?? DEFAULT_DIGITS;
  const window = opts.window ?? 1;
  const nowMs = opts.nowMs ?? Date.now();
  const code = supplied.trim();
  if (code.length !== digits || !/^\d+$/.test(code)) return null;
  const secret = base32Decode(secretBase32);
  const center = counterFor(nowMs, stepSeconds);
  for (let i = -window; i <= window; i++) {
    const counter = center + i;
    if (counter < 0) continue;
    const expected = hotp(secret, counter, digits);
    if (timingSafeEqual(Buffer.from(code), Buffer.from(expected))) {
      return counter;
    }
  }
  return null;
}

/** Build the otpauth:// URI an authenticator app scans from a QR code. */
export function otpauthUri(args: {
  secretBase32: string;
  account: string;
  issuer: string;
  digits?: number;
  stepSeconds?: number;
}): string {
  const digits = args.digits ?? DEFAULT_DIGITS;
  const period = args.stepSeconds ?? DEFAULT_STEP_SECONDS;
  const label = encodeURIComponent(`${args.issuer}:${args.account}`);
  const params = new URLSearchParams({
    secret: args.secretBase32,
    issuer: args.issuer,
    algorithm: "SHA1",
    digits: String(digits),
    period: String(period),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}
