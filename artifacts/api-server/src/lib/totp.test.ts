import { describe, it, expect } from "vitest";
import {
  base32Encode,
  base32Decode,
  generateSecret,
  totpCode,
  verifyTotp,
  otpauthUri,
  counterFor,
} from "./totp";

// RFC 6238 Appendix B reference test vectors. The shared seed is the ASCII
// string "12345678901234567890" (20 bytes) used with HMAC-SHA1; the published
// 8-digit TOTP values are the canonical interoperability check.
const RFC_SEED_ASCII = "12345678901234567890";
const RFC_SEED_B32 = base32Encode(Buffer.from(RFC_SEED_ASCII, "ascii"));

const RFC_VECTORS: Array<{ timeSeconds: number; totp8: string }> = [
  { timeSeconds: 59, totp8: "94287082" },
  { timeSeconds: 1111111109, totp8: "07081804" },
  { timeSeconds: 1111111111, totp8: "14050471" },
  { timeSeconds: 1234567890, totp8: "89005924" },
  { timeSeconds: 2000000000, totp8: "69279037" },
  { timeSeconds: 20000000000, totp8: "65353130" },
];

describe("base32", () => {
  it("round-trips arbitrary bytes", () => {
    for (const s of ["", "f", "fo", "foo", "foob", "fooba", "foobar"]) {
      const buf = Buffer.from(s, "ascii");
      expect(base32Decode(base32Encode(buf)).equals(buf)).toBe(true);
    }
  });

  it("matches known RFC 4648 vectors", () => {
    expect(base32Encode(Buffer.from("foobar", "ascii"))).toBe("MZXW6YTBOI");
    expect(base32Encode(Buffer.from("foo", "ascii"))).toBe("MZXW6");
  });

  it("tolerates lower-case, padding, and whitespace on decode", () => {
    expect(base32Decode("mz xw6===").equals(base32Decode("MZXW6"))).toBe(true);
  });

  it("throws on a non-alphabet character", () => {
    expect(() => base32Decode("MZXW0!")).toThrow();
  });
});

describe("totpCode against RFC 6238 vectors (SHA1, 8 digits)", () => {
  for (const v of RFC_VECTORS) {
    it(`T=${v.timeSeconds} → ${v.totp8}`, () => {
      const code = totpCode(RFC_SEED_B32, {
        nowMs: v.timeSeconds * 1000,
        digits: 8,
        stepSeconds: 30,
      });
      expect(code).toBe(v.totp8);
    });
  }

  it("derives the 6-digit code as the low 6 digits of the 8-digit value", () => {
    const code6 = totpCode(RFC_SEED_B32, { nowMs: 59 * 1000 });
    expect(code6).toBe("287082");
  });
});

describe("verifyTotp", () => {
  it("accepts the current code and returns the step counter", () => {
    const secret = generateSecret();
    const nowMs = 1_700_000_000_000;
    const code = totpCode(secret, { nowMs });
    const matched = verifyTotp(secret, code, { nowMs });
    expect(matched).toBe(counterFor(nowMs, 30));
  });

  it("accepts a code one step in the past/future (±1 skew window)", () => {
    const secret = generateSecret();
    const nowMs = 1_700_000_000_000;
    const prev = totpCode(secret, { nowMs: nowMs - 30_000 });
    const next = totpCode(secret, { nowMs: nowMs + 30_000 });
    expect(verifyTotp(secret, prev, { nowMs })).toBe(counterFor(nowMs, 30) - 1);
    expect(verifyTotp(secret, next, { nowMs })).toBe(counterFor(nowMs, 30) + 1);
  });

  it("rejects a code two steps away", () => {
    const secret = generateSecret();
    const nowMs = 1_700_000_000_000;
    const far = totpCode(secret, { nowMs: nowMs - 90_000 });
    expect(verifyTotp(secret, far, { nowMs })).toBeNull();
  });

  it("rejects malformed input without throwing", () => {
    const secret = generateSecret();
    expect(verifyTotp(secret, "")).toBeNull();
    expect(verifyTotp(secret, "abcdef")).toBeNull();
    expect(verifyTotp(secret, "12345")).toBeNull();
    expect(verifyTotp(secret, "1234567")).toBeNull();
  });

  it("widens the accepted window when configured", () => {
    const secret = generateSecret();
    const nowMs = 1_700_000_000_000;
    const far = totpCode(secret, { nowMs: nowMs - 60_000 });
    expect(verifyTotp(secret, far, { nowMs })).toBeNull();
    expect(verifyTotp(secret, far, { nowMs, window: 2 })).toBe(
      counterFor(nowMs, 30) - 2,
    );
  });
});

describe("otpauthUri", () => {
  it("builds a scannable otpauth:// URI with the expected params", () => {
    const uri = otpauthUri({
      secretBase32: "MZXW6",
      account: "analyst",
      issuer: "PHI-Audit",
    });
    expect(uri.startsWith("otpauth://totp/PHI-Audit%3Aanalyst?")).toBe(true);
    const q = new URL(uri).searchParams;
    expect(q.get("secret")).toBe("MZXW6");
    expect(q.get("issuer")).toBe("PHI-Audit");
    expect(q.get("algorithm")).toBe("SHA1");
    expect(q.get("digits")).toBe("6");
    expect(q.get("period")).toBe("30");
  });
});
