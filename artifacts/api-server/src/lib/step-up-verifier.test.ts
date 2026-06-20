import { describe, it, expect } from "vitest";
import { __testing, stepUpProvider } from "./step-up-verifier";

const { encryptSecret, decryptSecret } = __testing;

describe("step-up TOTP secret at-rest encryption", () => {
  it("round-trips a secret through AES-256-GCM", () => {
    const tenant = "tenant-a";
    const secret = "JBSWY3DPEHPK3PXP";
    const env = encryptSecret(tenant, secret);
    expect(env.startsWith("v1.")).toBe(true);
    expect(env).not.toContain(secret);
    expect(decryptSecret(tenant, secret ? env : env)).toBe(secret);
  });

  it("is bound to the tenant — a different tenant cannot decrypt", () => {
    const env = encryptSecret("tenant-a", "JBSWY3DPEHPK3PXP");
    expect(() => decryptSecret("tenant-b", env)).toThrow();
  });

  it("rejects a tampered ciphertext (GCM auth tag)", () => {
    const env = encryptSecret("tenant-a", "JBSWY3DPEHPK3PXP");
    const parts = env.split(".");
    // Flip a byte in the ciphertext segment.
    const ct = Buffer.from(parts[3], "base64url");
    ct[0] ^= 0xff;
    parts[3] = ct.toString("base64url");
    expect(() => decryptSecret("tenant-a", parts.join("."))).toThrow();
  });

  it("rejects a malformed envelope", () => {
    expect(() => decryptSecret("tenant-a", "not-an-envelope")).toThrow();
    expect(() => decryptSecret("tenant-a", "v9.a.b.c")).toThrow();
  });
});

describe("stepUpProvider", () => {
  it("defaults to dev and only flips to totp on the exact value", () => {
    const prev = process.env.STEP_UP_PROVIDER;
    try {
      delete process.env.STEP_UP_PROVIDER;
      expect(stepUpProvider()).toBe("dev");
      process.env.STEP_UP_PROVIDER = "TOTP";
      expect(stepUpProvider()).toBe("dev");
      process.env.STEP_UP_PROVIDER = "totp";
      expect(stepUpProvider()).toBe("totp");
    } finally {
      if (prev === undefined) delete process.env.STEP_UP_PROVIDER;
      else process.env.STEP_UP_PROVIDER = prev;
    }
  });
});
