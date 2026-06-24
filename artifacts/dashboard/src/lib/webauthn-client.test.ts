import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  b64urlToBytes,
  bytesToB64url,
  webauthnSupported,
  performWebauthnRegistration,
  performWebauthnAssertion,
} from "./webauthn-client";

// Unit coverage for the base64url<->ArrayBuffer seam and the two WebAuthn
// ceremonies. These are the only place the dashboard converts between the
// server's base64url wire format and the browser's ArrayBuffer WebAuthn API, so
// a regression here silently breaks every step-up.

describe("base64url codec", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 255]);
    const encoded = bytesToB64url(bytes.buffer);
    expect(encoded).not.toMatch(/[+/=]/); // url-safe, unpadded
    expect(Array.from(b64urlToBytes(encoded))).toEqual(Array.from(bytes));
  });

  it("decodes a known base64url string", () => {
    expect(Array.from(b64urlToBytes("AQID"))).toEqual([1, 2, 3]);
  });
});

describe("webauthnSupported", () => {
  afterEach(() => {
    delete (window as any).PublicKeyCredential;
  });
  it("is false without PublicKeyCredential", () => {
    delete (window as any).PublicKeyCredential;
    expect(webauthnSupported()).toBe(false);
  });
  it("is true when PublicKeyCredential exists", () => {
    (window as any).PublicKeyCredential = function () {};
    expect(webauthnSupported()).toBe(true);
  });
});

describe("performWebauthnRegistration", () => {
  const create = vi.fn();
  beforeEach(() => {
    create.mockReset();
    Object.defineProperty(navigator, "credentials", {
      value: { create, get: vi.fn() },
      configurable: true,
    });
  });

  it("passes decoded creation options and base64url-encodes the attestation", async () => {
    create.mockResolvedValue({
      rawId: new Uint8Array([1, 2, 3]).buffer,
      response: {
        attestationObject: new Uint8Array([4, 5, 6]).buffer,
        clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
      },
    });
    const out = await performWebauthnRegistration({
      challenge: "AQID",
      rpId: "example.com",
      rpName: "PHI Audit",
      userIdB64url: "AQID",
      userName: "analyst",
    });
    expect(out).toEqual({ attestationObject: "BAUG", clientDataJSON: "BwgJ" });
    const opts = create.mock.calls[0][0].publicKey;
    expect(opts.rp).toEqual({ id: "example.com", name: "PHI Audit" });
    expect(Array.from(new Uint8Array(opts.challenge))).toEqual([1, 2, 3]);
    expect(opts.pubKeyCredParams.map((p: any) => p.alg)).toEqual([-7, -257]);
  });

  it("throws when no credential is returned", async () => {
    create.mockResolvedValue(null);
    await expect(
      performWebauthnRegistration({
        challenge: "AQID",
        rpId: "example.com",
        rpName: "PHI Audit",
        userIdB64url: "AQID",
        userName: "analyst",
      }),
    ).rejects.toThrow();
  });
});

describe("performWebauthnAssertion", () => {
  const get = vi.fn();
  beforeEach(() => {
    get.mockReset();
    Object.defineProperty(navigator, "credentials", {
      value: { create: vi.fn(), get },
      configurable: true,
    });
  });

  it("assembles the JSON assertion token from the ceremony response", async () => {
    get.mockResolvedValue({
      rawId: new Uint8Array([1, 2, 3]).buffer,
      response: {
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
        authenticatorData: new Uint8Array([7, 8, 9]).buffer,
        signature: new Uint8Array([10, 11, 12]).buffer,
      },
    });
    const token = await performWebauthnAssertion({
      challenge: "AQID",
      rpId: "example.com",
      allowCredentials: ["AQID"],
    });
    expect(JSON.parse(token)).toEqual({
      credentialId: "AQID",
      clientDataJSON: "BAUG",
      authenticatorData: "BwgJ",
      signature: "CgsM",
    });
    const opts = get.mock.calls[0][0].publicKey;
    expect(opts.rpId).toBe("example.com");
    expect(opts.allowCredentials[0].type).toBe("public-key");
    expect(Array.from(new Uint8Array(opts.allowCredentials[0].id))).toEqual([
      1, 2, 3,
    ]);
  });
});
