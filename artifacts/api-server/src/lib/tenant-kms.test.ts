import { afterEach, describe, expect, it } from "vitest";
import type { Response } from "express";
import {
  resolveTenantSecret,
  hasTenantKey,
  setTenantKmsCache,
  resetTenantKmsForTests,
  type TenantKeyDescriptor,
} from "./tenant-kms";
import {
  issueCookie,
  parseCookie,
  issueStepUpCookie,
  parseStepUpCookie,
} from "./auth";

// M12.1: the per-tenant KMS resolver must be DEFAULT-INERT (no registered key
// ⇒ null ⇒ callers fall back to the global secret ⇒ byte-identical to pre-M12.1)
// and, when a key IS registered, must produce a tenant- and purpose-separated
// key that another tenant cannot reproduce.

afterEach(() => {
  resetTenantKmsForTests();
});

// Minimal fake Express Response that just captures Set-Cookie values so we can
// round-trip issue → parse without a real HTTP server.
function fakeRes(): { res: Response; cookies: Record<string, string> } {
  const cookies: Record<string, string> = {};
  const res = {
    cookie(name: string, value: string) {
      cookies[name] = value;
      return res;
    },
    clearCookie() {
      return res;
    },
  } as unknown as Response;
  return { res, cookies };
}

const derived = (tenantId: string, keyId = "k1"): TenantKeyDescriptor => ({
  tenantId,
  keyId,
  provider: "derived",
  keyRef: null,
});

describe("resolveTenantSecret (default-inert)", () => {
  it("returns null when the cache is unloaded", () => {
    resetTenantKmsForTests();
    expect(resolveTenantSecret("acme", "auth")).toBeNull();
    expect(hasTenantKey("acme")).toBe(false);
  });

  it("returns null for a tenant with no registered key", () => {
    setTenantKmsCache([derived("acme")]);
    expect(resolveTenantSecret("other", "auth")).toBeNull();
    expect(hasTenantKey("other")).toBe(false);
  });
});

describe("resolveTenantSecret (derived provider)", () => {
  it("is deterministic for the same tenant + purpose + keyId", () => {
    setTenantKmsCache([derived("acme")]);
    const a = resolveTenantSecret("acme", "auth");
    const b = resolveTenantSecret("acme", "auth");
    expect(a).toBeTruthy();
    expect(a).toBe(b);
  });

  it("derives a different key per tenant, per purpose, and per keyId", () => {
    setTenantKmsCache([derived("acme")]);
    const acmeAuth = resolveTenantSecret("acme", "auth");
    setTenantKmsCache([derived("globex")]);
    const globexAuth = resolveTenantSecret("globex", "auth");
    setTenantKmsCache([derived("acme")]);
    const acmeNotary = resolveTenantSecret("acme", "notarization");
    setTenantKmsCache([derived("acme", "k2")]);
    const acmeRotated = resolveTenantSecret("acme", "auth");

    const all = [acmeAuth, globexAuth, acmeNotary, acmeRotated];
    expect(new Set(all).size).toBe(all.length); // all distinct
  });
});

describe("resolveTenantSecret (external provider)", () => {
  const ENV = "PHIA_TEST_TENANT_KEY_ABC";
  afterEach(() => {
    delete process.env[ENV];
  });

  it("reads the named env var when present and long enough", () => {
    process.env[ENV] = "x".repeat(32);
    setTenantKmsCache([
      { tenantId: "acme", keyId: "k1", provider: "external", keyRef: ENV },
    ]);
    expect(resolveTenantSecret("acme", "auth")).toBe("x".repeat(32));
  });

  it("returns null when the referenced env var is missing or too short", () => {
    setTenantKmsCache([
      { tenantId: "acme", keyId: "k1", provider: "external", keyRef: ENV },
    ]);
    expect(resolveTenantSecret("acme", "auth")).toBeNull();
    process.env[ENV] = "short";
    expect(resolveTenantSecret("acme", "auth")).toBeNull();
  });
});

describe("auth cookies under per-tenant keys (M12.1)", () => {
  it("round-trips with the global secret when no key is registered", () => {
    resetTenantKmsForTests();
    const { res, cookies } = fakeRes();
    issueCookie(res, { sub: "u1", tenant_id: "default" });
    const parsed = parseCookie(cookies["phia_sess"]);
    expect(parsed?.sub).toBe("u1");
    expect(parsed?.tenant_id).toBe("default");
  });

  it("a cookie signed under a tenant key no longer verifies once the key is gone", () => {
    // Issue under acme's dedicated key.
    setTenantKmsCache([derived("acme")]);
    const { res, cookies } = fakeRes();
    issueCookie(res, { sub: "u1", tenant_id: "acme" });
    const value = cookies["phia_sess"];
    expect(parseCookie(value)?.sub).toBe("u1");

    // Drop the key ⇒ acme falls back to the global secret ⇒ the per-tenant
    // signature must NO LONGER validate. This proves the per-tenant key was
    // actually in force (not the global secret).
    resetTenantKmsForTests();
    expect(parseCookie(value)).toBeNull();
  });

  it("applies the same per-tenant keying to step-up cookies", () => {
    setTenantKmsCache([derived("acme")]);
    const { res, cookies } = fakeRes();
    issueStepUpCookie(res, { sub: "u1", tenant_id: "acme", reason: "audit" });
    const value = cookies["phia_stepup"];
    expect(parseStepUpCookie(value)?.reason).toBe("audit");

    resetTenantKmsForTests();
    expect(parseStepUpCookie(value)).toBeNull();
  });
});
