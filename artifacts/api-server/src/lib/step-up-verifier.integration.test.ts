import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { bootstrap } from "@workspace/db";
import {
  provisionTotpSecret,
  confirmTotpEnrollment,
  getFactorStatus,
  getStepUpVerifier,
} from "./step-up-verifier";
import { base32Decode, totpCode } from "./totp";
import { uniqueTenant } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// DB-backed coverage for the TOTP step-up verifier (STEP_UP_PROVIDER=totp):
// enroll → confirm → step-up → replay refusal, all against the real
// step_up_factors table (RLS-scoped via withTenant) with the secret encrypted
// at rest. Each test uses a fresh tenant id (uniqueTenant) so rows can't
// collide with the seed tenant or each other (M1.9 shared-DB pollution rule).
//
// The verifier calls verifyTotp() with the real wall clock, so to exercise the
// multi-step / replay-guard behaviour deterministically we pin Date.now() to a
// controlled value and advance it by whole TOTP steps (30s) between actions.
// ---------------------------------------------------------------------------

const prevProvider = process.env.STEP_UP_PROVIDER;
const STEP_MS = 30_000;

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  process.env.STEP_UP_PROVIDER = "totp";
});

afterAll(() => {
  if (prevProvider === undefined) delete process.env.STEP_UP_PROVIDER;
  else process.env.STEP_UP_PROVIDER = prevProvider;
});

/** Pin Date.now() to a mutable cursor so confirm/verify land on known steps. */
function pinnedClock(startMs: number) {
  let now = startMs;
  const spy = vi.spyOn(Date, "now").mockImplementation(() => now);
  return {
    nowMs: () => now,
    advanceSteps: (n: number) => {
      now += n * STEP_MS;
    },
    restore: () => spy.mockRestore(),
  };
}

describe("TOTP enrollment + step-up over the DB", () => {
  it("provisions an UNVERIFIED factor, confirms it, then satisfies a step-up", async () => {
    const tenant = uniqueTenant("totp");
    const user = "analyst-1";
    const clock = pinnedClock(1_700_000_000_000);
    try {
      const prov = await provisionTotpSecret(tenant, user);
      expect(prov.secret).toMatch(/^[A-Z2-7]+$/);
      expect(prov.otpauthUri.startsWith("otpauth://totp/")).toBe(true);
      expect(base32Decode(prov.secret).length).toBeGreaterThan(0);

      const code = () => totpCode(prov.secret, { nowMs: clock.nowMs() });

      let status = await getFactorStatus(tenant, user);
      expect(status).toEqual({ enrolled: true, verified: false });

      // A step-up before confirmation is refused (factor not verified).
      const verifier = getStepUpVerifier();
      expect(verifier.kind).toBe("totp");
      expect(
        await verifier.verify({ tenantId: tenant, sub: user, token: code() }),
      ).toBe(false);

      // Confirm enrollment with a live code at the current step.
      expect(await confirmTotpEnrollment(tenant, user, code())).toBe(true);
      status = await getFactorStatus(tenant, user);
      expect(status).toEqual({ enrolled: true, verified: true });

      // Advance two steps and step up with a fresh code.
      clock.advanceSteps(2);
      expect(
        await verifier.verify({ tenantId: tenant, sub: user, token: code() }),
      ).toBe(true);
    } finally {
      clock.restore();
    }
  });

  it("refuses a wrong code at enrollment and at step-up", async () => {
    const tenant = uniqueTenant("totp");
    const user = "analyst-2";
    const clock = pinnedClock(1_700_000_100_000);
    try {
      const prov = await provisionTotpSecret(tenant, user);
      const code = () => totpCode(prov.secret, { nowMs: clock.nowMs() });
      expect(await confirmTotpEnrollment(tenant, user, "000000")).toBe(false);
      expect(await confirmTotpEnrollment(tenant, user, code())).toBe(true);
      const verifier = getStepUpVerifier();
      clock.advanceSteps(2);
      expect(
        await verifier.verify({ tenantId: tenant, sub: user, token: "000000" }),
      ).toBe(false);
    } finally {
      clock.restore();
    }
  });

  it("enforces the per-step replay guard", async () => {
    const tenant = uniqueTenant("totp");
    const user = "analyst-3";
    const clock = pinnedClock(1_700_000_200_000);
    try {
      const prov = await provisionTotpSecret(tenant, user);
      const code = () => totpCode(prov.secret, { nowMs: clock.nowMs() });
      expect(await confirmTotpEnrollment(tenant, user, code())).toBe(true);

      const verifier = getStepUpVerifier();
      // Advance to a strictly later step and step up successfully.
      clock.advanceSteps(2);
      const stepCode = code();
      expect(
        await verifier.verify({ tenantId: tenant, sub: user, token: stepCode }),
      ).toBe(true);
      // Replaying the SAME code (same step, no clock advance) is refused.
      expect(
        await verifier.verify({ tenantId: tenant, sub: user, token: stepCode }),
      ).toBe(false);
    } finally {
      clock.restore();
    }
  });

  it("admits only one of two concurrent verifies for the same code (CAS replay guard)", async () => {
    const tenant = uniqueTenant("totp");
    const user = "analyst-4";
    const clock = pinnedClock(1_700_000_250_000);
    try {
      const prov = await provisionTotpSecret(tenant, user);
      const code = () => totpCode(prov.secret, { nowMs: clock.nowMs() });
      expect(await confirmTotpEnrollment(tenant, user, code())).toBe(true);

      const verifier = getStepUpVerifier();
      clock.advanceSteps(2);
      const stepCode = code();
      // Fire two verifies for the SAME code in parallel. The compare-and-swap
      // advance (last_used_step) must let exactly one win — no TOCTOU double-use.
      const results = await Promise.all([
        verifier.verify({ tenantId: tenant, sub: user, token: stepCode }),
        verifier.verify({ tenantId: tenant, sub: user, token: stepCode }),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
    } finally {
      clock.restore();
    }
  });

  it("isolates factors by tenant (RLS) — no cross-tenant verify", async () => {
    const tenantA = uniqueTenant("totp");
    const tenantB = uniqueTenant("totp");
    const user = "shared-name";
    const clock = pinnedClock(1_700_000_300_000);
    try {
      const prov = await provisionTotpSecret(tenantA, user);
      const code = () => totpCode(prov.secret, { nowMs: clock.nowMs() });
      expect(await confirmTotpEnrollment(tenantA, user, code())).toBe(true);
      // Same user id under tenant B has no factor at all.
      expect(await getFactorStatus(tenantB, user)).toEqual({
        enrolled: false,
        verified: false,
      });
      const verifier = getStepUpVerifier();
      clock.advanceSteps(2);
      expect(
        await verifier.verify({ tenantId: tenantB, sub: user, token: code() }),
      ).toBe(false);
    } finally {
      clock.restore();
    }
  });
});
