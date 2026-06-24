import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { bootstrap } from "@workspace/db";
import {
  provisionTotpSecret,
  confirmTotpEnrollment,
  generateRecoveryCodes,
  recoveryStatus,
  consumeRecoveryCode,
  removeFactor,
  getFactorStatus,
} from "./step-up-verifier";
import { totpCode } from "./totp";
import { uniqueTenant } from "../test-support/ledger-harness";

// ---------------------------------------------------------------------------
// DB-backed coverage for backup / recovery codes (M29). A recovery-code set is
// minted only for an already-VERIFIED factor; each code satisfies a step-up
// exactly once (single-use CAS), and removeFactor wipes the row (and its codes)
// for a clean re-enrollment. Codes are stored as keyed HMACs inside an
// AES-256-GCM envelope, so these tests assert behaviour via the public API only
// (the plaintext is returned once, at generation).
//
// Each test uses a fresh tenant id (uniqueTenant) so rows cannot collide with
// the seed tenant or each other (M1.9 shared-DB pollution rule). We enroll a
// real TOTP factor under a pinned clock to reach the VERIFIED precondition.
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

/** Provision + confirm a TOTP factor so the user has a VERIFIED second factor. */
async function enrollVerifiedFactor(tenant: string, user: string) {
  const startMs = 1_700_100_000_000;
  const spy = vi.spyOn(Date, "now").mockImplementation(() => startMs);
  try {
    const prov = await provisionTotpSecret(tenant, user);
    expect(
      await confirmTotpEnrollment(
        tenant,
        user,
        totpCode(prov.secret, { nowMs: startMs }),
      ),
    ).toBe(true);
  } finally {
    spy.mockRestore();
  }
}

describe("backup / recovery codes over the DB", () => {
  it("refuses to generate codes without a verified factor", async () => {
    const tenant = uniqueTenant("recov");
    const user = "no-factor";
    // No enrollment at all → null (nothing to back up).
    expect(await generateRecoveryCodes(tenant, user)).toBeNull();

    // Provision an UNVERIFIED factor → still refused.
    await provisionTotpSecret(tenant, user);
    expect(await generateRecoveryCodes(tenant, user)).toBeNull();
  });

  it("generates a fixed set of distinct, unambiguous codes shown once", async () => {
    const tenant = uniqueTenant("recov");
    const user = "analyst";
    await enrollVerifiedFactor(tenant, user);

    expect(await recoveryStatus(tenant, user)).toEqual({
      enabled: false,
      remaining: 0,
    });

    const res = await generateRecoveryCodes(tenant, user);
    expect(res).not.toBeNull();
    const codes = res!.codes;
    expect(codes).toHaveLength(10);
    // All distinct.
    expect(new Set(codes).size).toBe(codes.length);
    // Unambiguous base32 with a dash separator — no I/L/O/0/1/U.
    for (const c of codes) {
      expect(c).toMatch(/^[A-HJ-NP-TV-Z2-9]{4}-[A-HJ-NP-TV-Z2-9]{4}$/);
    }

    expect(await recoveryStatus(tenant, user)).toEqual({
      enabled: true,
      remaining: 10,
    });
  });

  it("consumes a code exactly once and decrements remaining", async () => {
    const tenant = uniqueTenant("recov");
    const user = "analyst";
    await enrollVerifiedFactor(tenant, user);
    const codes = (await generateRecoveryCodes(tenant, user))!.codes;

    // First use succeeds.
    expect(await consumeRecoveryCode(tenant, user, codes[0]!)).toBe(true);
    expect((await recoveryStatus(tenant, user)).remaining).toBe(9);

    // Replaying the same code is refused.
    expect(await consumeRecoveryCode(tenant, user, codes[0]!)).toBe(false);
    expect((await recoveryStatus(tenant, user)).remaining).toBe(9);

    // A different code still works.
    expect(await consumeRecoveryCode(tenant, user, codes[1]!)).toBe(true);
    expect((await recoveryStatus(tenant, user)).remaining).toBe(8);
  });

  it("refuses a non-matching code and codes from another tenant (RLS)", async () => {
    const tenantA = uniqueTenant("recov");
    const tenantB = uniqueTenant("recov");
    const user = "shared-name";
    await enrollVerifiedFactor(tenantA, user);
    const codesA = (await generateRecoveryCodes(tenantA, user))!.codes;

    expect(await consumeRecoveryCode(tenantA, user, "ZZZZ-ZZZZ")).toBe(false);
    // Tenant B has no factor/codes, so A's code cannot be redeemed under B.
    expect(await consumeRecoveryCode(tenantB, user, codesA[0]!)).toBe(false);
    // A's codes are untouched.
    expect((await recoveryStatus(tenantA, user)).remaining).toBe(10);
  });

  it("admits only one of two concurrent redemptions of the same code (CAS)", async () => {
    const tenant = uniqueTenant("recov");
    const user = "analyst";
    await enrollVerifiedFactor(tenant, user);
    const codes = (await generateRecoveryCodes(tenant, user))!.codes;

    const results = await Promise.all([
      consumeRecoveryCode(tenant, user, codes[0]!),
      consumeRecoveryCode(tenant, user, codes[0]!),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect((await recoveryStatus(tenant, user)).remaining).toBe(9);
  });

  it("regenerating replaces the old set (old codes stop working)", async () => {
    const tenant = uniqueTenant("recov");
    const user = "analyst";
    await enrollVerifiedFactor(tenant, user);
    const first = (await generateRecoveryCodes(tenant, user))!.codes;
    const second = (await generateRecoveryCodes(tenant, user))!.codes;

    // No overlap between the two sets, and the old set is dead.
    expect(first.some((c) => second.includes(c))).toBe(false);
    expect(await consumeRecoveryCode(tenant, user, first[0]!)).toBe(false);
    expect(await consumeRecoveryCode(tenant, user, second[0]!)).toBe(true);
  });

  it("removeFactor deletes the factor and its codes", async () => {
    const tenant = uniqueTenant("recov");
    const user = "analyst";
    await enrollVerifiedFactor(tenant, user);
    const codes = (await generateRecoveryCodes(tenant, user))!.codes;

    expect(await removeFactor(tenant, user)).toBe(true);
    expect(await getFactorStatus(tenant, user)).toEqual({
      enrolled: false,
      verified: false,
    });
    // With the row gone, recovery status is empty and codes no longer redeem.
    expect(await recoveryStatus(tenant, user)).toEqual({
      enabled: false,
      remaining: 0,
    });
    expect(await consumeRecoveryCode(tenant, user, codes[0]!)).toBe(false);
    // Removing again is a no-op.
    expect(await removeFactor(tenant, user)).toBe(false);
  });
});
