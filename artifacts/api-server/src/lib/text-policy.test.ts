// Boundary tests for the free-text validator used by break-glass
// justification, approval notes, and step-up reasons. Architect review on
// M1.7.1 specifically asked for these: assert that PHI/secrets/canary trip,
// that benign text passes, and that matched substrings never leave the
// validator (only detector names do).

import { describe, it, expect } from "vitest";
import { CANARY_TOKEN } from "@workspace/db";
import { validateLedgerSafeText } from "./text-policy";

describe("validateLedgerSafeText", () => {
  it("accepts benign analyst text", () => {
    const r = validateLedgerSafeText(
      "investigating credential exposure incident per ticket OPS-4421",
    );
    expect(r.ok).toBe(true);
  });

  it("accepts empty string", () => {
    // The caller's Zod schema enforces a min length; this validator is
    // only responsible for content safety. Empty in → ok out.
    const r = validateLedgerSafeText("");
    expect(r.ok).toBe(true);
  });

  it("rejects SSN", () => {
    const r = validateLedgerSafeText("patient ssn 123-45-6789 leaked");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("phi_or_secret_in_text");
      expect(r.detectors).toContain("ssn");
    }
  });

  it("rejects email", () => {
    const r = validateLedgerSafeText("escalating per alice@example.com today");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("phi_or_secret_in_text");
      expect(r.detectors).toContain("email");
    }
  });

  it("rejects AWS access key id", () => {
    const r = validateLedgerSafeText("key AKIAIOSFODNN7EXAMPLE was leaked");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.detectors).toContain("aws_akid");
    }
  });

  it("rejects JWT-shaped tokens", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
      "eyJzdWIiOiIxMjM0NSIsIm5hbWUiOiJBbGljZSJ9." +
      "abcd1234efgh5678ijkl9012";
    const r = validateLedgerSafeText(`token ${jwt} appeared in logs`);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detectors).toContain("jwt");
  });

  it("rejects MRN-like values", () => {
    const r = validateLedgerSafeText("see record MRN: 998877 for context");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.detectors).toContain("mrn_like");
  });

  it("rejects the honeypot canary token with reason=canary", () => {
    const r = validateLedgerSafeText(
      `harmless text ${CANARY_TOKEN} more text`,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("canary_token_in_text");
      expect(r.detectors).toEqual(["canary"]);
    }
  });

  it("canary check fires BEFORE PHI scan (so canary+PHI reports canary)", () => {
    // Defends the §25 invariant that an injected canary is always
    // categorized as such, even if the attacker pads with PHI.
    const r = validateLedgerSafeText(
      `${CANARY_TOKEN} and also ssn 123-45-6789`,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toBe("canary_token_in_text");
  });

  it("never returns the matched substring in the result (PHI must not leak via the validator itself)", () => {
    // Threat-model invariant: detector NAMES are safe metadata, matched
    // substrings are not. The validator's return type should not carry
    // them.
    const r = validateLedgerSafeText("contact alice@example.com please");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      const serialized = JSON.stringify(r);
      expect(serialized).not.toContain("alice@example.com");
      expect(serialized).not.toContain("alice");
      // Detector NAMES are fine and expected.
      expect(serialized).toContain("email");
    }
  });

  it("returns deduped detector names when one text trips the same detector multiple times", () => {
    const r = validateLedgerSafeText(
      "two emails: a@b.co and c@d.co both leaked",
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.detectors.filter((d) => d === "email")).toHaveLength(1);
    }
  });
});
