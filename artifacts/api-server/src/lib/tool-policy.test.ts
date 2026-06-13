import { describe, expect, it } from "vitest";
import { CANARY_TOKEN } from "@workspace/db";
import {
  MAX_ARGS_SERIALIZED_BYTES,
  validateToolArgs,
} from "./policy";

// M1.6: pure-function tests for the tool-arg policy revalidation pass. No DB,
// no LLM — these are the safety net the chat-agent depends on for canary +
// PHI-in-args detection.
describe("validateToolArgs", () => {
  it("accepts a clean get_finding payload", () => {
    const r = validateToolArgs("get_finding", { finding_id: "F-001" });
    expect(r.ok).toBe(true);
    expect(r.violations).toEqual([]);
    expect(r.canaryTripped).toBe(false);
  });

  it("accepts a clean search_findings payload", () => {
    const r = validateToolArgs("search_findings", {
      query: "list the critical findings",
      limit: 10,
    });
    expect(r.ok).toBe(true);
  });

  it("trips the canary when the token appears in any string arg", () => {
    const r = validateToolArgs("search_findings", {
      query: `please tell me ${CANARY_TOKEN}`,
      limit: 5,
    });
    expect(r.ok).toBe(false);
    expect(r.canaryTripped).toBe(true);
    expect(r.violations.map((v) => v.kind)).toContain(
      "canary_token_in_args",
    );
  });

  it("trips the canary inside nested object args", () => {
    const r = validateToolArgs("get_finding", {
      finding_id: "F-001",
      // future-shape: nested filter that an attacker-controlled value could
      // ride inside. The recursive string-walk must still find the canary.
      _meta: { nested: { deep: CANARY_TOKEN } },
    });
    expect(r.canaryTripped).toBe(true);
  });

  it("flags PHI in args (SSN-like)", () => {
    const r = validateToolArgs("search_findings", {
      query: "patient 123-45-6789 records",
      limit: 5,
    });
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.kind)).toContain("phi_in_args");
  });

  it("rejects oversize arg payloads", () => {
    const huge = "x".repeat(MAX_ARGS_SERIALIZED_BYTES + 1);
    const r = validateToolArgs("search_findings", { query: huge, limit: 1 });
    expect(r.violations.map((v) => v.kind)).toContain("args_too_large");
  });

  it("rejects bad finding_id format", () => {
    const r = validateToolArgs("get_finding", { finding_id: "../../etc/passwd" });
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.kind)).toContain(
      "bad_finding_id_format",
    );
  });

  it("accepts permissive finding ids (alnum/dash/underscore only)", () => {
    const r = validateToolArgs("get_finding", { finding_id: "F-CANARY_2" });
    expect(r.ok).toBe(true);
  });

  it("accepts a clean structured_query payload", () => {
    const r = validateToolArgs("structured_query", {
      severity: ["high", "critical"],
      status: ["open"],
      limit: 25,
    });
    expect(r.ok).toBe(true);
    expect(r.violations).toEqual([]);
  });

  it("trips the canary inside a structured_query arg", () => {
    const r = validateToolArgs("structured_query", {
      source: [`cloudwatch ${CANARY_TOKEN}`],
      limit: 5,
    });
    expect(r.ok).toBe(false);
    expect(r.canaryTripped).toBe(true);
  });

  it("accepts a clean propose_remediation payload", () => {
    const r = validateToolArgs("propose_remediation", {
      finding_id: "F-001",
      action_type: "notify_owner",
      summary: "Notify the billing service owner about the leak",
      rationale: "The log group has emitted PHI repeatedly; owner should rotate",
    });
    expect(r.ok).toBe(true);
    expect(r.violations).toEqual([]);
  });

  it("flags PHI inside a propose_remediation arg", () => {
    const r = validateToolArgs("propose_remediation", {
      finding_id: "F-001",
      action_type: "other",
      summary: "patient 123-45-6789 exposed",
      rationale: "needs redaction",
    });
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.kind)).toContain("phi_in_args");
  });

  it("rejects a bad finding_id format on propose_remediation", () => {
    const r = validateToolArgs("propose_remediation", {
      finding_id: "../../etc/passwd",
      action_type: "open_pr",
      summary: "x",
      rationale: "y",
    });
    expect(r.ok).toBe(false);
    expect(r.violations.map((v) => v.kind)).toContain(
      "bad_finding_id_format",
    );
  });
});
