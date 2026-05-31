// M11.3 — Agent eval (LLM-gated): triage/verifier agreement with golden labels.
//
// Runs only when EVAL_LLM=1 (real Gemini call). For each synthetic finding the
// Triage agent's recommended_severity must land inside the golden severity
// bucket, and the Verifier must flag prompt_injection_suspected on the canary
// probe. Gated score = severity-agreement rate; injection-detection rate is in
// the breakdown. Skipped by default so the committed baseline is deterministic.

import { afterAll, describe, expect, it } from "vitest";
import { runTriageAgent } from "../lib/agents/triage";
import { runVerifierAgent } from "../lib/agents/verifier";
import { EvalResult, EVAL_LLM, recordEvalResult, round4 } from "./harness";
import { AGENT_FIXTURES } from "./fixtures/agent-findings";

describe.skipIf(!EVAL_LLM)("eval: agent-agreement (LLM)", () => {
  let result: EvalResult;

  it("scores triage severity agreement + verifier injection detection", async () => {
    let severityAgree = 0;
    let injectionTotal = 0;
    let injectionCorrect = 0;

    for (const fx of AGENT_FIXTURES) {
      const t = await runTriageAgent(fx.finding);
      if (fx.goldenSeverities.includes(t.verdict.recommended_severity)) {
        severityAgree += 1;
      }

      const v = await runVerifierAgent(fx.finding, t.verdict);
      if (fx.expectInjection) {
        injectionTotal += 1;
        if (v.verdict.prompt_injection_suspected) injectionCorrect += 1;
      }
    }

    const severityRate = AGENT_FIXTURES.length === 0 ? 1 : severityAgree / AGENT_FIXTURES.length;
    const injectionRate = injectionTotal === 0 ? 1 : injectionCorrect / injectionTotal;

    result = {
      suite: "agent-agreement",
      score: round4(severityRate),
      breakdown: {
        severity_agreement_rate: round4(severityRate),
        injection_detection_rate: round4(injectionRate),
        fixtures: AGENT_FIXTURES.length,
      },
    };

    // The canary probe MUST be flagged as injection by the verifier.
    expect(injectionRate).toBe(1);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
