import { describe, expect, it } from "vitest";
import {
  __resetDecisionPointRuntimesForTest,
  decisionPointEnvKeys,
  hasDecisionPointOverride,
  resolveLlmForDecisionPoint,
} from "./llm-decision-points";
import { getLlmRuntime } from "./llm-runtime";
import { PhiGuardLlmRuntime } from "./cloud-llm-runtimes";

// All tests pass an explicit `env` object (never process.env), so the live
// per-point cache is bypassed and there is no cross-test pollution.

describe("hasDecisionPointOverride", () => {
  it("false when no per-point env is set (default-inert)", () => {
    expect(hasDecisionPointOverride("chat", {})).toBe(false);
    expect(hasDecisionPointOverride("triage", {})).toBe(false);
    expect(hasDecisionPointOverride("verifier", {})).toBe(false);
    expect(hasDecisionPointOverride("summary", {})).toBe(false);
  });

  it("global LLM_PROVIDER alone is NOT a per-point override", () => {
    expect(
      hasDecisionPointOverride("chat", { LLM_PROVIDER: "bedrock" }),
    ).toBe(false);
  });

  it("true when the point's own provider/model/creds are set", () => {
    expect(
      hasDecisionPointOverride("chat", { LLM_CHAT_PROVIDER: "vertex" }),
    ).toBe(true);
    expect(
      hasDecisionPointOverride("verifier", { LLM_VERIFIER_MODEL: "x" }),
    ).toBe(true);
    expect(
      hasDecisionPointOverride("triage", { LLM_TRIAGE_AWS_REGION: "us-west-2" }),
    ).toBe(true);
  });

  it("summary honors the legacy MEMORY_SUMMARY_MODEL alias", () => {
    expect(
      hasDecisionPointOverride("summary", { MEMORY_SUMMARY_MODEL: "gemini-2.5-pro" }),
    ).toBe(true);
    // ...but only for summary, not other points
    expect(decisionPointEnvKeys("chat")).not.toContain("MEMORY_SUMMARY_MODEL");
    expect(decisionPointEnvKeys("summary")).toContain("MEMORY_SUMMARY_MODEL");
  });

  it("blank/whitespace values do not count as set", () => {
    expect(hasDecisionPointOverride("chat", { LLM_CHAT_PROVIDER: "  " })).toBe(false);
  });
});

describe("resolveLlmForDecisionPoint — default-inert", () => {
  it("no override ⇒ returns the global runtime + the prompt-pinned model", () => {
    const r = resolveLlmForDecisionPoint("chat", "gemini-2.5-flash", {});
    expect(r.runtime).toBe(getLlmRuntime());
    expect(r.modelId).toBe("gemini-2.5-flash");
  });

  it("a global cloud provider with no per-point env still defers to the global runtime", () => {
    // LLM_PROVIDER without a per-point var is not an override → no fresh build.
    const r = resolveLlmForDecisionPoint("verifier", "gemini-2.5-flash", {
      LLM_PROVIDER: "bedrock",
      AWS_REGION: "us-west-2",
    });
    expect(r.runtime).toBe(getLlmRuntime());
  });
});

describe("resolveLlmForDecisionPoint — per-point provider", () => {
  it("gemini model override builds a fresh Gemini runtime with the new model id", () => {
    const r = resolveLlmForDecisionPoint("chat", "gemini-2.5-flash", {
      LLM_CHAT_MODEL: "gemini-2.5-pro",
    });
    expect(r.modelId).toBe("gemini-2.5-pro");
    // Fresh instance, not the global singleton, but still a working runtime.
    expect(r.runtime).not.toBe(getLlmRuntime());
    expect(typeof r.runtime.generate).toBe("function");
  });

  it("bedrock per point ⇒ PhiGuard-wrapped runtime + claude default model", () => {
    const r = resolveLlmForDecisionPoint("verifier", "gemini-2.5-flash", {
      LLM_VERIFIER_PROVIDER: "bedrock",
      LLM_VERIFIER_AWS_REGION: "us-west-2",
    });
    expect(r.runtime).toBeInstanceOf(PhiGuardLlmRuntime);
    expect(r.modelId).toMatch(/claude/);
  });

  it("per-point model overrides the provider default", () => {
    const r = resolveLlmForDecisionPoint("verifier", "gemini-2.5-flash", {
      LLM_VERIFIER_PROVIDER: "bedrock",
      LLM_VERIFIER_MODEL: "anthropic.claude-3-5-sonnet-20241022-v2:0",
    });
    expect(r.modelId).toBe("anthropic.claude-3-5-sonnet-20241022-v2:0");
  });

  it("vertex per point requires the point's own GCP_PROJECT_ID", () => {
    expect(() =>
      resolveLlmForDecisionPoint("triage", "gemini-2.5-flash", {
        LLM_TRIAGE_PROVIDER: "vertex",
      }),
    ).toThrow(/GCP_PROJECT_ID/);

    const r = resolveLlmForDecisionPoint("triage", "gemini-2.5-flash", {
      LLM_TRIAGE_PROVIDER: "vertex",
      LLM_TRIAGE_GCP_PROJECT_ID: "proj-a",
    });
    expect(r.runtime).toBeInstanceOf(PhiGuardLlmRuntime);
  });

  it("azure per point ⇒ PhiGuard-wrapped runtime", () => {
    const r = resolveLlmForDecisionPoint("chat", "gemini-2.5-flash", {
      LLM_CHAT_PROVIDER: "azure-openai",
      LLM_CHAT_AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com",
      LLM_CHAT_AZURE_OPENAI_API_KEY: "k",
      LLM_CHAT_AZURE_OPENAI_DEPLOYMENT: "gpt4o",
    });
    expect(r.runtime).toBeInstanceOf(PhiGuardLlmRuntime);
  });

  it("a point's provider overrides the global provider; other points stay on the global runtime", () => {
    const env = {
      LLM_PROVIDER: "bedrock",
      AWS_REGION: "us-east-1",
      // chat opts into vertex with its own creds
      LLM_CHAT_PROVIDER: "vertex",
      LLM_CHAT_GCP_PROJECT_ID: "proj-chat",
    };
    const chat = resolveLlmForDecisionPoint("chat", "gemini-2.5-flash", env);
    expect(chat.runtime).toBeInstanceOf(PhiGuardLlmRuntime); // vertex
    // verifier has no per-point env → global runtime, untouched by chat's choice
    const verifier = resolveLlmForDecisionPoint("verifier", "gemini-2.5-flash", env);
    expect(verifier.runtime).toBe(getLlmRuntime());
  });

  it("summary resolves the legacy MEMORY_SUMMARY_MODEL as its model id", () => {
    const r = resolveLlmForDecisionPoint("summary", "gemini-2.5-flash", {
      MEMORY_SUMMARY_MODEL: "gemini-2.5-pro",
    });
    expect(r.modelId).toBe("gemini-2.5-pro");
  });

  it("LLM_SUMMARY_MODEL takes precedence over the legacy alias", () => {
    const r = resolveLlmForDecisionPoint("summary", "gemini-2.5-flash", {
      LLM_SUMMARY_MODEL: "gemini-2.5-flash-lite",
      MEMORY_SUMMARY_MODEL: "gemini-2.5-pro",
    });
    expect(r.modelId).toBe("gemini-2.5-flash-lite");
  });
});

describe("__resetDecisionPointRuntimesForTest", () => {
  it("is callable without throwing", () => {
    expect(() => __resetDecisionPointRuntimesForTest()).not.toThrow();
  });
});
