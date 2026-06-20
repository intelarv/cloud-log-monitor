import { describe, it, expect, beforeEach } from "vitest";
import {
  classifyTier,
  isRouterEnabled,
  loadRouterPolicyFromEnv,
  hasTierOverride,
  tierEnvKeys,
  resolveLlmForRequest,
  __resetRouterRuntimesForTest,
  type RouterPolicy,
} from "./llm-router";
import {
  resolveLlmForDecisionPoint,
  __resetDecisionPointRuntimesForTest,
} from "./llm-decision-points";

const CHAT_DEFAULT_MODEL = "gemini-2.5-flash";

function envOf(extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  // A clean, explicit env that bypasses both module caches (env !== process.env)
  // and sets none of the cloud credentials, so every build resolves to the
  // credential-free gemini-replit path.
  return { ...extra };
}

beforeEach(() => {
  __resetRouterRuntimesForTest();
  __resetDecisionPointRuntimesForTest();
});

describe("isRouterEnabled", () => {
  it("is off by default and for falsey values", () => {
    expect(isRouterEnabled(envOf())).toBe(false);
    for (const v of ["", "0", "false", "off", "no", "nope"]) {
      expect(isRouterEnabled(envOf({ LLM_ROUTER: v }))).toBe(false);
    }
  });

  it("is on for truthy values", () => {
    for (const v of ["1", "true", "on", "yes", "TRUE", " On "]) {
      expect(isRouterEnabled(envOf({ LLM_ROUTER: v }))).toBe(true);
    }
  });
});

describe("loadRouterPolicyFromEnv", () => {
  it("uses defaults when unset", () => {
    const p = loadRouterPolicyFromEnv(envOf());
    expect(p.cheapMaxChars).toBe(280);
    expect(p.strongMinChars).toBe(2000);
  });

  it("honors valid positive-integer overrides", () => {
    const p = loadRouterPolicyFromEnv(
      envOf({
        LLM_ROUTER_CHEAP_MAX_CHARS: "100",
        LLM_ROUTER_STRONG_MIN_CHARS: "5000",
      }),
    );
    expect(p.cheapMaxChars).toBe(100);
    expect(p.strongMinChars).toBe(5000);
  });

  it("ignores blank / non-numeric / non-positive overrides", () => {
    const p = loadRouterPolicyFromEnv(
      envOf({
        LLM_ROUTER_CHEAP_MAX_CHARS: "abc",
        LLM_ROUTER_STRONG_MIN_CHARS: "-5",
      }),
    );
    expect(p.cheapMaxChars).toBe(280);
    expect(p.strongMinChars).toBe(2000);
  });

  it("clamps strongMin to at least cheapMax+1 so tiers never invert", () => {
    const p = loadRouterPolicyFromEnv(
      envOf({
        LLM_ROUTER_CHEAP_MAX_CHARS: "500",
        LLM_ROUTER_STRONG_MIN_CHARS: "100",
      }),
    );
    expect(p.cheapMaxChars).toBe(500);
    expect(p.strongMinChars).toBe(501);
  });
});

describe("classifyTier", () => {
  const policy: RouterPolicy = { cheapMaxChars: 10, strongMinChars: 100 };

  it("routes short input to cheap", () => {
    expect(classifyTier({ text: "hi" }, policy)).toBe("cheap");
    expect(classifyTier({ text: "x".repeat(10) }, policy)).toBe("cheap");
  });

  it("routes mid-length input to standard", () => {
    expect(classifyTier({ text: "x".repeat(11) }, policy)).toBe("standard");
    expect(classifyTier({ text: "x".repeat(99) }, policy)).toBe("standard");
  });

  it("routes long input to strong", () => {
    expect(classifyTier({ text: "x".repeat(100) }, policy)).toBe("strong");
    expect(classifyTier({ text: "x".repeat(5000) }, policy)).toBe("strong");
  });

  it("escalates high-risk to strong regardless of size", () => {
    expect(classifyTier({ text: "hi", highRisk: true }, policy)).toBe("strong");
  });

  it("measures trimmed length so trailing whitespace can't bump a tier", () => {
    expect(classifyTier({ text: "hi" + " ".repeat(50) }, policy)).toBe("cheap");
  });
});

describe("hasTierOverride / tierEnvKeys", () => {
  it("reports no override on a clean env", () => {
    expect(hasTierOverride("cheap", envOf())).toBe(false);
    expect(hasTierOverride("standard", envOf())).toBe(false);
    expect(hasTierOverride("strong", envOf())).toBe(false);
  });

  it("detects an override when any tier key is set", () => {
    expect(hasTierOverride("strong", envOf({ LLM_ROUTER_STRONG_MODEL: "m" }))).toBe(
      true,
    );
    expect(
      hasTierOverride("cheap", envOf({ LLM_ROUTER_CHEAP_PROVIDER: "bedrock" })),
    ).toBe(true);
  });

  it("tierEnvKeys includes the provider + model keys for the tier", () => {
    const keys = tierEnvKeys("strong");
    expect(keys).toContain("LLM_ROUTER_STRONG_PROVIDER");
    expect(keys).toContain("LLM_ROUTER_STRONG_MODEL");
  });
});

describe("resolveLlmForRequest (default-inert)", () => {
  it("router off ⇒ byte-identical to resolveLlmForDecisionPoint", () => {
    const env = envOf();
    const viaRouter = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "anything" },
      env,
    );
    const viaPoint = resolveLlmForDecisionPoint("chat", CHAT_DEFAULT_MODEL, env);
    // Same global runtime singleton + same default model id.
    expect(viaRouter.runtime).toBe(viaPoint.runtime);
    expect(viaRouter.modelId).toBe(viaPoint.modelId);
    expect(viaRouter.modelId).toBe(CHAT_DEFAULT_MODEL);
  });

  it("router on but tier unconfigured ⇒ falls back to point static selection", () => {
    const env = envOf({ LLM_ROUTER: "1" });
    const viaRouter = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "short" }, // routes to cheap, which has no config
      env,
    );
    const viaPoint = resolveLlmForDecisionPoint("chat", CHAT_DEFAULT_MODEL, env);
    expect(viaRouter.runtime).toBe(viaPoint.runtime);
    expect(viaRouter.modelId).toBe(CHAT_DEFAULT_MODEL);
  });
});

describe("resolveLlmForRequest (active routing)", () => {
  it("routes a long request to the configured strong tier model", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_STRONG_MODEL: "strong-model-x",
    });
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "x".repeat(5000) },
      env,
    );
    expect(resolved.modelId).toBe("strong-model-x");
    expect(resolved.runtime).toBeDefined();
    expect(typeof resolved.runtime.generate).toBe("function");
  });

  it("escalates a high-risk short request to the configured strong tier", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_STRONG_MODEL: "strong-model-x",
    });
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "tiny", highRisk: true },
      env,
    );
    expect(resolved.modelId).toBe("strong-model-x");
  });

  it("uses the cheap tier model for short input when configured", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_CHEAP_MODEL: "cheap-model-y",
    });
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "hi" },
      env,
    );
    expect(resolved.modelId).toBe("cheap-model-y");
  });

  it("only the matching tier's config applies (cheap config unused for long input)", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_CHEAP_MODEL: "cheap-model-y",
    });
    // Long input → strong tier, which is unconfigured → fall back to default.
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "x".repeat(5000) },
      env,
    );
    expect(resolved.modelId).toBe(CHAT_DEFAULT_MODEL);
  });

  it("routes a mid-length request to the configured standard tier model", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_STANDARD_MODEL: "standard-model-z",
      LLM_ROUTER_CHEAP_MAX_CHARS: "10",
      LLM_ROUTER_STRONG_MIN_CHARS: "100",
    });
    // 50 chars is above cheapMax (10) and below strongMin (100) ⇒ standard tier.
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "x".repeat(50) },
      env,
    );
    expect(resolved.modelId).toBe("standard-model-z");
  });

  it("a configured standard tier leaves cheap + strong on the static fallback", () => {
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_STANDARD_MODEL: "standard-model-z",
      LLM_ROUTER_CHEAP_MAX_CHARS: "10",
      LLM_ROUTER_STRONG_MIN_CHARS: "100",
    });
    // Short → cheap (unconfigured) → point static selection (default model).
    expect(
      resolveLlmForRequest("chat", CHAT_DEFAULT_MODEL, { text: "hi" }, env)
        .modelId,
    ).toBe(CHAT_DEFAULT_MODEL);
    // Long → strong (unconfigured) → point static selection (default model).
    expect(
      resolveLlmForRequest(
        "chat",
        CHAT_DEFAULT_MODEL,
        { text: "x".repeat(200) },
        env,
      ).modelId,
    ).toBe(CHAT_DEFAULT_MODEL);
  });

  it("per-tier MODEL overlay composes with the global credential-free provider", () => {
    // Setting only the tier MODEL (no PROVIDER) keeps the offline gemini path
    // while overriding the model id — i.e. the overlay composes onto the global
    // config rather than replacing it wholesale.
    const env = envOf({
      LLM_ROUTER: "1",
      LLM_ROUTER_STRONG_MODEL: "strong-model-x",
    });
    const resolved = resolveLlmForRequest(
      "chat",
      CHAT_DEFAULT_MODEL,
      { text: "x".repeat(5000) },
      env,
    );
    expect(resolved.modelId).toBe("strong-model-x");
    // A real runtime is still built (global provider), not a bare stub.
    expect(typeof resolved.runtime.generate).toBe("function");
  });
});
