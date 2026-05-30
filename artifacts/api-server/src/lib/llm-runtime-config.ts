import { logger } from "./logger";
import {
  setLlmRuntime,
  type LlmAgentRuntime,
} from "./llm-runtime";
import {
  AzureOpenAILlmRuntime,
  BedrockLlmRuntime,
  PhiGuardLlmRuntime,
  VertexLlmRuntime,
} from "./cloud-llm-runtimes";

// ---------------------------------------------------------------------------
// Cloud-aware LlmAgentRuntime selection
// ---------------------------------------------------------------------------
//
// Mirrors embedder-config.ts. The agent specialists (Triage, Verifier) and
// the chat agent all call `getLlmRuntime()` — switching providers is one env
// flip with no code changes.
//
// Configuration precedence (highest to lowest):
//   1. LLM_PROVIDER               — explicit override
//   2. DEPLOYMENT_TARGET          — cloud-shortcut: aws / gcp / azure / local / replit
//   3. (default)                  — gemini-replit (Replit AI Integrations)
//
// PHI guard wraps every cloud provider (not the dev default; the dev path
// uses Replit AI Integrations which has its own data-handling agreement and
// the input/output is already scanForPhi'd at the agent boundary).
// ---------------------------------------------------------------------------

export type LlmProvider =
  | "gemini-replit"
  | "bedrock"
  | "vertex"
  | "azure-openai";

export const ALL_LLM_PROVIDERS: readonly LlmProvider[] = [
  "gemini-replit",
  "bedrock",
  "vertex",
  "azure-openai",
];

// Default model id per provider. Chosen for cost/latency on the agent path
// (Triage/Verifier are short, structured-JSON calls — flash-class is plenty).
// Operators override per-agent at the prompts.ts layer if needed.
export const DEFAULT_MODEL_BY_LLM_PROVIDER: Record<LlmProvider, string | null> = {
  "gemini-replit": null, // model picked by prompts.ts (gemini-2.5-flash)
  bedrock: "anthropic.claude-3-5-haiku-20241022-v1:0",
  vertex: "gemini-2.5-flash",
  "azure-openai": null, // Azure routes by deployment name, not model id
};

export const LLM_PROVIDER_BY_DEPLOYMENT_TARGET: Record<string, LlmProvider> = {
  aws: "bedrock",
  gcp: "vertex",
  azure: "azure-openai",
  local: "gemini-replit",
  dev: "gemini-replit",
  replit: "gemini-replit",
};

export interface LlmRuntimeConfig {
  provider: LlmProvider;
  defaultModelId: string | null;
}

export function isLlmProvider(s: string): s is LlmProvider {
  return (ALL_LLM_PROVIDERS as readonly string[]).includes(s);
}

/**
 * Parse env vars into an LlmRuntimeConfig. Pure function: no I/O, no side
 * effects, no SDK loading. Throws on invalid input rather than silently
 * falling back.
 */
export function loadLlmRuntimeConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): LlmRuntimeConfig {
  const explicit = env["LLM_PROVIDER"]?.trim().toLowerCase();
  const target = env["DEPLOYMENT_TARGET"]?.trim().toLowerCase();

  let provider: LlmProvider;
  if (explicit) {
    if (!isLlmProvider(explicit)) {
      throw new Error(
        `LLM_PROVIDER=${explicit} is not a known provider. ` +
          `Valid: ${ALL_LLM_PROVIDERS.join(", ")}`,
      );
    }
    provider = explicit;
  } else if (target && target in LLM_PROVIDER_BY_DEPLOYMENT_TARGET) {
    provider = LLM_PROVIDER_BY_DEPLOYMENT_TARGET[target]!;
  } else {
    provider = "gemini-replit";
  }

  const defaultModelId =
    env["LLM_DEFAULT_MODEL"]?.trim() || DEFAULT_MODEL_BY_LLM_PROVIDER[provider];

  return { provider, defaultModelId };
}

/**
 * Build an LlmAgentRuntime for the given config. Cloud providers are wrapped
 * in PhiGuardLlmRuntime. Returns null for `gemini-replit` because that path
 * is the module's hard-coded default — letting the caller keep it untouched
 * avoids importing the Replit AI Integration into adapter tests.
 */
export function createLlmRuntime(
  cfg: LlmRuntimeConfig,
  env: NodeJS.ProcessEnv = process.env,
): LlmAgentRuntime | null {
  switch (cfg.provider) {
    case "gemini-replit":
      return null;
    case "bedrock": {
      const inner = new BedrockLlmRuntime({
        region: env["AWS_REGION"] ?? "us-east-1",
        ...(cfg.defaultModelId ? { defaultModelId: cfg.defaultModelId } : {}),
      });
      return new PhiGuardLlmRuntime(inner);
    }
    case "vertex": {
      const inner = new VertexLlmRuntime({
        project: requireEnv(env, "GCP_PROJECT_ID"),
        location: env["GCP_LOCATION"] ?? "us-central1",
        ...(cfg.defaultModelId ? { defaultModelId: cfg.defaultModelId } : {}),
      });
      return new PhiGuardLlmRuntime(inner);
    }
    case "azure-openai": {
      const inner = new AzureOpenAILlmRuntime({
        endpoint: requireEnv(env, "AZURE_OPENAI_ENDPOINT"),
        apiKey: requireEnv(env, "AZURE_OPENAI_API_KEY"),
        deployment: requireEnv(env, "AZURE_OPENAI_DEPLOYMENT"),
        apiVersion: env["AZURE_OPENAI_API_VERSION"] ?? "2024-08-01-preview",
      });
      return new PhiGuardLlmRuntime(inner);
    }
  }
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name]?.trim();
  if (!v) {
    throw new Error(`${name} is required for the configured LLM provider`);
  }
  return v;
}

/**
 * Apply env-driven LLM runtime selection at boot. No-op (and silent) when the
 * provider is `gemini-replit` so the dev/Replit default keeps working without
 * any env config. Logs the selection so operators can confirm.
 */
export function initLlmRuntimeFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): LlmRuntimeConfig {
  const config = loadLlmRuntimeConfigFromEnv(env);
  const runtime = createLlmRuntime(config, env);
  if (runtime) {
    setLlmRuntime(runtime);
  }
  logger.info(
    {
      provider: config.provider,
      defaultModelId: config.defaultModelId,
      phiGuard: config.provider !== "gemini-replit",
    },
    "LLM runtime initialized",
  );
  return config;
}
