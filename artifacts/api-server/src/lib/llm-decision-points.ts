// M17: per-decision-point LLM selection.
//
// The system has four places that call an LLM ("decision points"): the chat
// agent, the Triage specialist, the Verifier specialist, and the memory
// consolidation summarizer. Historically all four shared ONE global runtime
// (`getLlmRuntime()`) chosen by `LLM_PROVIDER` / `DEPLOYMENT_TARGET`, so the
// whole fleet ran on a single provider.
//
// This module lets each point run on a FULLY DIFFERENT provider + model
// (e.g. verifier → Bedrock Claude, chat → Gemini) by reading a per-point
// SCOPED env overlay (`LLM_<POINT>_PROVIDER`, `LLM_<POINT>_MODEL`, and
// per-point credential overrides) and building a dedicated runtime through the
// SAME `loadLlmRuntimeConfigFromEnv` + `createLlmRuntime` factory used at boot.
//
// DEFAULT-INERT invariant: if a point has NO per-point env set, it resolves to
// the global `getLlmRuntime()` + its prompt-pinned default model id — i.e.
// byte-identical to the pre-M17 single-runtime behavior. The credential-free
// eval gate sets none of these vars, so it stays byte-identical.
//
// The input-based LLM *router* (pick a model per request from the input) is a
// deferred future milestone (see docs/MILESTONES.md) — this module only does
// static per-point selection.

import {
  createLlmRuntime,
  loadLlmRuntimeConfigFromEnv,
} from "./llm-runtime-config";
import {
  getLlmRuntime,
  makeGeminiRuntime,
  type LlmAgentRuntime,
} from "./llm-runtime";
import { logger } from "./logger";

export type LlmDecisionPoint = "chat" | "triage" | "verifier" | "summary";

export const ALL_LLM_DECISION_POINTS: readonly LlmDecisionPoint[] = [
  "chat",
  "triage",
  "verifier",
  "summary",
];

// Maps a global config env var (read by loadLlmRuntimeConfigFromEnv /
// createLlmRuntime) to its per-point suffix. A per-point var
// `LLM_<POINT>_<suffix>` overlays the corresponding global var when set.
// `LLM_DEFAULT_MODEL` is surfaced as the friendlier `..._MODEL`.
const OVERLAY_KEYS: Readonly<Record<string, string>> = {
  LLM_PROVIDER: "PROVIDER",
  LLM_DEFAULT_MODEL: "MODEL",
  AWS_REGION: "AWS_REGION",
  GCP_PROJECT_ID: "GCP_PROJECT_ID",
  GCP_LOCATION: "GCP_LOCATION",
  AZURE_OPENAI_ENDPOINT: "AZURE_OPENAI_ENDPOINT",
  AZURE_OPENAI_API_KEY: "AZURE_OPENAI_API_KEY",
  AZURE_OPENAI_DEPLOYMENT: "AZURE_OPENAI_DEPLOYMENT",
  AZURE_OPENAI_API_VERSION: "AZURE_OPENAI_API_VERSION",
};

function pointPrefix(point: LlmDecisionPoint): string {
  return `LLM_${point.toUpperCase()}_`;
}

/** All per-point env var names whose presence signals an override for `point`.
 *  `summary` additionally honors the pre-M17 `MEMORY_SUMMARY_MODEL` alias. */
export function decisionPointEnvKeys(point: LlmDecisionPoint): string[] {
  const prefix = pointPrefix(point);
  const keys = Object.values(OVERLAY_KEYS).map((suffix) => prefix + suffix);
  if (point === "summary") keys.push("MEMORY_SUMMARY_MODEL");
  return keys;
}

function isSet(env: NodeJS.ProcessEnv, key: string): boolean {
  return (env[key]?.trim() ?? "") !== "";
}

/** True when ANY per-point env var is set for this decision point. When false,
 *  the point uses the global runtime unchanged (byte-identical to pre-M17). */
export function hasDecisionPointOverride(
  point: LlmDecisionPoint,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return decisionPointEnvKeys(point).some((k) => isSet(env, k));
}

/** Build a per-point env view: each `LLM_<POINT>_<suffix>` (when set) overrides
 *  the matching global key, so the existing config factory resolves the point's
 *  own provider/model/credentials while still falling back to global values for
 *  anything not overridden. */
function scopedEnv(
  point: LlmDecisionPoint,
  env: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const prefix = pointPrefix(point);
  const merged: NodeJS.ProcessEnv = { ...env };
  for (const [base, suffix] of Object.entries(OVERLAY_KEYS)) {
    const v = env[prefix + suffix];
    if (v !== undefined && v.trim() !== "") merged[base] = v;
  }
  // Back-compat: pre-M17 the summarizer read MEMORY_SUMMARY_MODEL directly.
  // Honor it as the summary model when the new LLM_SUMMARY_MODEL is not set.
  if (point === "summary" && !isSet(env, prefix + "MODEL")) {
    const legacy = env["MEMORY_SUMMARY_MODEL"]?.trim();
    if (legacy) merged["LLM_DEFAULT_MODEL"] = legacy;
  }
  return merged;
}

export interface ResolvedDecisionPointLlm {
  runtime: LlmAgentRuntime;
  /** Model-id hint to pass to `generate()`. For gemini-replit this is the
   *  model actually used; cloud runtimes may still override with their
   *  operator-configured default (the runtime returns the effective id). */
  modelId: string;
}

// Built cloud runtimes are cached per point so we don't reconstruct the SDK
// client (+ PhiGuard wrapper) on every call. Only cached for the live
// `process.env` path; test calls pass an explicit env and bypass the cache.
//
// CONTRACT: per-point LLM config is **boot-time only**, same as the global
// `getLlmRuntime()` singleton it falls back to — env is read once and the
// resolved runtime is reused for the process lifetime. Mutating `LLM_<POINT>_*`
// on the live `process.env` after first resolve will NOT rebuild that point's
// runtime (by design — there is no runtime config-reload path in this system).
// Tests that need to re-resolve against different env call
// `__resetDecisionPointRuntimesForTest()` (or pass an explicit env, which
// bypasses the cache entirely).
const cache = new Map<LlmDecisionPoint, ResolvedDecisionPointLlm>();

/**
 * Resolve the runtime + model-id hint for a decision point.
 *
 * No per-point env ⇒ `{ getLlmRuntime(), defaultModelId }` (byte-identical to
 * the pre-M17 single-runtime path). Otherwise build a dedicated runtime from
 * the per-point scoped env via the shared `createLlmRuntime` factory (cloud
 * providers wrapped in PhiGuard; gemini-replit ⇒ a fresh Gemini runtime).
 */
export function resolveLlmForDecisionPoint(
  point: LlmDecisionPoint,
  defaultModelId: string,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedDecisionPointLlm {
  if (!hasDecisionPointOverride(point, env)) {
    return { runtime: getLlmRuntime(), modelId: defaultModelId };
  }

  const useCache = env === process.env;
  if (useCache) {
    const hit = cache.get(point);
    if (hit) return hit;
  }

  const sEnv = scopedEnv(point, env);
  const cfg = loadLlmRuntimeConfigFromEnv(sEnv);
  const runtime = createLlmRuntime(cfg, sEnv) ?? makeGeminiRuntime();
  const modelId =
    sEnv["LLM_DEFAULT_MODEL"]?.trim() || cfg.defaultModelId || defaultModelId;

  const resolved: ResolvedDecisionPointLlm = { runtime, modelId };
  if (useCache) {
    cache.set(point, resolved);
    logger.info(
      { point, provider: cfg.provider, modelId },
      "per-decision-point LLM runtime resolved",
    );
  }
  return resolved;
}

/** Test-only: drop cached per-point runtimes so a later test can re-resolve
 *  against different env. */
export function __resetDecisionPointRuntimesForTest(): void {
  cache.clear();
}
