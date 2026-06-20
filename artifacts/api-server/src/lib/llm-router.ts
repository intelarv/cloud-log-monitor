// Input-based LLM router (request-driven model selection).
//
// M17 (`llm-decision-points.ts`) selects a runtime per DECISION POINT — chosen
// statically once at boot. This module adds the DYNAMIC counterpart: pick the
// model per REQUEST from the input's content (size) + an optional risk flag,
// layered IN FRONT of M17.
//
// DEFAULT-INERT invariant: when `LLM_ROUTER` is unset/off, `resolveLlmForRequest`
// is exactly `resolveLlmForDecisionPoint(point, defaultModelId, env)` — i.e.
// byte-identical to the M17 path, so the credential-free eval gate is unchanged.
// (The agent loops only resolve when no runtime is injected; tests inject
// `deps.runtime` and bypass resolution entirely, so the router never runs there.)
//
// When ON, the router:
//   1. classifies the request into a TIER (`cheap | standard | strong`) from a
//      deterministic policy over input length + an optional `highRisk` flag, then
//   2. resolves a runtime for that tier from a per-tier scoped env overlay
//      (`LLM_ROUTER_<TIER>_<PROVIDER|MODEL|...>`) via the SAME
//      `loadLlmRuntimeConfigFromEnv` + `createLlmRuntime` factory M17 uses.
//
// BUDGET-AWARE FALLBACK: a tier with no env override falls back to
// `resolveLlmForDecisionPoint(point, defaultModelId, env)`, so the router
// COMPOSES with M17: request → tier → [tier config] else point static → global.
// This means an operator can configure only the `strong` tier (escalate long /
// high-risk requests to a bigger model) and leave everything else on the cheap
// default, with no other wiring.
//
// PHI posture: the router reads only the request's TEXT LENGTH and a boolean
// risk flag for classification — never the content itself — and never logs the
// input. It builds no SDK unless a tier is configured (same posture as M17).

import {
  createLlmRuntime,
  loadLlmRuntimeConfigFromEnv,
} from "./llm-runtime-config";
import {
  getLlmRuntime,
  makeGeminiRuntime,
  type LlmAgentRuntime,
} from "./llm-runtime";
import {
  OVERLAY_KEYS,
  resolveLlmForDecisionPoint,
  type LlmDecisionPoint,
  type ResolvedDecisionPointLlm,
} from "./llm-decision-points";
import { logger } from "./logger";

export type RouterTier = "cheap" | "standard" | "strong";

export const ALL_ROUTER_TIERS: readonly RouterTier[] = [
  "cheap",
  "standard",
  "strong",
];

/** Per-request signal the router classifies. `text` is the user/request input
 *  (only its LENGTH is read, never the content); `highRisk` lets a caller that
 *  knows the request touches a high/critical-severity finding force escalation
 *  regardless of size (e.g. triage/verifier could pass finding severity). */
export interface RoutingSignal {
  text: string;
  highRisk?: boolean;
}

export interface RouterPolicy {
  /** Inputs at or below this length (and not high-risk) route to `cheap`. */
  cheapMaxChars: number;
  /** Inputs at or above this length route to `strong`. */
  strongMinChars: number;
}

const DEFAULT_CHEAP_MAX_CHARS = 280;
const DEFAULT_STRONG_MIN_CHARS = 2000;

function truthy(v: string | undefined): boolean {
  if (v === undefined) return false;
  const s = v.trim().toLowerCase();
  return s === "1" || s === "true" || s === "on" || s === "yes";
}

/** Parse a positive integer env override, ignoring blanks / non-numeric / ≤0. */
function posIntEnv(
  env: NodeJS.ProcessEnv,
  key: string,
  fallback: number,
): number {
  const raw = env[key]?.trim();
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

/** True when the input-based router is enabled (`LLM_ROUTER` truthy). Off by
 *  default ⇒ `resolveLlmForRequest` is byte-identical to the M17 static path. */
export function isRouterEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return truthy(env["LLM_ROUTER"]);
}

/** Load the (env-tunable) routing thresholds. `strongMin` is clamped to be at
 *  least `cheapMax + 1` so the three tiers never overlap/invert under a
 *  misconfiguration. */
export function loadRouterPolicyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): RouterPolicy {
  const cheapMaxChars = posIntEnv(
    env,
    "LLM_ROUTER_CHEAP_MAX_CHARS",
    DEFAULT_CHEAP_MAX_CHARS,
  );
  const strongMinChars = Math.max(
    cheapMaxChars + 1,
    posIntEnv(env, "LLM_ROUTER_STRONG_MIN_CHARS", DEFAULT_STRONG_MIN_CHARS),
  );
  return { cheapMaxChars, strongMinChars };
}

/** Deterministically classify a request into a tier. High-risk always escalates
 *  to `strong`; otherwise short → `cheap`, long → `strong`, middle → `standard`.
 *  Length is measured on the trimmed input so trailing whitespace can't tip a
 *  short prompt into `standard`. */
export function classifyTier(
  signal: RoutingSignal,
  policy: RouterPolicy,
): RouterTier {
  if (signal.highRisk) return "strong";
  const len = signal.text.trim().length;
  if (len <= policy.cheapMaxChars) return "cheap";
  if (len >= policy.strongMinChars) return "strong";
  return "standard";
}

function tierPrefix(tier: RouterTier): string {
  return `LLM_ROUTER_${tier.toUpperCase()}_`;
}

/** All env var names whose presence signals a configured override for `tier`. */
export function tierEnvKeys(tier: RouterTier): string[] {
  const prefix = tierPrefix(tier);
  return Object.values(OVERLAY_KEYS).map((suffix) => prefix + suffix);
}

function isSet(env: NodeJS.ProcessEnv, key: string): boolean {
  return (env[key]?.trim() ?? "") !== "";
}

/** True when ANY per-tier env var is set. When false the tier is unconfigured
 *  and `resolveLlmForRequest` falls back to the point's static M17 selection. */
export function hasTierOverride(
  tier: RouterTier,
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  return tierEnvKeys(tier).some((k) => isSet(env, k));
}

/** Overlay each set `LLM_ROUTER_<TIER>_<suffix>` onto the matching global key so
 *  the shared config factory resolves the tier's own provider/model/credentials,
 *  falling back to global values for anything not overridden. Mirrors the M17
 *  per-point overlay, reusing the same `OVERLAY_KEYS` map. */
function scopedTierEnv(
  tier: RouterTier,
  env: NodeJS.ProcessEnv,
): NodeJS.ProcessEnv {
  const prefix = tierPrefix(tier);
  const merged: NodeJS.ProcessEnv = { ...env };
  for (const [base, suffix] of Object.entries(OVERLAY_KEYS)) {
    const v = env[prefix + suffix];
    if (v !== undefined && v.trim() !== "") merged[base] = v;
  }
  return merged;
}

// Built per-tier runtimes are cached for the live `process.env` path so the SDK
// client (+ PhiGuard wrapper) is constructed at most once per tier. Test calls
// pass an explicit env and bypass the cache. Same boot-time-only contract as the
// M17 cache: mutating `LLM_ROUTER_*` on live env after first resolve will not
// rebuild a tier's runtime (call `__resetRouterRuntimesForTest()` in tests).
const tierCache = new Map<RouterTier, ResolvedDecisionPointLlm>();

function resolveTierRuntime(
  tier: RouterTier,
  defaultModelId: string,
  env: NodeJS.ProcessEnv,
): ResolvedDecisionPointLlm {
  const useCache = env === process.env;
  if (useCache) {
    const hit = tierCache.get(tier);
    if (hit) return hit;
  }

  const sEnv = scopedTierEnv(tier, env);
  const cfg = loadLlmRuntimeConfigFromEnv(sEnv);
  const runtime: LlmAgentRuntime =
    createLlmRuntime(cfg, sEnv) ?? makeGeminiRuntime();
  const modelId =
    sEnv["LLM_DEFAULT_MODEL"]?.trim() || cfg.defaultModelId || defaultModelId;

  const resolved: ResolvedDecisionPointLlm = { runtime, modelId };
  if (useCache) {
    tierCache.set(tier, resolved);
    logger.info(
      { tier, provider: cfg.provider, modelId },
      "input-based LLM router tier runtime resolved",
    );
  }
  return resolved;
}

/**
 * Resolve the runtime + model-id hint for ONE request.
 *
 * Router off ⇒ `resolveLlmForDecisionPoint(point, defaultModelId, env)`
 * (byte-identical to M17). Router on ⇒ classify the request into a tier; if the
 * tier is configured (`LLM_ROUTER_<TIER>_*`), build/return its dedicated runtime;
 * otherwise fall back to the point's static M17 selection.
 */
export function resolveLlmForRequest(
  point: LlmDecisionPoint,
  defaultModelId: string,
  signal: RoutingSignal,
  env: NodeJS.ProcessEnv = process.env,
): ResolvedDecisionPointLlm {
  if (!isRouterEnabled(env)) {
    return resolveLlmForDecisionPoint(point, defaultModelId, env);
  }
  const tier = classifyTier(signal, loadRouterPolicyFromEnv(env));
  if (!hasTierOverride(tier, env)) {
    // Unconfigured tier → compose with M17 (point static → global).
    return resolveLlmForDecisionPoint(point, defaultModelId, env);
  }
  return resolveTierRuntime(tier, defaultModelId, env);
}

/** Test-only: drop cached per-tier runtimes so a later test can re-resolve
 *  against different env. */
export function __resetRouterRuntimesForTest(): void {
  tierCache.clear();
}
