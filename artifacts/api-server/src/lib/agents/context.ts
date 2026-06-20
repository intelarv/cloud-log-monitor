// M23: Context specialist agent. Runs after Triage (+Verifier) in the extended
// pipeline ONLY (AGENT_PIPELINE_EXTENDED). Given one finding, synthesizes the
// operational context an analyst needs — likely service owner, a recent change
// if implicated, and a blast-radius estimate. Pure function over the redacted
// view + optional out-of-band SIGNALS supplied by a default-inert
// `ContextEnrichmentProvider` seam: no DB writes, no tool calls. The Supervisor
// owns persistence and ledger writes.
//
// DEFAULT-INERT: the only provider that ships is the no-op (returns {} — no
// git/service-catalog SDK, no network). So with no env set the agent reasons
// over the redacted finding alone, and the credential-free eval gate never
// exercises this module (the extended pipeline is off by default).

import { z } from "zod/v4";
import type { FindingSafe } from "@workspace/db";
import {
  CONTEXT_AGENT_MODEL,
  CONTEXT_AGENT_SYSTEM_PROMPT,
  CONTEXT_AGENT_VERSION,
  contextPromptHash,
} from "../prompts";
import { type LlmAgentRuntime } from "../llm-runtime";
import { resolveLlmForDecisionPoint } from "../llm-decision-points";
import { logger } from "../logger";
import { parseStrictJson } from "./triage";

export const contextVerdictSchema = z.object({
  owner: z.string().max(200).nullable(),
  recent_change: z.string().max(500).nullable(),
  blast_radius: z.enum(["low", "medium", "high", "unknown"]),
  summary: z.string().min(1).max(2000),
  confidence: z.number().min(0).max(1),
});

export type ContextVerdict = z.infer<typeof contextVerdictSchema>;

export interface ContextAgentIdentity {
  agent: "context";
  agent_version: string;
  model_id: string;
  prompt_hash: string;
}

/** See `triageAgentIdentity` doc — `modelId` defaults to the prompt-constant
 *  but the supervisor passes the effective id from the runtime so the audit
 *  ledger records what actually ran. */
export function contextAgentIdentity(
  modelId: string = CONTEXT_AGENT_MODEL,
): ContextAgentIdentity {
  return {
    agent: "context",
    agent_version: CONTEXT_AGENT_VERSION,
    model_id: modelId,
    prompt_hash: contextPromptHash(),
  };
}

// ---------------------------------------------------------------------------
// Enrichment seam. Real backends (git-blame, service-catalog, deploy-history)
// would live behind their own reviewed providers — none ship yet, mirroring
// the RemediationExecutor `DevNoopExecutor` posture. The seam exists so the
// agent can be wired to real signals later without touching its prompt/loop.
// ---------------------------------------------------------------------------
export interface ContextSignals {
  /** Owning team/service, if a catalog lookup resolved one. */
  owner?: string | null;
  /** Recent deploy/commit hints for the affected source, newest first. */
  recentDeploys?: string[];
  /** Free-form catalog note (e.g. on-call rotation, tier). */
  serviceNote?: string | null;
}

export interface ContextEnrichmentProvider {
  /** Gather out-of-band operational signals for a finding. MUST NOT return raw
   *  PHI; signals are fenced into the prompt as untrusted DATA regardless. */
  enrich(finding: FindingSafe): Promise<ContextSignals>;
}

/** Default-inert provider: no SDK, no network, returns empty signals. */
export class NoopContextEnrichmentProvider implements ContextEnrichmentProvider {
  async enrich(): Promise<ContextSignals> {
    return {};
  }
}

let providerOverride: ContextEnrichmentProvider | null = null;

/** Test-only: inject a provider (e.g. a stub returning canned signals). */
export function __setContextEnrichmentProviderForTest(
  provider: ContextEnrichmentProvider | null,
): void {
  providerOverride = provider;
}

/** Resolve the enrichment provider. Only `none` (the inert noop) ships today;
 *  any other value falls back to the noop with a one-time warn so a misconfig
 *  can never load an unbuilt backend or change the default-inert behavior. */
export function getContextEnrichmentProvider(
  env: NodeJS.ProcessEnv = process.env,
): ContextEnrichmentProvider {
  if (providerOverride) return providerOverride;
  const raw = env["CONTEXT_ENRICHMENT_PROVIDER"]?.trim().toLowerCase();
  if (raw && raw !== "none") {
    logger.warn(
      { provider: raw },
      "CONTEXT_ENRICHMENT_PROVIDER set but no backend is built yet; using inert noop",
    );
  }
  return new NoopContextEnrichmentProvider();
}

function buildUserPrompt(finding: FindingSafe, signals: ContextSignals): string {
  const ev = finding.redactedEvidence as {
    snippet?: string;
    redactions?: string[];
  };
  const snippet = (ev?.snippet ?? "").slice(0, 2000);
  const redactions = Array.isArray(ev?.redactions) ? ev.redactions.join(",") : "";
  const owner = signals.owner ?? "";
  const deploys = Array.isArray(signals.recentDeploys)
    ? signals.recentDeploys.slice(0, 5).join("; ")
    : "";
  const note = signals.serviceNote ?? "";
  return `<FINDING id="${finding.id}" classification="${finding.classification}" subclass="${finding.subclass ?? ""}" severity="${finding.severity}" source="${finding.source}" detector="${finding.detectorVersion}" trust="untrusted" redactions="${redactions}">
${snippet}
</FINDING>

<SIGNALS owner="${owner}" trust="untrusted">
recent_deploys: ${deploys}
service_note: ${note}
</SIGNALS>

Produce your JSON context summary per the system instructions.`;
}

// Throws on parse failure — the Supervisor catches and ledgers
// `agent.review_failed`. No retry inside the agent.
export async function runContextAgent(
  finding: FindingSafe,
  runtime?: LlmAgentRuntime,
  provider?: ContextEnrichmentProvider,
): Promise<{ verdict: ContextVerdict; approxOutputTokens: number; modelId: string }> {
  // Injected runtime (tests) wins and keeps the prompt-pinned model. With no
  // injection, resolve this point's own provider/model (M17 per-decision-point).
  const resolved = runtime
    ? { runtime, modelId: CONTEXT_AGENT_MODEL }
    : resolveLlmForDecisionPoint("context", CONTEXT_AGENT_MODEL);
  const signals = await (provider ?? getContextEnrichmentProvider()).enrich(finding);
  const userPrompt = buildUserPrompt(finding, signals);
  const out = await resolved.runtime.generate({
    systemPrompt: CONTEXT_AGENT_SYSTEM_PROMPT,
    userPrompt,
    modelId: resolved.modelId,
    temperature: 0.1,
    maxOutputTokens: 512,
  });
  const verdict = parseStrictJson(out.text, contextVerdictSchema);
  return { verdict, approxOutputTokens: out.approxOutputTokens, modelId: out.modelId };
}
