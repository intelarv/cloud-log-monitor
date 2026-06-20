// M23: Notifier specialist agent. Runs LAST in the extended pipeline ONLY
// (AGENT_PIPELINE_EXTENDED). Given one finding plus the Triage, Verifier, and
// Context verdicts, it DRAFTS a notification — channel + urgency + a PHI-free
// message — for a human to review and dispatch. It NEVER sends: drafting only,
// HITL preserved (real dispatch stays behind the channel router). Pure function
// over the redacted view; no DB writes, no tool calls, no network.

import { z } from "zod/v4";
import type { FindingSafe } from "@workspace/db";
import {
  NOTIFIER_AGENT_MODEL,
  NOTIFIER_AGENT_SYSTEM_PROMPT,
  NOTIFIER_AGENT_VERSION,
  notifierPromptHash,
} from "../prompts";
import { type LlmAgentRuntime } from "../llm-runtime";
import { resolveLlmForDecisionPoint } from "../llm-decision-points";
import { parseStrictJson } from "./triage";
import type { TriageVerdict } from "./triage";
import type { VerifierVerdict } from "./verifier";
import type { ContextVerdict } from "./context";

export const notifierDraftSchema = z.object({
  channel: z.enum(["pagerduty", "slack", "webhook", "none"]),
  urgency: z.enum(["page", "notify", "digest", "suppress"]),
  subject: z.string().min(1).max(200),
  body: z.string().min(1).max(2000),
  confidence: z.number().min(0).max(1),
});

export type NotifierDraft = z.infer<typeof notifierDraftSchema>;

export interface NotifierAgentIdentity {
  agent: "notifier";
  agent_version: string;
  model_id: string;
  prompt_hash: string;
}

/** See `triageAgentIdentity` doc — `modelId` defaults to the prompt-constant
 *  but the supervisor passes the effective id from the runtime so the audit
 *  ledger records what actually ran. */
export function notifierAgentIdentity(
  modelId: string = NOTIFIER_AGENT_MODEL,
): NotifierAgentIdentity {
  return {
    agent: "notifier",
    agent_version: NOTIFIER_AGENT_VERSION,
    model_id: modelId,
    prompt_hash: notifierPromptHash(),
  };
}

function buildUserPrompt(
  finding: FindingSafe,
  triage: TriageVerdict,
  verifier: VerifierVerdict,
  context: ContextVerdict,
): string {
  const ev = finding.redactedEvidence as {
    snippet?: string;
    redactions?: string[];
  };
  const snippet = (ev?.snippet ?? "").slice(0, 2000);
  const redactions = Array.isArray(ev?.redactions) ? ev.redactions.join(",") : "";
  return `<FINDING id="${finding.id}" classification="${finding.classification}" subclass="${finding.subclass ?? ""}" severity="${finding.severity}" source="${finding.source}" detector="${finding.detectorVersion}" trust="untrusted" redactions="${redactions}">
${snippet}
</FINDING>

<TRIAGE recommended_severity="${triage.recommended_severity}" recommended_action="${triage.recommended_action}" confidence="${triage.confidence.toFixed(2)}" prompt_injection_suspected="${triage.prompt_injection_suspected}">
${triage.rationale}
</TRIAGE>

<VERIFIER verdict="${verifier.verdict}" confidence="${verifier.confidence.toFixed(2)}" prompt_injection_suspected="${verifier.prompt_injection_suspected}" agrees_with_triage="${verifier.agrees_with_triage}">
${verifier.rationale}
</VERIFIER>

<CONTEXT owner="${context.owner ?? ""}" blast_radius="${context.blast_radius}" confidence="${context.confidence.toFixed(2)}">
${context.summary}
</CONTEXT>

Produce your JSON notification draft per the system instructions.`;
}

// Throws on parse failure — the Supervisor catches and ledgers
// `agent.review_failed`. No retry inside the agent.
export async function runNotifierAgent(
  finding: FindingSafe,
  triage: TriageVerdict,
  verifier: VerifierVerdict,
  context: ContextVerdict,
  runtime?: LlmAgentRuntime,
): Promise<{ verdict: NotifierDraft; approxOutputTokens: number; modelId: string }> {
  // Injected runtime (tests) wins and keeps the prompt-pinned model. With no
  // injection, resolve this point's own provider/model (M17 per-decision-point).
  const resolved = runtime
    ? { runtime, modelId: NOTIFIER_AGENT_MODEL }
    : resolveLlmForDecisionPoint("notifier", NOTIFIER_AGENT_MODEL);
  const userPrompt = buildUserPrompt(finding, triage, verifier, context);
  const out = await resolved.runtime.generate({
    systemPrompt: NOTIFIER_AGENT_SYSTEM_PROMPT,
    userPrompt,
    modelId: resolved.modelId,
    temperature: 0.1,
    maxOutputTokens: 512,
  });
  const verdict = parseStrictJson(out.text, notifierDraftSchema);
  return { verdict, approxOutputTokens: out.approxOutputTokens, modelId: out.modelId };
}
