// M5: Verifier specialist agent. Independent second opinion on the
// finding + the Triage verdict. The Verifier is also the live test of
// the prompt-injection defense: snippets containing canary/honeypot
// payloads MUST come back with prompt_injection_suspected = true.

import { z } from "zod/v4";
import type { FindingSafe } from "@workspace/db";
import {
  VERIFIER_AGENT_MODEL,
  VERIFIER_AGENT_SYSTEM_PROMPT,
  VERIFIER_AGENT_VERSION,
  verifierPromptHash,
} from "../prompts";
import { getLlmRuntime, type LlmAgentRuntime } from "../llm-runtime";
import { parseStrictJson } from "./triage";
import type { TriageVerdict } from "./triage";

export const verifierVerdictSchema = z.object({
  verdict: z.enum(["true_positive", "likely_false_positive", "needs_human_review"]),
  rationale: z.string().min(1).max(2000),
  confidence: z.number().min(0).max(1),
  prompt_injection_suspected: z.boolean(),
  agrees_with_triage: z.boolean(),
});

export type VerifierVerdict = z.infer<typeof verifierVerdictSchema>;

export interface VerifierAgentIdentity {
  agent: "verifier";
  agent_version: string;
  model_id: string;
  prompt_hash: string;
}

/** See `triageAgentIdentity` doc — `modelId` defaults to the prompt-constant
 *  but the supervisor passes the effective id from `LlmGenerateResult` so
 *  the audit ledger records what actually ran. */
export function verifierAgentIdentity(modelId: string = VERIFIER_AGENT_MODEL): VerifierAgentIdentity {
  return {
    agent: "verifier",
    agent_version: VERIFIER_AGENT_VERSION,
    model_id: modelId,
    prompt_hash: verifierPromptHash(),
  };
}

function buildUserPrompt(finding: FindingSafe, triage: TriageVerdict): string {
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

Produce your JSON verdict per the system instructions.`;
}

export async function runVerifierAgent(
  finding: FindingSafe,
  triage: TriageVerdict,
  runtime: LlmAgentRuntime = getLlmRuntime(),
): Promise<{ verdict: VerifierVerdict; approxOutputTokens: number; modelId: string }> {
  const userPrompt = buildUserPrompt(finding, triage);
  const out = await runtime.generate({
    systemPrompt: VERIFIER_AGENT_SYSTEM_PROMPT,
    userPrompt,
    modelId: VERIFIER_AGENT_MODEL,
    temperature: 0.1,
    maxOutputTokens: 512,
  });
  const verdict = parseStrictJson(out.text, verifierVerdictSchema);
  return { verdict, approxOutputTokens: out.approxOutputTokens, modelId: out.modelId };
}
