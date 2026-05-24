// M5: Triage specialist agent. Given one finding, asks the LLM for a
// recommended severity + immediate action category. Pure function over the
// redacted view — no DB writes, no tool calls. The Supervisor owns
// persistence and ledger writes.

import { z } from "zod/v4";
import type { FindingSafe } from "@workspace/db";
import {
  TRIAGE_AGENT_MODEL,
  TRIAGE_AGENT_SYSTEM_PROMPT,
  TRIAGE_AGENT_VERSION,
  triagePromptHash,
} from "../prompts";
import { getLlmRuntime, type LlmAgentRuntime } from "../llm-runtime";

export const triageVerdictSchema = z.object({
  recommended_severity: z.enum(["low", "medium", "high", "critical"]),
  recommended_action: z.enum([
    "page_oncall",
    "open_ticket",
    "human_review",
    "auto_resolve",
  ]),
  rationale: z.string().min(1).max(2000),
  confidence: z.number().min(0).max(1),
  prompt_injection_suspected: z.boolean(),
});

export type TriageVerdict = z.infer<typeof triageVerdictSchema>;

export interface TriageAgentIdentity {
  agent: "triage";
  agent_version: string;
  model_id: string;
  prompt_hash: string;
}

export function triageAgentIdentity(): TriageAgentIdentity {
  return {
    agent: "triage",
    agent_version: TRIAGE_AGENT_VERSION,
    model_id: TRIAGE_AGENT_MODEL,
    prompt_hash: triagePromptHash(),
  };
}

function buildUserPrompt(finding: FindingSafe): string {
  const ev = finding.redactedEvidence as {
    snippet?: string;
    trust?: string;
    redactions?: string[];
  };
  const snippet = (ev?.snippet ?? "").slice(0, 2000);
  const redactions = Array.isArray(ev?.redactions) ? ev.redactions.join(",") : "";
  return `<FINDING id="${finding.id}" classification="${finding.classification}" subclass="${finding.subclass ?? ""}" severity="${finding.severity}" source="${finding.source}" detector="${finding.detectorVersion}" trust="untrusted" redactions="${redactions}">
${snippet}
</FINDING>

Produce your JSON verdict per the system instructions.`;
}

// Throws on parse failure — the Supervisor catches and ledgers
// `agent.review_failed`. We don't retry inside the agent; the Supervisor
// decides retry policy.
export async function runTriageAgent(
  finding: FindingSafe,
  runtime: LlmAgentRuntime = getLlmRuntime(),
): Promise<{ verdict: TriageVerdict; approxOutputTokens: number }> {
  const userPrompt = buildUserPrompt(finding);
  const out = await runtime.generate({
    systemPrompt: TRIAGE_AGENT_SYSTEM_PROMPT,
    userPrompt,
    modelId: TRIAGE_AGENT_MODEL,
    temperature: 0.1,
    maxOutputTokens: 512,
  });
  const verdict = parseStrictJson(out.text, triageVerdictSchema);
  return { verdict, approxOutputTokens: out.approxOutputTokens };
}

// Strip common markdown fences the model occasionally emits despite the
// "no fences" instruction, then parse + Zod-validate. Throws with a stable
// shape on failure.
export function parseStrictJson<T>(text: string, schema: z.ZodType<T>): T {
  let cleaned = text.trim();
  if (cleaned.startsWith("```")) {
    cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/i, "").trim();
  }
  // Some models emit prose before/after the object — extract the first {...}
  // block as a fallback. Brace-counting is naive but adequate here because
  // verdict objects are small and never embed nested strings with braces.
  if (!cleaned.startsWith("{")) {
    const start = cleaned.indexOf("{");
    const end = cleaned.lastIndexOf("}");
    if (start >= 0 && end > start) cleaned = cleaned.slice(start, end + 1);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch (e) {
    throw new Error(`agent returned non-JSON: ${(e as Error).message}`);
  }
  const res = schema.safeParse(parsed);
  if (!res.success) {
    throw new Error(`agent JSON failed schema: ${res.error.message}`);
  }
  return res.data;
}
