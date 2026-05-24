// M5: thin LlmAgentRuntime interface around the LLM call so specialist
// agents (Triage, Verifier) can be tested without hitting the network and
// so the production runtime can be swapped for Bedrock AgentCore / Vertex
// AI Agent Builder per ARCHITECTURE.md §20 without rewriting the agents.
//
// The default runtime wraps Replit's Gemini AI Integration (same library
// the chat agent uses). Tests inject a `FakeLlmRuntime` that returns
// canned strings, so the specialist tests assert orchestration shape
// (parse / persist / ledger), not model behavior.

import { ai } from "@workspace/integrations-gemini-ai";

export interface LlmGenerateOpts {
  systemPrompt: string;
  userPrompt: string;
  modelId: string;
  /** 0.0..1.0; defaults to 0.2 for deterministic-ish structured output. */
  temperature?: number;
  /** Hard cap on output size. */
  maxOutputTokens?: number;
}

export interface LlmGenerateResult {
  text: string;
  /** Approximate output token count for cost accounting. Real providers
   *  return this via usageMetadata; the Gemini stream wrapper here doesn't,
   *  so we fall back to a chars/4 estimate. Marked approximate explicitly
   *  so callers don't treat it as authoritative billing data. */
  approxOutputTokens: number;
}

export interface LlmAgentRuntime {
  generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult>;
}

// Default runtime: non-streaming Gemini call. Specialist agents don't
// stream — their consumers want the parsed verdict, not deltas.
class GeminiLlmRuntime implements LlmAgentRuntime {
  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    const stream = await ai.models.generateContentStream({
      model: opts.modelId,
      contents: [{ role: "user", parts: [{ text: opts.userPrompt }] }],
      config: {
        systemInstruction: opts.systemPrompt,
        temperature: opts.temperature ?? 0.2,
        maxOutputTokens: opts.maxOutputTokens ?? 512,
      },
    });
    let text = "";
    for await (const chunk of stream) {
      if (chunk.text) text += chunk.text;
    }
    return {
      text,
      // chars / 4 is the standard rough Gemini/BPE estimate. Production
      // would replace with usageMetadata.totalTokenCount when available.
      approxOutputTokens: Math.ceil(text.length / 4),
    };
  }
}

let runtime: LlmAgentRuntime = new GeminiLlmRuntime();

export function getLlmRuntime(): LlmAgentRuntime {
  return runtime;
}

/** Test-only: swap in a fake runtime. Production code never calls this. */
export function __setLlmRuntimeForTest(r: LlmAgentRuntime): void {
  runtime = r;
}

/** Test-only: restore the default Gemini runtime. */
export function __resetLlmRuntimeForTest(): void {
  runtime = new GeminiLlmRuntime();
}
