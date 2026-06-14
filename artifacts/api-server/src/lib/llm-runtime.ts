// M5 + M9.5: thin LlmAgentRuntime interface around the LLM call so the
// specialist agents (Triage, Verifier) AND the chat agent share the same
// cloud-portable seam. Production runtimes (Bedrock Converse, Vertex
// generateContent, Azure OpenAI Chat Completions) live in
// cloud-llm-runtimes.ts; the default below wraps Replit's Gemini AI
// Integration. Tests inject a `FakeLlmRuntime` that returns canned strings.
//
// The interface has two methods:
//
//   - `generate(opts)`           blocking, used by Triage/Verifier whose
//                                callers want the parsed verdict
//   - `generateStream(opts)`     incremental text deltas, used by the chat
//                                agent for AG-UI SSE. Optional on the
//                                interface so existing test fakes that only
//                                implement `generate` keep working — the
//                                `streamFromRuntime` helper below adapts a
//                                blocking impl to a single-chunk stream.

import { ai } from "@workspace/integrations-gemini-ai";

/** A single turn of prior dialogue. `model` maps to `assistant` for OpenAI-
 *  shaped providers (Bedrock Converse / Azure OpenAI) and stays `model` for
 *  Gemini/Vertex. Kept minimal — text-only, no tool roles, because the chat
 *  agent's tool-call protocol is JSON-in-text, not provider-native function
 *  calling. */
export interface LlmHistoryTurn {
  role: "user" | "model";
  text: string;
}

export interface LlmGenerateOpts {
  systemPrompt: string;
  /** Final user message that the model should respond to. */
  userPrompt: string;
  /** Caller's preferred model id — a *hint*. Cloud runtimes that have an
   *  operator-configured `LLM_DEFAULT_MODEL` will use that instead, because
   *  the prompt-constant model id is provider-specific (e.g. agent prompts
   *  pin a Gemini id; Bedrock can't honor that). The runtime returns the
   *  effective model id in `LlmGenerateResult.modelId` / the final
   *  `LlmStreamChunk.done.modelId` so the audit ledger records what was
   *  actually called, not what was requested. */
  modelId: string;
  /** Prior turns of the conversation, oldest first. The runtime prepends
   *  these before `userPrompt`. Omit/empty for single-turn calls (the
   *  specialist agents' default). */
  history?: LlmHistoryTurn[];
  /** 0.0..1.0; defaults to 0.2 for deterministic-ish structured output. */
  temperature?: number;
  /** Hard cap on output size. */
  maxOutputTokens?: number;
}

export interface LlmGenerateResult {
  text: string;
  /** Approximate output token count for cost accounting. Cloud providers
   *  that return authoritative counts (Bedrock Converse, Azure OpenAI,
   *  Vertex usageMetadata) use them; the Gemini stream wrapper here
   *  falls back to a chars/4 estimate. Marked approximate explicitly so
   *  callers don't treat it as authoritative billing data. */
  approxOutputTokens: number;
  /** Effective model id that actually serviced the request. May differ
   *  from `opts.modelId` when a cloud runtime overrides with its
   *  operator-configured default. Used by Supervisor + agents to ledger
   *  accurate `agent_identity.model_id` per audit / non-repudiation
   *  (ARCH §24, threat_model §Repudiation). */
  modelId: string;
}

/** Stream chunk shape. Every text delta arrives as `{text: "..."}`; the
 *  stream ends with a single `{done: {...}}` chunk carrying the final
 *  usage + effective model id. Implementations MUST emit `done` exactly
 *  once, as the last chunk. */
export interface LlmStreamChunk {
  text?: string;
  done?: { approxOutputTokens: number; modelId: string };
}

export interface LlmAgentRuntime {
  generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult>;
  /** Optional incremental-streaming entry. Required for the chat agent;
   *  optional on the interface so test fakes that only need blocking
   *  `generate` (Triage/Verifier tests) don't have to implement both.
   *  Callers should use `streamFromRuntime(runtime, opts)` which falls
   *  back to a single-chunk stream when this is undefined. */
  generateStream?(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk>;
}

/** Adapter: returns an async-iterable of stream chunks regardless of
 *  whether the underlying runtime implements `generateStream`. Fallback is
 *  one `{text}` chunk + one `{done}` chunk built from `generate()` —
 *  preserves the contract so chat-agent code is uniform. */
export async function* streamFromRuntime(
  runtime: LlmAgentRuntime,
  opts: LlmGenerateOpts,
): AsyncIterable<LlmStreamChunk> {
  if (runtime.generateStream) {
    yield* runtime.generateStream(opts);
    return;
  }
  const r = await runtime.generate(opts);
  if (r.text) yield { text: r.text };
  yield { done: { approxOutputTokens: r.approxOutputTokens, modelId: r.modelId } };
}

// Default runtime: Gemini via Replit AI Integration. `generate` buffers the
// stream (specialist consumers want the parsed verdict, not deltas);
// `generateStream` exposes the underlying SDK's native streaming so chat
// SSE doesn't pay an extra blocking round-trip.
class GeminiLlmRuntime implements LlmAgentRuntime {
  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    let text = "";
    let approxOutputTokens = 0;
    let modelId = opts.modelId;
    for await (const chunk of this.generateStream(opts)) {
      if (chunk.text) text += chunk.text;
      if (chunk.done) {
        approxOutputTokens = chunk.done.approxOutputTokens;
        modelId = chunk.done.modelId;
      }
    }
    return { text, approxOutputTokens, modelId };
  }

  async *generateStream(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk> {
    // Gemini SDK uses {role: 'user'|'model', parts: [{text}]}. Our
    // `LlmHistoryTurn.role` is already in that vocabulary so the mapping
    // is a pass-through.
    const history = (opts.history ?? []).map((h) => ({
      role: h.role,
      parts: [{ text: h.text }],
    }));
    const stream = await ai.models.generateContentStream({
      model: opts.modelId,
      contents: [
        ...history,
        { role: "user" as const, parts: [{ text: opts.userPrompt }] },
      ],
      config: {
        systemInstruction: opts.systemPrompt,
        temperature: opts.temperature ?? 0.2,
        maxOutputTokens: opts.maxOutputTokens ?? 512,
      },
    });
    let total = 0;
    for await (const chunk of stream) {
      const t = chunk.text;
      if (t) {
        total += t.length;
        yield { text: t };
      }
    }
    // chars / 4 is the standard rough Gemini/BPE estimate. Production
    // would replace with usageMetadata.totalTokenCount when available.
    yield {
      done: { approxOutputTokens: Math.ceil(total / 4), modelId: opts.modelId },
    };
  }
}

/** Build a fresh, stateless Gemini (Replit AI Integration) runtime. Used by
 *  the per-decision-point resolver (`llm-decision-points.ts`) when a point
 *  resolves to `gemini-replit` even though the *global* runtime may have been
 *  swapped to a cloud provider at boot — the global singleton can't be reused
 *  in that case. Cheap: GeminiLlmRuntime holds no per-instance state. */
export function makeGeminiRuntime(): LlmAgentRuntime {
  return new GeminiLlmRuntime();
}

let runtime: LlmAgentRuntime = new GeminiLlmRuntime();

export function getLlmRuntime(): LlmAgentRuntime {
  return runtime;
}

/** Production setter — used at boot by `initLlmRuntimeFromEnv()` to swap in
 *  a cloud-provider runtime when `LLM_PROVIDER` / `DEPLOYMENT_TARGET` is set. */
export function setLlmRuntime(r: LlmAgentRuntime): void {
  runtime = r;
}

/** Test-only alias for `setLlmRuntime`. Kept as a separate name so test
 *  intent is explicit at call sites. */
export function __setLlmRuntimeForTest(r: LlmAgentRuntime): void {
  runtime = r;
}

/** Test-only: restore the default Gemini runtime. */
export function __resetLlmRuntimeForTest(): void {
  runtime = new GeminiLlmRuntime();
}
