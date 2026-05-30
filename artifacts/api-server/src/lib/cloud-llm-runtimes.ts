import type {
  LlmAgentRuntime,
  LlmGenerateOpts,
  LlmGenerateResult,
  LlmHistoryTurn,
  LlmStreamChunk,
} from "./llm-runtime";
import { scanForPhi } from "./redact";

// Hidden-import shim — same pattern as cloud-embedders.ts / cloud-log-sources.ts.
// Keeps optional cloud SDKs out of the dev install and out of TS static analysis.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ---------------------------------------------------------------------------
// Cloud-specific LlmAgentRuntime implementations.
//
// Each class supports BOTH `generate` (blocking; used by Triage/Verifier) AND
// `generateStream` (incremental deltas; used by the chat agent's AG-UI SSE).
// `generate` is implemented in terms of `generateStream` so the streaming
// path is the canonical one and the blocking path can't drift.
//
// PhiGuardLlmRuntime wraps every one of these — outbound prompt text to a
// third-party model endpoint is PHI-scanned before it ever reaches the wire.
// See threat_model.md §Info Disclosure: defense in depth on top of
// findingSafeColumns / scanForPhi-on-output already in the agents pipeline.
// ---------------------------------------------------------------------------

/** Drains an AsyncIterable<LlmStreamChunk> into a single LlmGenerateResult.
 *  Shared between every cloud runtime so the blocking + streaming paths
 *  produce identical text / token counts / model ids. */
async function drainStream(
  stream: AsyncIterable<LlmStreamChunk>,
  fallbackModelId: string,
): Promise<LlmGenerateResult> {
  let text = "";
  let approxOutputTokens = 0;
  let modelId = fallbackModelId;
  for await (const chunk of stream) {
    if (chunk.text) text += chunk.text;
    if (chunk.done) {
      approxOutputTokens = chunk.done.approxOutputTokens;
      modelId = chunk.done.modelId;
    }
  }
  return { text, approxOutputTokens, modelId };
}

/** Map our `LlmHistoryTurn` to the {role:'user'|'assistant'} shape used by
 *  Bedrock Converse + Azure OpenAI. */
function toAssistantRole(turns: readonly LlmHistoryTurn[]): Array<{
  role: "user" | "assistant";
  text: string;
}> {
  return turns.map((t) => ({
    role: t.role === "model" ? "assistant" : "user",
    text: t.text,
  }));
}

// ---------------------------------------------------------------------------
// AWS Bedrock — Converse / ConverseStream APIs (model-agnostic chat shape).
//
// Why Converse: same call surface works across Claude, Llama, Titan, Mistral,
// Nova — operators pick the model via env without code changes.
//
// Auth: standard AWS SDK credential chain (IRSA on EKS, env, instance role).
// ---------------------------------------------------------------------------
export class BedrockLlmRuntime implements LlmAgentRuntime {
  private clientPromise: Promise<BedrockBindings> | null = null;

  constructor(
    private readonly opts: {
      region: string;
      /** Default model id if the caller doesn't pin one in opts.modelId. */
      defaultModelId?: string;
    },
  ) {}

  private async getClient(): Promise<BedrockBindings> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          const id = "@aws-sdk/client-bedrock-runtime";
          mod = await loadOptional(id);
        } catch {
          throw new Error(
            "Bedrock LLM runtime selected but @aws-sdk/client-bedrock-runtime " +
              "is not installed. Run: pnpm --filter @workspace/api-server add @aws-sdk/client-bedrock-runtime",
          );
        }
        const client = new mod.BedrockRuntimeClient({ region: this.opts.region });
        return {
          send: (cmd: unknown): Promise<BedrockResponse> =>
            client.send(cmd) as Promise<BedrockResponse>,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ConverseCommand: mod.ConverseCommand as new (args: any) => unknown,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          ConverseStreamCommand: mod.ConverseStreamCommand as new (args: any) => unknown,
        };
      })();
    }
    return this.clientPromise;
  }

  private resolveModelId(opts: LlmGenerateOpts): string {
    // Operator-configured `defaultModelId` wins. Callers (Triage / Verifier)
    // pass a prompt-constant model id (e.g. a Gemini id) which Bedrock can't
    // service — this lets the operator's `LLM_DEFAULT_MODEL` env actually
    // control which model runs.
    const modelId = this.opts.defaultModelId || opts.modelId;
    if (!modelId) {
      throw new Error(
        "Bedrock: no model id resolved. Set LLM_DEFAULT_MODEL or pass opts.modelId.",
      );
    }
    return modelId;
  }

  private buildMessages(opts: LlmGenerateOpts): Array<{
    role: "user" | "assistant";
    content: Array<{ text: string }>;
  }> {
    const history = toAssistantRole(opts.history ?? []);
    return [
      ...history.map((h) => ({ role: h.role, content: [{ text: h.text }] })),
      { role: "user" as const, content: [{ text: opts.userPrompt }] },
    ];
  }

  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    const { send, ConverseCommand } = await this.getClient();
    const modelId = this.resolveModelId(opts);
    const cmd = new ConverseCommand({
      modelId,
      system: [{ text: opts.systemPrompt }],
      messages: this.buildMessages(opts),
      inferenceConfig: {
        temperature: opts.temperature ?? 0.2,
        maxTokens: opts.maxOutputTokens ?? 512,
      },
    });
    const resp = await send(cmd);
    const text =
      resp.output?.message?.content?.map((c) => c.text ?? "").join("") ?? "";
    // Bedrock Converse returns authoritative token counts — prefer them.
    const approxOutputTokens =
      resp.usage?.outputTokens ?? Math.ceil(text.length / 4);
    return { text, approxOutputTokens, modelId };
  }

  async *generateStream(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk> {
    const { send, ConverseStreamCommand } = await this.getClient();
    const modelId = this.resolveModelId(opts);
    const cmd = new ConverseStreamCommand({
      modelId,
      system: [{ text: opts.systemPrompt }],
      messages: this.buildMessages(opts),
      inferenceConfig: {
        temperature: opts.temperature ?? 0.2,
        maxTokens: opts.maxOutputTokens ?? 512,
      },
    });
    const resp = await send(cmd);
    let charCount = 0;
    let authoritativeTokens: number | undefined;
    if (resp.stream) {
      for await (const event of resp.stream) {
        const delta = event.contentBlockDelta?.delta?.text;
        if (delta) {
          charCount += delta.length;
          yield { text: delta };
        }
        if (event.metadata?.usage?.outputTokens != null) {
          authoritativeTokens = event.metadata.usage.outputTokens;
        }
      }
    }
    yield {
      done: {
        approxOutputTokens: authoritativeTokens ?? Math.ceil(charCount / 4),
        modelId,
      },
    };
  }
}

interface BedrockResponse {
  output?: { message?: { content?: Array<{ text?: string }> } };
  usage?: { outputTokens?: number };
  // ConverseStreamCommand response shape (subset).
  stream?: AsyncIterable<{
    contentBlockDelta?: { delta?: { text?: string } };
    metadata?: { usage?: { outputTokens?: number } };
  }>;
}

interface BedrockBindings {
  send: (cmd: unknown) => Promise<BedrockResponse>;
  ConverseCommand: new (args: {
    modelId: string;
    system: Array<{ text: string }>;
    messages: Array<{ role: "user" | "assistant"; content: Array<{ text: string }> }>;
    inferenceConfig: { temperature?: number; maxTokens?: number };
  }) => unknown;
  ConverseStreamCommand: new (args: {
    modelId: string;
    system: Array<{ text: string }>;
    messages: Array<{ role: "user" | "assistant"; content: Array<{ text: string }> }>;
    inferenceConfig: { temperature?: number; maxTokens?: number };
  }) => unknown;
}

// ---------------------------------------------------------------------------
// GCP Vertex AI — generateContent + streamGenerateContent REST (Gemini on
// Vertex). BAA-eligible. Pure REST via Application Default Credentials.
// ---------------------------------------------------------------------------
export class VertexLlmRuntime implements LlmAgentRuntime {
  private authPromise: Promise<VertexAuth> | null = null;

  constructor(
    private readonly opts: {
      project: string;
      location: string;
      defaultModelId?: string;
    },
  ) {}

  private async getAuth(): Promise<VertexAuth> {
    if (!this.authPromise) {
      this.authPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          const id = "google-auth-library";
          mod = await loadOptional(id);
        } catch {
          throw new Error(
            "Vertex LLM runtime selected but google-auth-library is not " +
              "installed. Run: pnpm --filter @workspace/api-server add google-auth-library",
          );
        }
        const auth = new mod.GoogleAuth({
          scopes: ["https://www.googleapis.com/auth/cloud-platform"],
        });
        return {
          getAccessToken: async (): Promise<string> => {
            const t = (await auth.getAccessToken()) as string | null | undefined;
            if (!t) throw new Error("Vertex: failed to obtain access token");
            return t;
          },
        };
      })();
    }
    return this.authPromise;
  }

  private resolveModelId(opts: LlmGenerateOpts): string {
    const modelId = this.opts.defaultModelId || opts.modelId;
    if (!modelId) {
      throw new Error(
        "Vertex: no model id resolved. Set LLM_DEFAULT_MODEL or pass opts.modelId.",
      );
    }
    return modelId;
  }

  private buildBody(opts: LlmGenerateOpts): unknown {
    // Vertex contents shape matches Gemini: role 'user'|'model', parts[{text}].
    const history = (opts.history ?? []).map((h) => ({
      role: h.role,
      parts: [{ text: h.text }],
    }));
    return {
      systemInstruction: { parts: [{ text: opts.systemPrompt }] },
      contents: [
        ...history,
        { role: "user", parts: [{ text: opts.userPrompt }] },
      ],
      generationConfig: {
        temperature: opts.temperature ?? 0.2,
        maxOutputTokens: opts.maxOutputTokens ?? 512,
      },
    };
  }

  private endpoint(modelId: string, method: string): string {
    return (
      `https://${this.opts.location}-aiplatform.googleapis.com/v1/projects/` +
      `${this.opts.project}/locations/${this.opts.location}/publishers/google/models/` +
      `${modelId}:${method}`
    );
  }

  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    const modelId = this.resolveModelId(opts);
    const token = await (await this.getAuth()).getAccessToken();
    const resp = await fetch(this.endpoint(modelId, "generateContent"), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(this.buildBody(opts)),
    });
    if (!resp.ok) {
      throw new Error(
        `Vertex generateContent failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const json = (await resp.json()) as {
      candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
      usageMetadata?: { candidatesTokenCount?: number };
    };
    const text =
      json.candidates?.[0]?.content?.parts?.map((p) => p.text ?? "").join("") ??
      "";
    const approxOutputTokens =
      json.usageMetadata?.candidatesTokenCount ?? Math.ceil(text.length / 4);
    return { text, approxOutputTokens, modelId };
  }

  async *generateStream(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk> {
    const modelId = this.resolveModelId(opts);
    const token = await (await this.getAuth()).getAccessToken();
    // `?alt=sse` makes Vertex emit Server-Sent Events; without it the
    // endpoint returns a JSON array, which buffers the whole response.
    const resp = await fetch(
      this.endpoint(modelId, "streamGenerateContent") + "?alt=sse",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
          Accept: "text/event-stream",
        },
        body: JSON.stringify(this.buildBody(opts)),
      },
    );
    if (!resp.ok || !resp.body) {
      throw new Error(
        `Vertex streamGenerateContent failed: ${resp.status} ${await resp.text()}`,
      );
    }
    let charCount = 0;
    let authoritativeTokens: number | undefined;
    for await (const event of parseSseStream(resp.body)) {
      if (event === "[DONE]") continue;
      let json: {
        candidates?: Array<{ content?: { parts?: Array<{ text?: string }> } }>;
        usageMetadata?: { candidatesTokenCount?: number };
      };
      try {
        json = JSON.parse(event);
      } catch {
        continue;
      }
      const parts = json.candidates?.[0]?.content?.parts ?? [];
      for (const p of parts) {
        if (p.text) {
          charCount += p.text.length;
          yield { text: p.text };
        }
      }
      if (json.usageMetadata?.candidatesTokenCount != null) {
        authoritativeTokens = json.usageMetadata.candidatesTokenCount;
      }
    }
    yield {
      done: {
        approxOutputTokens: authoritativeTokens ?? Math.ceil(charCount / 4),
        modelId,
      },
    };
  }
}

interface VertexAuth {
  getAccessToken: () => Promise<string>;
}

// ---------------------------------------------------------------------------
// Azure OpenAI — Chat Completions REST (blocking + streaming via SSE).
// BAA-eligible via the operator's Azure OpenAI resource. Pure fetch.
// ---------------------------------------------------------------------------
export class AzureOpenAILlmRuntime implements LlmAgentRuntime {
  constructor(
    private readonly opts: {
      endpoint: string;
      apiKey: string;
      deployment: string;
      apiVersion: string;
    },
  ) {}

  // Azure routes by deployment name, not model id — the deployment is the
  // operator-stable identity we can record in the ledger.
  private get modelId(): string {
    return `azure-openai:${this.opts.deployment}`;
  }

  private url(): string {
    const base = this.opts.endpoint.replace(/\/$/, "");
    return (
      `${base}/openai/deployments/${this.opts.deployment}/chat/completions?` +
      `api-version=${encodeURIComponent(this.opts.apiVersion)}`
    );
  }

  private buildMessages(opts: LlmGenerateOpts): Array<{
    role: "system" | "user" | "assistant";
    content: string;
  }> {
    const history = toAssistantRole(opts.history ?? []);
    return [
      { role: "system", content: opts.systemPrompt },
      ...history.map((h) => ({ role: h.role, content: h.text })),
      { role: "user", content: opts.userPrompt },
    ];
  }

  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    const resp = await fetch(this.url(), {
      method: "POST",
      headers: {
        "api-key": this.opts.apiKey,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        messages: this.buildMessages(opts),
        temperature: opts.temperature ?? 0.2,
        max_tokens: opts.maxOutputTokens ?? 512,
      }),
    });
    if (!resp.ok) {
      throw new Error(
        `Azure OpenAI chat failed: ${resp.status} ${await resp.text()}`,
      );
    }
    const json = (await resp.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { completion_tokens?: number };
    };
    const text = json.choices?.[0]?.message?.content ?? "";
    const approxOutputTokens =
      json.usage?.completion_tokens ?? Math.ceil(text.length / 4);
    return { text, approxOutputTokens, modelId: this.modelId };
  }

  async *generateStream(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk> {
    const resp = await fetch(this.url(), {
      method: "POST",
      headers: {
        "api-key": this.opts.apiKey,
        "Content-Type": "application/json",
        Accept: "text/event-stream",
      },
      body: JSON.stringify({
        messages: this.buildMessages(opts),
        temperature: opts.temperature ?? 0.2,
        max_tokens: opts.maxOutputTokens ?? 512,
        stream: true,
        // Ask Azure for usage in the final chunk (Chat Completions
        // supports this since api-version 2024-04-01-preview).
        stream_options: { include_usage: true },
      }),
    });
    if (!resp.ok || !resp.body) {
      throw new Error(
        `Azure OpenAI stream failed: ${resp.status} ${await resp.text()}`,
      );
    }
    let charCount = 0;
    let authoritativeTokens: number | undefined;
    for await (const event of parseSseStream(resp.body)) {
      if (event === "[DONE]") break;
      let json: {
        choices?: Array<{ delta?: { content?: string } }>;
        usage?: { completion_tokens?: number };
      };
      try {
        json = JSON.parse(event);
      } catch {
        continue;
      }
      const delta = json.choices?.[0]?.delta?.content;
      if (delta) {
        charCount += delta.length;
        yield { text: delta };
      }
      if (json.usage?.completion_tokens != null) {
        authoritativeTokens = json.usage.completion_tokens;
      }
    }
    yield {
      done: {
        approxOutputTokens: authoritativeTokens ?? Math.ceil(charCount / 4),
        modelId: this.modelId,
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Tiny SSE-frame parser. Reads a ReadableStream<Uint8Array>, splits on
// blank-line frame boundaries, and yields each frame's `data:` payload
// (joining multi-line `data:` per the SSE spec). Used by Vertex + Azure
// streams. No external dep — `eventsource-parser` would be 80 LoC of dep
// for something we already do in ~25 LoC.
// ---------------------------------------------------------------------------
async function* parseSseStream(
  body: ReadableStream<Uint8Array>,
): AsyncIterable<string> {
  const decoder = new TextDecoder();
  let buf = "";
  const reader = body.getReader();
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      let idx: number;
      // SSE separates frames by blank line; tolerate \n\n or \r\n\r\n.
      while ((idx = buf.search(/\r?\n\r?\n/)) !== -1) {
        const frame = buf.slice(0, idx);
        buf = buf.slice(idx + (buf[idx] === "\r" ? 4 : 2));
        const data = frame
          .split(/\r?\n/)
          .filter((l) => l.startsWith("data:"))
          .map((l) => l.slice(5).trimStart())
          .join("\n");
        if (data) yield data;
      }
    }
    // Flush a trailing frame that arrived without a terminating blank
    // line (some servers close the connection right after the last
    // `data:` line). Without this, Azure's `[DONE]` sentinel and the
    // final usage chunk would be dropped on certain HTTP/2 close paths.
    const tail = buf.trim();
    if (tail) {
      const data = tail
        .split(/\r?\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trimStart())
        .join("\n");
      if (data) yield data;
    }
  } finally {
    reader.releaseLock();
  }
}

// Re-export drainStream for tests that want to assert generate==stream parity.
export { drainStream as __drainStreamForTest };

// ---------------------------------------------------------------------------
// PHI guard wrapper. Outbound prompt text is scanned for PHI/secrets BEFORE
// it reaches any third-party model. Hit → throw before any network call OR
// any iterator delta is yielded.
// ---------------------------------------------------------------------------
export class PhiGuardLlmRuntime implements LlmAgentRuntime {
  constructor(private readonly inner: LlmAgentRuntime) {}

  private check(opts: LlmGenerateOpts): void {
    // System prompt is operator-controlled, but scanning it is cheap and
    // catches the mistake of pasting an example payload into a prompt.
    // History turns are scanned too — a multi-turn chat that previously
    // got a redacted finding back from a tool must not echo it onward to
    // a cloud model in turn N+1.
    const all = [
      ...scanForPhi(opts.systemPrompt),
      ...scanForPhi(opts.userPrompt),
      ...(opts.history ?? []).flatMap((h) => scanForPhi(h.text)),
    ];
    if (all.length > 0) {
      const detectors = [...new Set(all.map((h) => h.detector))].sort();
      throw new Error(
        `PHI guard: refused to send prompt to LLM. detectors=[${detectors.join(",")}]`,
      );
    }
  }

  async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
    this.check(opts);
    return this.inner.generate(opts);
  }

  async *generateStream(opts: LlmGenerateOpts): AsyncIterable<LlmStreamChunk> {
    // Synchronous check BEFORE we delegate: an async generator's body
    // doesn't run until the first `next()`, but throwing here throws on
    // the very first `for await` step which is what the caller sees.
    this.check(opts);
    if (this.inner.generateStream) {
      yield* this.inner.generateStream(opts);
      return;
    }
    // Inner runtime doesn't expose streaming — adapt blocking generate
    // to a single-chunk stream so chat-agent's code path stays uniform.
    const r = await this.inner.generate(opts);
    if (r.text) yield { text: r.text };
    yield {
      done: { approxOutputTokens: r.approxOutputTokens, modelId: r.modelId },
    };
  }
}
