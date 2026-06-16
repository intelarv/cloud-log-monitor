import { describe, it, expect } from "vitest";
import {
  runAgentLoop,
  clampJson,
  extractToolCall,
  extractCitations,
  type CallTool,
  type RunChatTurnOpts,
} from "./chat-agent";
import type { FindingSafe } from "@workspace/db";
import type {
  LlmAgentRuntime,
  LlmGenerateOpts,
  LlmGenerateResult,
  LlmStreamChunk,
} from "./llm-runtime";

// ---------------------------------------------------------------------------
// Offline fakes — no DB, no network. The hardened loop is dependency-injected
// (`runtime`, `callTool`, `limits`) so every harness branch is deterministic.
// ---------------------------------------------------------------------------

function finding(id: string, severity = "high"): FindingSafe {
  return {
    id,
    tenantId: "t_test",
    classification: "phi",
    subclass: "name",
    severity,
    status: "open",
    source: "log:test",
    fingerprint: `fp:${id}`,
    redactedEvidence: { snippet: `evidence for ${id}`, trust: "untrusted" },
    detectorVersion: "test@0",
    firstSeenAt: new Date(),
    lastSeenAt: new Date(),
    occurrenceCount: 1,
  } as unknown as FindingSafe;
}

const FINDINGS = [finding("F-1"), finding("F-2"), finding("F-3")];

const baseOpts = (): RunChatTurnOpts => ({
  tenantId: "t_test",
  userId: "u_test",
  userQuestion: "what are the critical findings?",
});

/** Runtime that returns a scripted text per call index. Implements only
 *  `generate`; `streamFromRuntime` falls back to a single-chunk stream. */
function scriptedRuntime(
  responses: Array<string | (() => string)>,
  tokensPer = 4,
): LlmAgentRuntime {
  let i = 0;
  return {
    async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
      const r = responses[Math.min(i, responses.length - 1)]!;
      i += 1;
      const text = typeof r === "function" ? r() : r;
      return {
        text,
        approxOutputTokens: tokensPer,
        modelId: opts.modelId,
      };
    },
  };
}

const toolCallEnvelope = (name: string, args: Record<string, unknown>): string =>
  JSON.stringify({ tool_call: { name, args } });

const okTool: CallTool = async (name) => ({
  ok: true,
  result: { echoed: name },
  tool: { name, version: "1.0.0" },
});

describe("extractToolCall", () => {
  it("parses a whole-message tool_call envelope", () => {
    expect(extractToolCall(toolCallEnvelope("get_finding", { finding_id: "F-1" }))).toEqual({
      name: "get_finding",
      args: { finding_id: "F-1" },
    });
  });
  it("rejects prose, mixed content, and malformed JSON", () => {
    expect(extractToolCall("Here is the answer [F:F-1]")).toBeNull();
    expect(extractToolCall('Sure: {"tool_call":{"name":"x","args":{}}}')).toBeNull();
    expect(extractToolCall('{"tool_call": broken')).toBeNull();
    expect(extractToolCall('{"not_a_tool":1}')).toBeNull();
  });
});

describe("extractCitations", () => {
  it("collects unique [F:id] markers", () => {
    expect(extractCitations("see [F:F-1] and [F:F-2] and [F:F-1]")).toEqual([
      "F-1",
      "F-2",
    ]);
  });
});

describe("clampJson", () => {
  it("returns compact JSON under the limit", () => {
    expect(clampJson({ a: 1 }, 1024)).toBe('{"a":1}');
  });
  it("truncates oversize payloads with a marker", () => {
    const big = { blob: "x".repeat(5000) };
    const out = JSON.parse(clampJson(big, 256)) as { truncated: boolean };
    expect(out.truncated).toBe(true);
  });
});

describe("runAgentLoop", () => {
  it("returns a plain answer with citations when the model emits prose", async () => {
    const runtime = scriptedRuntime(["The critical finding is [F:F-1]."]);
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
    });
    expect(res.degraded).toBe(false);
    expect(res.text).toContain("[F:F-1]");
    expect(res.citations).toEqual(["F-1"]);
    expect(res.tool_calls).toHaveLength(0);
    expect(res.preloaded_finding_ids).toEqual(["F-1", "F-2", "F-3"]);
  });

  it("runs a tool then produces a final answer", async () => {
    const runtime = scriptedRuntime([
      toolCallEnvelope("get_finding", { finding_id: "F-1" }),
      "Based on the tool result, see [F:F-1].",
    ]);
    let calls = 0;
    const callTool: CallTool = async (name, args) => {
      calls += 1;
      return { ok: true, result: { name, args }, tool: { name, version: "1.0.0" } };
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, { runtime, callTool });
    expect(calls).toBe(1);
    expect(res.tool_calls).toHaveLength(1);
    expect(res.tool_calls[0]).toMatchObject({ name: "get_finding", ok: true });
    expect(res.text).toContain("[F:F-1]");
    expect(res.degraded).toBe(false);
  });

  it("feeds a tool error back to the model and still finalizes", async () => {
    const runtime = scriptedRuntime([
      toolCallEnvelope("get_finding", { finding_id: "F-404" }),
      "I could not load that finding, but here is [F:F-1].",
    ]);
    const callTool: CallTool = async () => ({
      ok: false,
      error: "not found",
      code: "exec_error",
    });
    const res = await runAgentLoop(baseOpts(), FINDINGS, { runtime, callTool });
    expect(res.tool_calls[0]).toMatchObject({ name: "get_finding", ok: false });
    expect(res.text).toContain("[F:F-1]");
    expect(res.degraded).toBe(false);
  });

  it("seeds the loop's history with priorHistory (working memory)", async () => {
    let seenHistory: ReadonlyArray<{ role: string; text: string }> = [];
    const runtime: LlmAgentRuntime = {
      async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
        seenHistory = opts.history ?? [];
        return { text: "Recalling earlier, see [F:F-1].", approxOutputTokens: 4, modelId: opts.modelId };
      },
    };
    const priorHistory = [
      { role: "user" as const, text: "what tenants are affected?" },
      { role: "model" as const, text: "Tenant t_test, see [F:F-1]." },
    ];
    const res = await runAgentLoop(
      { ...baseOpts(), priorHistory },
      FINDINGS,
      { runtime, callTool: okTool },
    );
    // The replayed turns precede this turn's question in the model's history.
    expect(seenHistory.slice(0, 2)).toEqual(priorHistory);
    expect(res.degraded).toBe(false);
  });

  it("treats malformed tool-call JSON as a final answer (no execution)", async () => {
    const runtime = scriptedRuntime(['{"tool_call": not-valid-json']);
    let calls = 0;
    const callTool: CallTool = async (name) => {
      calls += 1;
      return { ok: true, result: {}, tool: { name, version: "1" } };
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, { runtime, callTool });
    expect(calls).toBe(0);
    expect(res.text).toContain("not-valid-json");
    expect(res.degraded).toBe(false);
  });

  it("dedups identical repeated tool calls and never re-executes them", async () => {
    // Model stubbornly emits the SAME call forever.
    const runtime = scriptedRuntime([
      () => toolCallEnvelope("get_finding", { finding_id: "F-1" }),
    ]);
    let calls = 0;
    const callTool: CallTool = async (name, args) => {
      calls += 1;
      return { ok: true, result: { name, args }, tool: { name, version: "1" } };
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool,
      limits: { maxToolCalls: 2 },
    });
    expect(calls).toBe(1); // dedup prevented the second identical execution
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("tool_budget_exhausted");
    // The raw tool_call JSON envelope must NEVER reach the user.
    expect(extractToolCall(res.text)).toBeNull();
  });

  it("degrades (not raw JSON) when the model exhausts its tool budget", async () => {
    // Distinct args each call → no dedup; exercises pure budget exhaustion.
    let n = 0;
    const runtime = scriptedRuntime([
      () => toolCallEnvelope("get_finding", { finding_id: `F-${n++}` }),
    ]);
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { maxToolCalls: 2 },
    });
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("tool_budget_exhausted");
    expect(res.tool_calls).toHaveLength(2);
    expect(extractToolCall(res.text)).toBeNull();
    expect(res.text).toContain("[F:F-1]"); // deterministic fallback cites findings
  });

  it("trips the output-token cost cap and degrades", async () => {
    let n = 0;
    const runtime = scriptedRuntime(
      [() => toolCallEnvelope("get_finding", { finding_id: `F-${n++}` })],
      1000, // each call reports 1000 approx tokens
    );
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { maxToolCalls: 5, maxOutputTokensPerTurn: 10 },
    });
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("cost_cap");
    expect(res.approx_output_tokens).toBeGreaterThan(10);
  });

  it("trips the cost cap on an over-budget NON-tool final answer", async () => {
    // The very first response is a plain (non-tool) answer that already blew
    // the cap. It must degrade — not slip through as a verbatim final answer.
    const runtime = scriptedRuntime(["a very long final answer [F:F-1]"], 1000);
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { maxToolCalls: 5, maxOutputTokensPerTurn: 10 },
    });
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("cost_cap");
    expect(res.text).not.toContain("a very long final answer");
  });

  it("retries a transient LLM failure before succeeding", async () => {
    let attempts = 0;
    const runtime: LlmAgentRuntime = {
      async generate(opts) {
        attempts += 1;
        if (attempts === 1) throw new Error("transient 503");
        return { text: "recovered [F:F-1]", approxOutputTokens: 4, modelId: opts.modelId };
      },
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { maxLlmRetries: 1, llmRetryDelayMs: 0 },
    });
    expect(attempts).toBe(2);
    expect(res.degraded).toBe(false);
    expect(res.text).toContain("[F:F-1]");
  });

  it("degrades to a deterministic answer when the LLM keeps failing", async () => {
    const runtime: LlmAgentRuntime = {
      async generate() {
        throw new Error("provider down");
      },
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { maxLlmRetries: 1, llmRetryDelayMs: 0 },
    });
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("llm_unavailable");
    expect(res.citations).toContain("F-1");
  });

  it("times out a hung LLM stream and degrades", async () => {
    const runtime: LlmAgentRuntime = {
      async generate(opts) {
        return { text: "", approxOutputTokens: 0, modelId: opts.modelId };
      },
      async *generateStream(): AsyncIterable<LlmStreamChunk> {
        // Never yields — simulates a wedged provider stream.
        await new Promise<void>(() => {});
        yield { done: { approxOutputTokens: 0, modelId: "x" } };
      },
    };
    const res = await runAgentLoop(baseOpts(), FINDINGS, {
      runtime,
      callTool: okTool,
      limits: { llmCallTimeoutMs: 20, maxLlmRetries: 0 },
    });
    expect(res.degraded).toBe(true);
    expect(res.degrade_reason).toBe("llm_unavailable");
  });

  it("degrades gracefully with an empty-findings fallback", async () => {
    const runtime: LlmAgentRuntime = {
      async generate() {
        throw new Error("down");
      },
    };
    const res = await runAgentLoop(baseOpts(), [], {
      runtime,
      callTool: okTool,
      limits: { maxLlmRetries: 0 },
    });
    expect(res.degraded).toBe(true);
    expect(res.text).toMatch(/temporarily unavailable/i);
    expect(res.citations).toEqual([]);
  });
});
