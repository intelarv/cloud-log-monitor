import { describe, it, expect } from "vitest";
import {
  approxTokens,
  getChatMemoryConfigFromEnv,
  selectWindow,
  assembleRecallWindow,
  toHistoryTurns,
  buildChatSummaryPrompt,
  summarizeChatOverflow,
  type ChatMemoryConfig,
  type StoredChatMessage,
  type RecallCandidate,
} from "./chat-memory";
import type {
  LlmAgentRuntime,
  LlmGenerateOpts,
  LlmGenerateResult,
} from "./llm-runtime";

const cfg = (over: Partial<ChatMemoryConfig> = {}): ChatMemoryConfig => ({
  tokenBudget: 1500,
  maxTurns: 20,
  summaryEnabled: false,
  summaryMaxMessages: 40,
  semanticRecallEnabled: false,
  semanticRecallK: 8,
  semanticRecallRecencyTail: 2,
  ...over,
});

function msgs(...specs: Array<[StoredChatMessage["role"], string]>): StoredChatMessage[] {
  return specs.map(([role, content]) => ({ role, content }));
}

describe("approxTokens", () => {
  it("is chars/4 rounded up and monotonic", () => {
    expect(approxTokens("")).toBe(0);
    expect(approxTokens("abc")).toBe(1);
    expect(approxTokens("abcd")).toBe(1);
    expect(approxTokens("abcde")).toBe(2);
    expect(approxTokens("a".repeat(400))).toBe(100);
  });
});

describe("getChatMemoryConfigFromEnv", () => {
  it("defaults are safe: summary + semantic recall off, sensible budgets", () => {
    const c = getChatMemoryConfigFromEnv({});
    expect(c.summaryEnabled).toBe(false);
    expect(c.tokenBudget).toBe(1500);
    expect(c.maxTurns).toBe(20);
    expect(c.summaryMaxMessages).toBe(40);
    expect(c.summaryModel).toBeUndefined();
    expect(c.semanticRecallEnabled).toBe(false);
    expect(c.semanticRecallK).toBe(8);
    expect(c.semanticRecallRecencyTail).toBe(2);
  });

  it("parses overrides and the summary switch", () => {
    const c = getChatMemoryConfigFromEnv({
      CHAT_MEMORY_TOKEN_BUDGET: "500",
      CHAT_MEMORY_MAX_TURNS: "6",
      CHAT_MEMORY_SUMMARY: "true",
      CHAT_MEMORY_SUMMARY_MAX_MESSAGES: "10",
      CHAT_MEMORY_SUMMARY_MODEL: "some-model",
    });
    expect(c).toEqual({
      tokenBudget: 500,
      maxTurns: 6,
      summaryEnabled: true,
      summaryMaxMessages: 10,
      summaryModel: "some-model",
      semanticRecallEnabled: false,
      semanticRecallK: 8,
      semanticRecallRecencyTail: 2,
    });
  });

  it("parses semantic-recall overrides and switch", () => {
    const c = getChatMemoryConfigFromEnv({
      CHAT_MEMORY_SEMANTIC_RECALL: "true",
      CHAT_MEMORY_SEMANTIC_RECALL_K: "5",
      CHAT_MEMORY_SEMANTIC_RECALL_RECENCY_TAIL: "0",
    });
    expect(c.semanticRecallEnabled).toBe(true);
    expect(c.semanticRecallK).toBe(5);
    expect(c.semanticRecallRecencyTail).toBe(0);
  });

  it("treats only truthy tokens as enabling the summary", () => {
    for (const v of ["0", "false", "no", "off", ""]) {
      expect(getChatMemoryConfigFromEnv({ CHAT_MEMORY_SUMMARY: v }).summaryEnabled).toBe(false);
    }
    for (const v of ["1", "true", "YES", "On"]) {
      expect(getChatMemoryConfigFromEnv({ CHAT_MEMORY_SUMMARY: v }).summaryEnabled).toBe(true);
    }
  });

  it("treats only truthy tokens as enabling semantic recall", () => {
    for (const v of ["0", "false", "no", "off", ""]) {
      expect(getChatMemoryConfigFromEnv({ CHAT_MEMORY_SEMANTIC_RECALL: v }).semanticRecallEnabled).toBe(false);
    }
    for (const v of ["1", "true", "YES", "On"]) {
      expect(getChatMemoryConfigFromEnv({ CHAT_MEMORY_SEMANTIC_RECALL: v }).semanticRecallEnabled).toBe(true);
    }
  });

  it("rejects a non-positive numeric override", () => {
    expect(() => getChatMemoryConfigFromEnv({ CHAT_MEMORY_MAX_TURNS: "0" })).toThrow();
    expect(() => getChatMemoryConfigFromEnv({ CHAT_MEMORY_TOKEN_BUDGET: "-3" })).toThrow();
  });

  it("rejects a non-positive semantic-recall K but allows a zero recency tail", () => {
    expect(() => getChatMemoryConfigFromEnv({ CHAT_MEMORY_SEMANTIC_RECALL_K: "0" })).toThrow();
    expect(() => getChatMemoryConfigFromEnv({ CHAT_MEMORY_SEMANTIC_RECALL_RECENCY_TAIL: "-1" })).toThrow();
    expect(getChatMemoryConfigFromEnv({ CHAT_MEMORY_SEMANTIC_RECALL_RECENCY_TAIL: "0" }).semanticRecallRecencyTail).toBe(0);
  });
});

describe("selectWindow", () => {
  it("returns everything when it fits both budgets, preserving order", () => {
    const m = msgs(["user", "q1"], ["assistant", "a1"], ["user", "q2"]);
    const { window, overflow } = selectWindow(m, cfg());
    expect(overflow).toEqual([]);
    expect(window.map((x) => x.content)).toEqual(["q1", "a1", "q2"]);
  });

  it("drops oldest first under the token budget", () => {
    // each message ~ 25 tokens (100 chars). Budget 60 ⇒ only the newest 2 fit.
    const big = "x".repeat(100);
    const m = msgs(["user", big], ["assistant", big], ["user", big]);
    const { window, overflow } = selectWindow(m, cfg({ tokenBudget: 60 }));
    expect(window).toHaveLength(2);
    expect(overflow).toHaveLength(1);
    // Window stays chronological (overflow is the older head).
    expect(overflow[0]).toBe(m[0]);
    expect(window[0]).toBe(m[1]);
    expect(window[1]).toBe(m[2]);
  });

  it("respects the max-turns cap independent of tokens", () => {
    const m = msgs(
      ["user", "a"],
      ["assistant", "b"],
      ["user", "c"],
      ["assistant", "d"],
    );
    const { window, overflow } = selectWindow(m, cfg({ maxTurns: 2 }));
    expect(window.map((x) => x.content)).toEqual(["c", "d"]);
    expect(overflow.map((x) => x.content)).toEqual(["a", "b"]);
  });

  it("always keeps the most-recent message even if it alone exceeds budget", () => {
    const huge = "y".repeat(10000);
    const m = msgs(["user", "old"], ["assistant", huge]);
    const { window, overflow } = selectWindow(m, cfg({ tokenBudget: 10 }));
    expect(window).toHaveLength(1);
    expect(window[0]!.content).toBe(huge);
    expect(overflow.map((x) => x.content)).toEqual(["old"]);
  });

  it("handles an empty conversation", () => {
    expect(selectWindow([], cfg())).toEqual({ window: [], overflow: [] });
  });
});

describe("assembleRecallWindow", () => {
  const cand = (
    ...specs: Array<[string, StoredChatMessage["role"], string]>
  ): RecallCandidate[] => specs.map(([id, role, content]) => ({ id, role, content }));

  it("unions semantic hits with the recency tail, restored to chronological order", () => {
    const all = cand(
      ["m1", "user", "old relevant"],
      ["m2", "assistant", "noise"],
      ["m3", "user", "more noise"],
      ["m4", "assistant", "recent a"],
      ["m5", "user", "recent b"],
    );
    // Relevant: m1. Recency tail (2): m4, m5.
    const { window, overflow } = assembleRecallWindow(all, ["m1"], cfg({ semanticRecallRecencyTail: 2 }));
    expect(window.map((x) => x.content)).toEqual(["old relevant", "recent a", "recent b"]);
    expect(overflow.map((x) => x.content)).toEqual(["noise", "more noise"]);
  });

  it("dedupes when a semantic hit is also in the recency tail", () => {
    const all = cand(
      ["m1", "user", "a"],
      ["m2", "assistant", "b"],
      ["m3", "user", "c"],
    );
    // m3 is both a hit and in the tail; must appear once.
    const { window } = assembleRecallWindow(all, ["m3"], cfg({ semanticRecallRecencyTail: 1 }));
    expect(window.map((x) => x.content)).toEqual(["c"]);
  });

  it("with a zero recency tail keeps only semantic hits", () => {
    const all = cand(
      ["m1", "user", "hit"],
      ["m2", "assistant", "miss"],
      ["m3", "user", "newest"],
    );
    const { window } = assembleRecallWindow(all, ["m1"], cfg({ semanticRecallRecencyTail: 0 }));
    expect(window.map((x) => x.content)).toEqual(["hit"]);
  });

  it("ignores relevant ids that are not in the message list", () => {
    const all = cand(["m1", "user", "a"], ["m2", "assistant", "b"]);
    const { window } = assembleRecallWindow(all, ["does-not-exist"], cfg({ semanticRecallRecencyTail: 1 }));
    expect(window.map((x) => x.content)).toEqual(["b"]);
  });

  it("enforces the turn cap, preferring newest", () => {
    const all = cand(
      ["m1", "user", "a"],
      ["m2", "assistant", "b"],
      ["m3", "user", "c"],
      ["m4", "assistant", "d"],
    );
    // All four wanted (tail 4) but capped at 2 turns ⇒ newest two.
    const { window, overflow } = assembleRecallWindow(
      all,
      [],
      cfg({ maxTurns: 2, semanticRecallRecencyTail: 4 }),
    );
    expect(window.map((x) => x.content)).toEqual(["c", "d"]);
    expect(overflow.map((x) => x.content)).toEqual(["a", "b"]);
  });

  it("enforces the token budget, dropping older wanted messages first", () => {
    const big = "x".repeat(100); // ~25 tokens each
    const all = cand(
      ["m1", "user", big],
      ["m2", "assistant", big],
      ["m3", "user", big],
    );
    // tail 3 wants all, budget 60 ⇒ newest 2 fit.
    const { window } = assembleRecallWindow(
      all,
      [],
      cfg({ tokenBudget: 60, semanticRecallRecencyTail: 3 }),
    );
    expect(window).toHaveLength(2);
    expect(window.map((x) => x.content)).toEqual([big, big]);
  });

  it("handles an empty conversation", () => {
    expect(assembleRecallWindow([], [], cfg())).toEqual({ window: [], overflow: [] });
  });
});

describe("toHistoryTurns", () => {
  it("maps user→user and assistant→model in order", () => {
    const turns = toHistoryTurns(msgs(["user", "q"], ["assistant", "a"]));
    expect(turns).toEqual([
      { role: "user", text: "q" },
      { role: "model", text: "a" },
    ]);
  });

  it("prepends a summary context pair when a summary is present", () => {
    const turns = toHistoryTurns(msgs(["user", "q"]), "earlier we discussed F-1");
    expect(turns).toHaveLength(3);
    expect(turns[0]!.role).toBe("user");
    expect(turns[0]!.text).toContain("<CONVERSATION_SUMMARY>");
    expect(turns[0]!.text).toContain("earlier we discussed F-1");
    expect(turns[1]!.role).toBe("model");
    expect(turns[2]).toEqual({ role: "user", text: "q" });
  });

  it("ignores an empty/whitespace summary", () => {
    expect(toHistoryTurns(msgs(["user", "q"]), "   ")).toEqual([
      { role: "user", text: "q" },
    ]);
    expect(toHistoryTurns(msgs(["user", "q"]), null)).toEqual([
      { role: "user", text: "q" },
    ]);
  });
});

describe("buildChatSummaryPrompt", () => {
  it("forbids PHI in the system prompt and includes prior + new content", () => {
    const { systemPrompt, userPrompt } = buildChatSummaryPrompt(
      "prior summary text",
      msgs(["user", "list critical findings"], ["assistant", "see [F:F-9]"]),
    );
    expect(systemPrompt.toLowerCase()).toContain("never include personal data");
    expect(userPrompt).toContain("prior summary text");
    expect(userPrompt).toContain("ANALYST: list critical findings");
    expect(userPrompt).toContain("ASSISTANT: see [F:F-9]");
  });

  it("marks the earlier summary as none when absent", () => {
    const { userPrompt } = buildChatSummaryPrompt(null, msgs(["user", "hi"]));
    expect(userPrompt).toContain("EARLIER_SUMMARY: (none)");
  });
});

describe("summarizeChatOverflow", () => {
  it("calls the injected runtime and returns trimmed text + effective model", async () => {
    let seen: LlmGenerateOpts | undefined;
    const runtime: LlmAgentRuntime = {
      async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
        seen = opts;
        return { text: "  rolling summary  ", approxOutputTokens: 3, modelId: "effective-model" };
      },
    };
    const out = await summarizeChatOverflow({
      runtime,
      modelId: "hint-model",
      priorSummary: null,
      newMessages: msgs(["user", "q1"], ["assistant", "a1"]),
    });
    expect(out).toEqual({ text: "rolling summary", modelId: "effective-model" });
    expect(seen?.modelId).toBe("hint-model");
    expect(seen?.maxOutputTokens).toBeGreaterThan(0);
  });
});
