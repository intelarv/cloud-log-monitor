// Chat-agent short-term / working memory + context-window management.
//
// The chat agent's long-term memory (associative recall over findings) already
// exists via pgvector hybrid search. What was missing is *working memory*: each
// chat turn used to be stateless — prior turns were persisted to chat_messages
// but never fed back to the model, and there was no token-budget management for
// the conversation itself (only an output-token cost cap). This module supplies
// the two missing techniques:
//
//   1. A token-budgeted SLIDING WINDOW over the persisted conversation. The
//      most-recent turns that fit within a token budget (and a turn count cap)
//      are replayed into the model's history; older turns "overflow".
//   2. OPT-IN ROLLING SUMMARY compaction of the overflow. When the operator
//      enables CHAT_MEMORY_SUMMARY, the overflow that falls out of the window
//      is folded into a single running per-session summary (an LLM call) so the
//      conversation's older context is preserved compactly instead of dropped.
//
// PHI posture (threat_model §Information Disclosure):
//   - The window is built from chat_messages content only. That content is
//     already safe: user input is PHI-scanned and refused BEFORE it is persisted
//     (routes/chat.ts input scan), and assistant output is PHI-scanned and
//     replaced with SAFE_REFUSAL BEFORE it is persisted. So replaying it cannot
//     introduce raw PHI that wasn't already gated.
//   - The summary is generated from that same already-safe text, and the caller
//     re-scans the summary output with scanForPhi before it is persisted or
//     used (defense-in-depth, mirroring memory-summarizer.ts).
//
// Default-safe: a fresh single-turn session has no prior messages, so the
// window is empty and behavior is byte-identical to the pre-memory loop. The
// LLM-calling summary is inert unless CHAT_MEMORY_SUMMARY is set. The
// credential-free offline eval gate never exercises persisted multi-turn chat,
// so it is unaffected.

import { type LlmAgentRuntime, type LlmHistoryTurn } from "./llm-runtime";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ChatMemoryConfig {
  /** Token budget for the replayed sliding window (excludes the current turn,
   *  the findings context, and the system prompt). */
  tokenBudget: number;
  /** Hard cap on how many prior messages may enter the window. */
  maxTurns: number;
  /** Opt-in: fold overflow into a rolling per-session summary (one LLM call). */
  summaryEnabled: boolean;
  /** Max overflow messages folded into the summary in a single turn (cost
   *  bound — remaining overflow is folded on subsequent turns). */
  summaryMaxMessages: number;
  /** Optional model id hint for the summary call; cloud runtimes may override. */
  summaryModel?: string;
  /** Opt-in: replay the most-RELEVANT prior turns (pgvector cosine over
   *  per-message embeddings) instead of only the most-recent ones. */
  semanticRecallEnabled: boolean;
  /** Opt-in upgrade to semantic recall: also run a lexical (BM25/FTS) leg over
   *  the conversation and fuse it with the vector leg via RRF. Only takes effect
   *  when `semanticRecallEnabled` is also on; off ⇒ vector-only (M19). */
  hybridRecallEnabled: boolean;
  /** How many semantically-closest prior messages to retrieve. */
  semanticRecallK: number;
  /** Always also include this many of the most-recent messages, regardless of
   *  similarity, so local conversational coherence is preserved. */
  semanticRecallRecencyTail: number;
}

function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
  label: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${label}=${raw} must be a positive number`);
  }
  return Math.floor(n);
}

function parseNonNegativeInt(
  raw: string | undefined,
  fallback: number,
  label: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) {
    throw new Error(`${label}=${raw} must be a non-negative number`);
  }
  return Math.floor(n);
}

function isTruthyFlag(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

export function getChatMemoryConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ChatMemoryConfig {
  return {
    tokenBudget: parsePositiveInt(
      env["CHAT_MEMORY_TOKEN_BUDGET"],
      1500,
      "CHAT_MEMORY_TOKEN_BUDGET",
    ),
    maxTurns: parsePositiveInt(
      env["CHAT_MEMORY_MAX_TURNS"],
      20,
      "CHAT_MEMORY_MAX_TURNS",
    ),
    summaryEnabled: isTruthyFlag(env["CHAT_MEMORY_SUMMARY"]),
    summaryMaxMessages: parsePositiveInt(
      env["CHAT_MEMORY_SUMMARY_MAX_MESSAGES"],
      40,
      "CHAT_MEMORY_SUMMARY_MAX_MESSAGES",
    ),
    summaryModel: env["CHAT_MEMORY_SUMMARY_MODEL"]?.trim() || undefined,
    semanticRecallEnabled: isTruthyFlag(env["CHAT_MEMORY_SEMANTIC_RECALL"]),
    hybridRecallEnabled: isTruthyFlag(env["CHAT_MEMORY_HYBRID_RECALL"]),
    semanticRecallK: parsePositiveInt(
      env["CHAT_MEMORY_SEMANTIC_RECALL_K"],
      8,
      "CHAT_MEMORY_SEMANTIC_RECALL_K",
    ),
    semanticRecallRecencyTail: parseNonNegativeInt(
      env["CHAT_MEMORY_SEMANTIC_RECALL_RECENCY_TAIL"],
      2,
      "CHAT_MEMORY_SEMANTIC_RECALL_RECENCY_TAIL",
    ),
  };
}

// ---------------------------------------------------------------------------
// Pure helpers (no DB / no LLM)
// ---------------------------------------------------------------------------

export interface StoredChatMessage {
  role: "user" | "assistant";
  content: string;
}

/** Cheap, deterministic token estimate (chars/4). Intentionally an estimate —
 *  the window is a soft budget, not a billing figure. */
export function approxTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Split a chronological (oldest-first) message list into the most-recent
 * `window` that fits the token + turn-count budget and the older `overflow`.
 * The most-recent message is always included even if it alone exceeds the
 * budget, so a single huge turn can never produce an empty window.
 */
export function selectWindow(
  messages: readonly StoredChatMessage[],
  cfg: ChatMemoryConfig,
): { window: StoredChatMessage[]; overflow: StoredChatMessage[] } {
  const picked: StoredChatMessage[] = [];
  let tokens = 0;
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i]!;
    if (picked.length >= cfg.maxTurns) break;
    const t = approxTokens(m.content);
    if (picked.length > 0 && tokens + t > cfg.tokenBudget) break;
    picked.push(m);
    tokens += t;
  }
  picked.reverse();
  const overflow = messages.slice(0, messages.length - picked.length);
  return { window: picked, overflow };
}

/** A stored message enriched with the identity needed for semantic recall:
 *  its id (for dedupe + similarity lookup) and a chronological sort key. */
export interface RecallCandidate extends StoredChatMessage {
  id: string;
}

/**
 * Assemble the replayed window for SEMANTIC recall mode. Given the full
 * chronological message list (with ids) and the ids of the messages a vector
 * search judged most relevant to the current query, return the window to
 * replay: the union of (a) the semantically-relevant messages and (b) the most
 * recent `recencyTail` messages (always kept for local conversational
 * coherence), deduped, restored to chronological order, and bounded by the same
 * token + turn budgets as the recency window.
 *
 * Newest messages are preferred when the budget is tight (we walk from the end),
 * so the current question's immediate context is never dropped in favor of an
 * older relevant turn. `overflow` is every message not selected, chronological.
 */
export function assembleRecallWindow(
  allMessages: readonly RecallCandidate[],
  relevantIds: Iterable<string>,
  cfg: ChatMemoryConfig,
): { window: StoredChatMessage[]; overflow: StoredChatMessage[] } {
  const relevant = new Set(relevantIds);
  const tail = Math.max(0, cfg.semanticRecallRecencyTail);
  const tailStart = Math.max(0, allMessages.length - tail);
  const wanted = new Set<string>();
  allMessages.forEach((m, i) => {
    if (relevant.has(m.id) || i >= tailStart) wanted.add(m.id);
  });

  // Walk newest→oldest applying the token + turn budgets, then restore order.
  const pickedIds = new Set<string>();
  let tokens = 0;
  for (let i = allMessages.length - 1; i >= 0; i--) {
    const m = allMessages[i]!;
    if (!wanted.has(m.id)) continue;
    if (pickedIds.size >= cfg.maxTurns) break;
    const t = approxTokens(m.content);
    if (pickedIds.size > 0 && tokens + t > cfg.tokenBudget) break;
    pickedIds.add(m.id);
    tokens += t;
  }

  const window: StoredChatMessage[] = [];
  const overflow: StoredChatMessage[] = [];
  for (const m of allMessages) {
    const target = pickedIds.has(m.id) ? window : overflow;
    target.push({ role: m.role, content: m.content });
  }
  return { window, overflow };
}

/**
 * Map a window into runtime history turns (user→user, assistant→model). When a
 * rolling `summary` is present it is prepended as a trusted context turn pair so
 * the model treats it as conversation background rather than a user question.
 */
export function toHistoryTurns(
  window: readonly StoredChatMessage[],
  summary?: string | null,
): LlmHistoryTurn[] {
  const turns: LlmHistoryTurn[] = [];
  if (summary && summary.trim() !== "") {
    turns.push({
      role: "user",
      text: `<CONVERSATION_SUMMARY>\n${summary.trim()}\n</CONVERSATION_SUMMARY>\n\nThe text above is a trusted summary of earlier turns in this same conversation. Use it as background context.`,
    });
    turns.push({
      role: "model",
      text: "Understood. I'll use that summary as context for the rest of this conversation.",
    });
  }
  for (const m of window) {
    turns.push({
      role: m.role === "assistant" ? "model" : "user",
      text: m.content,
    });
  }
  return turns;
}

// ---------------------------------------------------------------------------
// Summary prompt + runner (LLM; opt-in, dependency-injected)
// ---------------------------------------------------------------------------

export const MAX_CHAT_SUMMARY_OUTPUT_TOKENS = 256;

/** Build the rolling-summary prompt from the prior summary + the new overflow
 *  messages. Input is already-redacted chat text only. */
export function buildChatSummaryPrompt(
  priorSummary: string | null,
  newMessages: readonly StoredChatMessage[],
): { systemPrompt: string; userPrompt: string } {
  const systemPrompt = [
    "You maintain a running summary of a healthcare-compliance analyst's chat",
    "conversation with an audit assistant. Fold the EARLIER summary (if any) and",
    "the NEW messages into a single concise summary (at most ~150 words) that",
    "captures the analyst's goals, the questions asked, and key conclusions or",
    "finding ids ([F:<id>]) referenced. Use ONLY the provided text. Do not invent",
    "details, and never include personal data, secrets, or verbatim log content.",
    "Output plain prose only.",
  ].join(" ");

  const lines: string[] = [];
  lines.push(
    priorSummary && priorSummary.trim() !== ""
      ? `EARLIER_SUMMARY:\n${priorSummary.trim()}`
      : "EARLIER_SUMMARY: (none)",
  );
  lines.push("");
  lines.push("NEW_MESSAGES:");
  for (const m of newMessages) {
    const who = m.role === "assistant" ? "ASSISTANT" : "ANALYST";
    lines.push(`${who}: ${m.content.replace(/\s+/g, " ").trim()}`);
  }
  return { systemPrompt, userPrompt: lines.join("\n") };
}

/** Generate an updated rolling summary. The caller is responsible for the
 *  output PHI re-scan before persisting/using the returned text. */
export async function summarizeChatOverflow(args: {
  runtime: LlmAgentRuntime;
  modelId: string;
  priorSummary: string | null;
  newMessages: readonly StoredChatMessage[];
}): Promise<{ text: string; modelId: string }> {
  const { systemPrompt, userPrompt } = buildChatSummaryPrompt(
    args.priorSummary,
    args.newMessages,
  );
  const gen = await args.runtime.generate({
    systemPrompt,
    userPrompt,
    modelId: args.modelId,
    temperature: 0.2,
    maxOutputTokens: MAX_CHAT_SUMMARY_OUTPUT_TOKENS,
  });
  return { text: (gen.text ?? "").trim(), modelId: gen.modelId };
}
