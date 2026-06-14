import { randomUUID } from "node:crypto";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
type Finding = FindingSafe;
import { and, eq, or, sql } from "drizzle-orm";
import { withTenant } from "./db-context";
import { toolRegistry, type ToolCallResult } from "./tools";
import { hybridSearchFindings } from "./search";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import {
  CHAT_AGENT_MODEL,
  CHAT_AGENT_SYSTEM_PROMPT,
  CHAT_AGENT_VERSION,
  promptHash,
} from "./prompts";
import type { PolicyViolation } from "./policy";
import type { ToolName } from "./policy";
import {
  streamFromRuntime,
  type LlmAgentRuntime,
  type LlmHistoryTurn,
} from "./llm-runtime";
import { resolveLlmForDecisionPoint } from "./llm-decision-points";
import { withTimeout } from "./with-timeout";

// ---------------------------------------------------------------------------
// Harness limits
// ---------------------------------------------------------------------------
//
// Every knob below exists to satisfy a threat-model §DoS requirement: hard
// timeouts on LLM calls, a per-turn cost ceiling, and a bounded number of
// tool calls so a compromised/looping agent can never wedge a chat turn or
// run up unbounded cost. Defaults are dev-safe; operators override via env.
// The total wall-clock cost of a turn is bounded deterministically by
// (maxToolCalls + 1) LLM calls × llmCallTimeoutMs, so no separate turn-level
// deadline knob is needed.
export interface HarnessLimits {
  /** Max tool calls the agent may chain (search → get_finding is the typical
   *  2-step pattern). */
  maxToolCalls: number;
  /** Hard timeout on a single LLM call (consuming the whole stream). */
  llmCallTimeoutMs: number;
  /** Retries on an LLM call that fails/times out before degrading. */
  maxLlmRetries: number;
  /** Fixed delay between LLM retries. */
  llmRetryDelayMs: number;
  /** Per-turn cap on cumulative (approx) output tokens. A breach stops further
   *  tool rounds and degrades — the circuit breaker from threat model §DoS. */
  maxOutputTokensPerTurn: number;
  /** Max serialized bytes of a tool result fed back into the model prompt. */
  maxToolResultBytes: number;
}

function envInt(name: string, def: number): number {
  const v = process.env[name];
  if (v === undefined) return def;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : def;
}

export function defaultHarnessLimits(): HarnessLimits {
  return {
    // M1: the agent may chain up to two tool calls (typical pattern:
    // search_findings → get_finding). Bounded loop is what enforces the cap.
    maxToolCalls: envInt("AGENT_MAX_TOOL_CALLS", 2),
    llmCallTimeoutMs: envInt("LLM_CALL_TIMEOUT_MS", 30_000),
    maxLlmRetries: envInt("AGENT_MAX_LLM_RETRIES", 1),
    llmRetryDelayMs: envInt("AGENT_LLM_RETRY_DELAY_MS", 250),
    maxOutputTokensPerTurn: envInt("AGENT_MAX_OUTPUT_TOKENS_PER_TURN", 4096),
    maxToolResultBytes: envInt("AGENT_MAX_TOOL_RESULT_BYTES", 16 * 1024),
  };
}

// Hybrid-search top-K seeded with the user question, plus a "context floor"
// of the most-severe open findings so questions like "list the critical
// findings" still surface even when their tokens don't overlap the query.
const HYBRID_TOP_K = 10;
const SEVERITY_FLOOR_LIMIT = 8;

const sleep = (ms: number): Promise<void> =>
  ms > 0 ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve();

/** Why a turn fell back to a deterministic answer instead of an LLM one. */
export type DegradeReason =
  | "llm_unavailable"
  | "cost_cap"
  | "tool_budget_exhausted";

export interface ChatTurnResult {
  text: string;
  citations: string[];
  tool_calls: Array<{
    name: string;
    args: Record<string, unknown>;
    ok: boolean;
    error?: string;
  }>;
  // M1: ids of the findings pre-loaded into the agent's context (hybrid
  // search top-K ∪ severity floor). Audited via the chat.agent_turn ledger
  // entry so a reviewer can reconstruct exactly what the model was shown.
  preloaded_finding_ids: string[];
  /** True when the turn could not produce an LLM answer and fell back to a
   *  deterministic, redacted finding summary (threat model §DoS: "chat MUST
   *  degrade to deterministic search-only responses, not error pages"). */
  degraded: boolean;
  degrade_reason?: DegradeReason;
  /** Approximate cumulative output tokens across the turn's LLM calls. Used
   *  for cost accounting / the audit ledger; provider estimates vary. */
  approx_output_tokens: number;
  agent_identity: {
    agent: string;
    agent_version: string;
    /** Effective model id returned by the LlmAgentRuntime — may differ from
     *  the prompt-pinned CHAT_AGENT_MODEL when a cloud provider overrode
     *  with its operator-configured LLM_DEFAULT_MODEL. Per threat_model
     *  §Repudiation, the ledger records what was actually called. */
    model_id: string;
    prompt_hash: string;
    tool_versions: string[];
  };
}

export interface RunChatTurnOpts {
  tenantId: string;
  userId: string;
  userQuestion: string;
  // Streaming callback for incremental text deltas.
  onDelta?: (delta: string) => void;
  onToolCall?: (info: {
    call_id: string;
    name: string;
    args: Record<string, unknown>;
  }) => void;
  onToolResult?: (info: {
    call_id: string;
    ok: boolean;
    result?: unknown;
    error?: string;
  }) => void;
}

/** A tool executor bound to a tenant/user/agent context. Injected so the loop
 *  is unit-testable offline without the DB-backed tool registry. */
export type CallTool = (
  name: string,
  args: Record<string, unknown>,
) => Promise<ToolCallResult>;

export interface AgentLoopDeps {
  /** LLM runtime; defaults to the process-wide `getLlmRuntime()`. */
  runtime?: LlmAgentRuntime;
  /** Tool executor; defaults to the real registry bound to the opts context. */
  callTool?: CallTool;
  /** Harness limits; defaults to `defaultHarnessLimits()`. */
  limits?: Partial<HarnessLimits>;
}

// M1.6: side-effect emitter for tool-arg policy violations. Writes an incident
// finding into the same tenant (so the dashboard surfaces it immediately) and
// appends a ledger entry. Canary trips get a distinct event type +
// `critical` severity so a verifier can grep for them precisely. Threat model
// §EoP: "canary in any tool argument MUST trigger alert + ledgered incident".
async function recordToolPolicyViolation(args: {
  tenantId: string;
  userId: string;
  tool: ToolName;
  violations: PolicyViolation[];
  canaryTripped: boolean;
}): Promise<void> {
  const findingId = args.canaryTripped
    ? `F-CANARY-TRIP-${randomUUID().slice(0, 8)}`
    : `F-POLICY-VIOL-${randomUUID().slice(0, 8)}`;
  const severity = args.canaryTripped ? "critical" : "high";
  const subclass = args.canaryTripped
    ? "canary_in_tool_args"
    : args.violations[0]?.kind ?? "policy_violation";
  await withTenant(args.tenantId, async (tx) =>
    tx.insert(findingsTable).values({
      id: findingId,
      tenantId: args.tenantId,
      classification: "phi_in_output",
      subclass,
      severity,
      status: "open",
      source: `agent:chat:${args.userId}`,
      fingerprint: `tool_policy:${args.tool}:${subclass}`,
      redactedEvidence: {
        snippet: `<REDACTED: ${args.violations.length} tool-arg policy violation(s) on ${args.tool}>`,
        redactions: args.violations.map((v) => v.kind),
        truncated: true,
        trust: "untrusted",
      },
      detectorVersion: "tool-policy@m1.6",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      occurrenceCount: 1,
    }),
  );
  await appendLedger({
    tenantId: args.tenantId,
    actor: { kind: "human", id: args.userId },
    eventType: args.canaryTripped
      ? "agent.canary_in_tool_args"
      : "agent.tool_args_policy_violation",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      tool: args.tool,
      finding_id: findingId,
      // Per threat_model §Repudiation: ledger payload carries the kinds
      // (categorical) and messages (already redacted to detector names),
      // NEVER the raw arg values. The incident-finding subclass is enough
      // for an investigator to pivot.
      violations: args.violations.map((v) => ({
        kind: v.kind,
        message: v.message,
      })),
      canary_tripped: args.canaryTripped,
    },
  });
}

function buildContext(findings: Finding[]): string {
  // Source-tagged context. Trust is "untrusted" because all log content is
  // attacker-influenced. The agent prompt instructs the model to treat
  // anything inside <FINDING_EVIDENCE> as data.
  const lines = findings.map((f) => {
    const ev = f.redactedEvidence as { snippet?: string; trust?: string };
    const snippet = ev.snippet ?? "";
    const trust = ev.trust ?? "untrusted";
    return `<FINDING id="${f.id}" classification="${f.classification}" severity="${f.severity}" source="${f.source}" trust="${trust}">${snippet}</FINDING>`;
  });
  return lines.join("\n");
}

export function extractToolCall(
  text: string,
): { name: string; args: Record<string, unknown> } | null {
  const trimmed = text.trim();
  // Only treat the entire response as a tool call when the WHOLE message is
  // valid JSON of the expected shape. Mixed prose + JSON is rejected so the
  // model can't accidentally smuggle a call inside an answer.
  if (!trimmed.startsWith("{")) return null;
  try {
    const obj = JSON.parse(trimmed) as {
      tool_call?: { name?: string; args?: Record<string, unknown> };
    };
    if (
      obj.tool_call &&
      typeof obj.tool_call.name === "string" &&
      obj.tool_call.args &&
      typeof obj.tool_call.args === "object"
    ) {
      return { name: obj.tool_call.name, args: obj.tool_call.args };
    }
  } catch {
    return null;
  }
  return null;
}

// Exported for the M11 eval suite (citation-correctness): observation only,
// no behavior change. Parses inline `[F:<id>]` citation markers.
export function extractCitations(text: string): string[] {
  const set = new Set<string>();
  const re = /\[F:([A-Za-z0-9_-]+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) set.add(m[1]!);
  return Array.from(set);
}

/** Deterministic key for a tool call, used to detect an agent that repeats an
 *  identical call (wasting its bounded budget / looping). Key order is
 *  stabilized so `{a,b}` and `{b,a}` hash the same. */
function toolCallSignature(name: string, args: Record<string, unknown>): string {
  return `${name}:${stableStringify(args)}`;
}

function stableStringify(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(
      ([a], [b]) => (a < b ? -1 : a > b ? 1 : 0),
    );
    return `{${entries
      .map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

/** Serialize a tool result, clamping oversized payloads so a tool cannot blow
 *  up the next prompt (a cheap context-stuffing DoS vector). */
export function clampJson(value: unknown, maxBytes: number): string {
  const s = JSON.stringify(value) ?? "null";
  if (Buffer.byteLength(s, "utf8") <= maxBytes) return s;
  return JSON.stringify({
    truncated: true,
    note: `tool result exceeded ${maxBytes} bytes and was clamped`,
    preview: s.slice(0, Math.max(0, maxBytes)),
  });
}

/** Deterministic, PHI-safe fallback answer built from the already-retrieved
 *  (redacted) findings. Used when the LLM is unavailable, the cost cap trips,
 *  or the tool budget is exhausted. Cites findings as `[F:<id>]` so the normal
 *  citation extraction + output PHI scan still apply downstream. */
function deterministicAnswer(findings: Finding[]): string {
  if (findings.length === 0) {
    return "The assistant is temporarily unavailable and no relevant findings were retrieved for this question. Please try again shortly.";
  }
  const top = findings.slice(0, 5).map((f) => {
    const ev = f.redactedEvidence as { snippet?: string };
    const snippet = (ev.snippet ?? "").replace(/\s+/g, " ").slice(0, 160);
    return `- [F:${f.id}] ${f.severity}/${f.classification}: ${snippet}`;
  });
  return [
    "The AI assistant could not generate a response, so here are the most relevant findings retrieved deterministically (redacted):",
    ...top,
  ].join("\n");
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Drains an LlmAgentRuntime stream into a single buffered string plus the
 *  effective model id + approx token count from the final `done` chunk. The
 *  whole stream is bounded by `timeoutMs` (threat model §DoS). */
async function callLlm(
  runtime: LlmAgentRuntime,
  history: LlmHistoryTurn[],
  userPrompt: string,
  timeoutMs: number,
  modelIdHint: string,
): Promise<{ text: string; modelId: string; approxOutputTokens: number }> {
  const iterator = streamFromRuntime(runtime, {
    systemPrompt: CHAT_AGENT_SYSTEM_PROMPT,
    history,
    userPrompt,
    modelId: modelIdHint,
    temperature: 0.2,
    maxOutputTokens: 1024,
  })[Symbol.asyncIterator]();

  let full = "";
  let modelId = modelIdHint;
  let approxOutputTokens = 0;
  const deadline = Date.now() + timeoutMs;
  try {
    for (;;) {
      const remaining = timeoutMs > 0 ? deadline - Date.now() : 0;
      const next = await withTimeout(
        iterator.next(),
        timeoutMs > 0 ? Math.max(1, remaining) : 0,
        "llm_call",
      );
      if (next.done) break;
      const chunk = next.value;
      if (chunk.text) full += chunk.text;
      if (chunk.done) {
        modelId = chunk.done.modelId;
        approxOutputTokens = chunk.done.approxOutputTokens;
      }
    }
  } finally {
    // Best-effort: signal the provider iterator we're done (don't await — a
    // hung iterator's return() may itself never settle).
    void iterator.return?.(undefined);
  }
  return { text: full, modelId, approxOutputTokens };
}

/** `callLlm` plus bounded retry. Throws if all attempts fail; the caller
 *  degrades to a deterministic answer. */
async function callLlmWithRetry(
  runtime: LlmAgentRuntime,
  history: LlmHistoryTurn[],
  userPrompt: string,
  limits: HarnessLimits,
  modelIdHint: string,
): Promise<{ text: string; modelId: string; approxOutputTokens: number }> {
  let attempt = 0;
  for (;;) {
    try {
      return await callLlm(
        runtime,
        history,
        userPrompt,
        limits.llmCallTimeoutMs,
        modelIdHint,
      );
    } catch (err) {
      attempt += 1;
      if (attempt > limits.maxLlmRetries) throw err;
      logger.warn(
        { err: errMsg(err), attempt, maxRetries: limits.maxLlmRetries },
        "chat agent LLM call failed; retrying",
      );
      await sleep(limits.llmRetryDelayMs);
    }
  }
}

/**
 * Hardened agent loop. Pure of retrieval — the caller supplies the already
 * tenant-scoped, redacted `findings`. Dependency-injected (`runtime`,
 * `callTool`, `limits`) so the harness behavior is unit-testable offline.
 *
 * Guarantees:
 *   - At most `limits.maxToolCalls` tool executions per turn.
 *   - Every LLM call is timeout-bounded (with bounded retry).
 *   - Cumulative output tokens are capped (cost circuit breaker).
 *   - Identical repeated tool calls are deduped (loop guard).
 *   - The raw `{"tool_call":...}` envelope is NEVER surfaced to the user; if
 *     the model wants another tool with no budget left, the turn degrades.
 *   - Any LLM failure degrades to a deterministic, redacted finding summary
 *     instead of erroring out.
 */
export async function runAgentLoop(
  opts: RunChatTurnOpts,
  findings: Finding[],
  deps: AgentLoopDeps = {},
): Promise<ChatTurnResult> {
  // Injected runtime (tests) wins and keeps the prompt-pinned model. With no
  // injection, resolve the chat point's own provider/model (M17).
  const { runtime, modelId: chatModelId } = deps.runtime
    ? { runtime: deps.runtime, modelId: CHAT_AGENT_MODEL }
    : resolveLlmForDecisionPoint("chat", CHAT_AGENT_MODEL);
  const limits = { ...defaultHarnessLimits(), ...deps.limits };
  const callTool: CallTool =
    deps.callTool ??
    ((name, args) =>
      toolRegistry.call(name, args, {
        tenantId: opts.tenantId,
        userId: opts.userId,
        agent: "chat",
        // M1.6: when the policy revalidation pass rejects an arg payload
        // (canary in args, PHI in args, oversize, bad id format), this hook
        // creates an incident finding + ledger entry. See policy.ts +
        // ARCHITECTURE.md §23.1.
        onPolicyViolation: async (info) =>
          recordToolPolicyViolation({
            tenantId: opts.tenantId,
            userId: opts.userId,
            tool: info.tool,
            violations: info.violations,
            canaryTripped: info.canaryTripped,
          }),
      }));

  const preloadedFindingIds = findings.map((f) => f.id);

  const initialPrompt = `<AVAILABLE_FINDINGS>
${buildContext(findings)}
</AVAILABLE_FINDINGS>

<USER_QUESTION>
${opts.userQuestion}
</USER_QUESTION>

Respond per the system instructions.`;

  // Multi-turn conversation: `history` accumulates prior turns (model
  // responses + tool-result user messages); `nextUserPrompt` is the last
  // user message that the runtime should respond to.
  const history: LlmHistoryTurn[] = [];
  let nextUserPrompt = initialPrompt;

  const toolCalls: ChatTurnResult["tool_calls"] = [];
  const executedSignatures = new Set<string>();
  let toolBudget = limits.maxToolCalls;
  let approxOutputTokens = 0;
  let finalText = "";
  let degraded = false;
  let degradeReason: DegradeReason | undefined;
  // Track the effective model id across turns so the ledger records what
  // actually serviced the FINAL response.
  let effectiveModelId = chatModelId;

  for (;;) {
    let buffered: { text: string; modelId: string; approxOutputTokens: number };
    try {
      buffered = await callLlmWithRetry(
        runtime,
        history,
        nextUserPrompt,
        limits,
        chatModelId,
      );
    } catch (err) {
      logger.warn(
        { err: errMsg(err), tenantId: opts.tenantId },
        "chat agent degrading to deterministic answer (LLM unavailable)",
      );
      degraded = true;
      degradeReason = "llm_unavailable";
      finalText = deterministicAnswer(findings);
      break;
    }
    effectiveModelId = buffered.modelId;
    approxOutputTokens += buffered.approxOutputTokens;
    const text = buffered.text;
    const call = extractToolCall(text);

    // Per-turn output-token circuit breaker (threat model §DoS). Check it for
    // EVERY response shape — a non-tool final answer that already blew the cap
    // must degrade too, not just a response that wants another tool round.
    if (approxOutputTokens > limits.maxOutputTokensPerTurn) {
      logger.warn(
        {
          tenantId: opts.tenantId,
          approxOutputTokens,
          cap: limits.maxOutputTokensPerTurn,
        },
        "chat agent output-token cost cap tripped; degrading",
      );
      degraded = true;
      degradeReason = "cost_cap";
      finalText = deterministicAnswer(findings);
      break;
    }

    if (call) {
      if (toolBudget <= 0) {
        // The model wants another tool but has no budget. NEVER surface the
        // raw tool_call JSON envelope to the user — degrade instead.
        logger.warn(
          { tenantId: opts.tenantId, tool: call.name },
          "chat agent tool budget exhausted; degrading",
        );
        degraded = true;
        degradeReason = "tool_budget_exhausted";
        finalText = deterministicAnswer(findings);
        break;
      }

      const signature = toolCallSignature(call.name, call.args);
      if (executedSignatures.has(signature)) {
        // Identical repeat — don't re-run it; spend a unit of budget (so the
        // loop is guaranteed to terminate) and nudge the model to finalize.
        toolBudget -= 1;
        history.push({ role: "user", text: nextUserPrompt });
        history.push({ role: "model", text });
        nextUserPrompt = `You already called ${call.name} with identical arguments; the result is unchanged. Do not repeat tool calls. Produce your final answer now.`;
        continue;
      }

      toolBudget -= 1;
      executedSignatures.add(signature);
      const callId = `tc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
      opts.onToolCall?.({ call_id: callId, name: call.name, args: call.args });
      const result = await callTool(call.name, call.args);
      toolCalls.push({
        name: call.name,
        args: call.args,
        ok: result.ok,
        error: result.ok ? undefined : result.error,
      });
      if (result.ok) {
        opts.onToolResult?.({ call_id: callId, ok: true, result: result.result });
      } else {
        opts.onToolResult?.({ call_id: callId, ok: false, error: result.error });
      }
      // Append the FULL prior turn into history before swapping in the
      // tool-result prompt. Order matters: the original user prompt (carrying
      // <AVAILABLE_FINDINGS> + <USER_QUESTION>) must remain visible to the
      // next model call, otherwise the post-tool turn sees only the model's
      // tool-call envelope and the tool result — not the question that
      // triggered them.
      history.push({ role: "user", text: nextUserPrompt });
      history.push({ role: "model", text });
      const resultBody = clampJson(
        result.ok ? result.result : { error: result.error },
        limits.maxToolResultBytes,
      );
      nextUserPrompt = `<TOOL_RESULT name="${call.name}" ok="${result.ok}">
${resultBody}
</TOOL_RESULT>

Now produce your final answer per the system instructions.`;
      continue;
    }

    // Not a tool call — this is the final answer.
    finalText = text;
    break;
  }

  // If we have an onDelta callback, replay the final (post-loop) text as a
  // single delta. The runtime already streamed internally; we forward only
  // after we know this is the final, non-tool-call text.
  if (opts.onDelta && finalText) opts.onDelta(finalText);

  const citations = extractCitations(finalText);
  return {
    text: finalText,
    citations,
    tool_calls: toolCalls,
    preloaded_finding_ids: preloadedFindingIds,
    degraded,
    ...(degradeReason ? { degrade_reason: degradeReason } : {}),
    approx_output_tokens: approxOutputTokens,
    agent_identity: {
      agent: "chat",
      agent_version: CHAT_AGENT_VERSION,
      model_id: effectiveModelId,
      prompt_hash: promptHash(),
      tool_versions: toolRegistry.list().map((t) => `${t.name}@${t.version}`),
    },
  };
}

/** Retrieve the tenant-scoped, redacted candidate set the agent sees:
 *  hybrid (BM25 + vector) top-K ∪ a severity floor of the most-severe open
 *  findings. Both legs run inside `withTenant`, so RLS isolates the tenant. */
async function retrieveCandidates(
  tenantId: string,
  userQuestion: string,
): Promise<Finding[]> {
  const [hybrid, floor] = await Promise.all([
    hybridSearchFindings(tenantId, userQuestion, { topK: HYBRID_TOP_K }),
    withTenant(tenantId, async (tx) =>
      // M1.6: safe projection — severity-floor preloads feed the agent prompt.
      tx
        .select(findingSafeColumns)
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.tenantId, tenantId),
            eq(findingsTable.status, "open"),
            or(
              eq(findingsTable.severity, "critical"),
              eq(findingsTable.severity, "high"),
            ),
          ),
        )
        // Severity is a text column; sort by an explicit ordinal so
        // `critical` always wins ties with `high` regardless of last_seen_at.
        .orderBy(
          sql`CASE ${findingsTable.severity}
                WHEN 'critical' THEN 0
                WHEN 'high' THEN 1
                ELSE 2
              END`,
          sql`${findingsTable.lastSeenAt} DESC`,
        )
        .limit(SEVERITY_FLOOR_LIMIT),
    ),
  ]);

  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const f of hybrid.findings) {
    if (!seen.has(f.id)) {
      seen.add(f.id);
      findings.push(f);
    }
  }
  for (const f of floor) {
    if (!seen.has(f.id)) {
      seen.add(f.id);
      findings.push(f);
    }
  }
  return findings;
}

export async function runChatTurn(
  opts: RunChatTurnOpts,
  deps: AgentLoopDeps = {},
): Promise<ChatTurnResult> {
  // Step 1: build the candidate set the agent sees (DB-backed retrieval).
  const findings = await retrieveCandidates(opts.tenantId, opts.userQuestion);
  // Step 2: run the hardened, bounded agent loop over that context.
  return runAgentLoop(opts, findings, deps);
}
