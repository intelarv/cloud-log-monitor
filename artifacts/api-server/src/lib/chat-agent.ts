import { randomUUID } from "node:crypto";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
type Finding = FindingSafe;
import { and, eq, inArray, or, sql } from "drizzle-orm";
import { withTenant } from "./db-context";
import { toolRegistry } from "./tools";
import { hybridSearchFindings } from "./search";
import { appendLedger } from "./ledger";
import {
  CHAT_AGENT_MODEL,
  CHAT_AGENT_SYSTEM_PROMPT,
  CHAT_AGENT_VERSION,
  promptHash,
} from "./prompts";
import type { PolicyViolation } from "./policy";
import type { ToolName } from "./policy";
import {
  getLlmRuntime,
  streamFromRuntime,
  type LlmHistoryTurn,
} from "./llm-runtime";

// M1: the agent may chain up to two tool calls (typical pattern:
// search_findings → get_finding). Bounded loop is what enforces the cap.
const MAX_TOOL_CALLS = 2;

// Hybrid-search top-K seeded with the user question, plus a "context floor"
// of the most-severe open findings so questions like "list the critical
// findings" still surface even when their tokens don't overlap the query.
const HYBRID_TOP_K = 10;
const SEVERITY_FLOOR_LIMIT = 8;

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

function extractToolCall(
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

function extractCitations(text: string): string[] {
  const set = new Set<string>();
  const re = /\[F:([A-Za-z0-9_-]+)\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) set.add(m[1]!);
  return Array.from(set);
}

/** Drains an LlmAgentRuntime stream into a single buffered string plus the
 *  effective model id from the final `done` chunk. Optionally forwards
 *  `text` chunks to `onDelta` for SSE. */
async function callLlm(
  history: LlmHistoryTurn[],
  userPrompt: string,
  onDelta?: (delta: string) => void,
): Promise<{ text: string; modelId: string }> {
  let full = "";
  let modelId = CHAT_AGENT_MODEL;
  const runtime = getLlmRuntime();
  for await (const chunk of streamFromRuntime(runtime, {
    systemPrompt: CHAT_AGENT_SYSTEM_PROMPT,
    history,
    userPrompt,
    modelId: CHAT_AGENT_MODEL,
    temperature: 0.2,
    maxOutputTokens: 1024,
  })) {
    if (chunk.text) {
      full += chunk.text;
      onDelta?.(chunk.text);
    }
    if (chunk.done) modelId = chunk.done.modelId;
  }
  return { text: full, modelId };
}

export async function runChatTurn(
  opts: RunChatTurnOpts,
): Promise<ChatTurnResult> {
  // M1 — Step 1: build the candidate set the agent sees.
  //
  // Two retrievers compose the visible context:
  //
  //   (a) Hybrid BM25 + vector search over findings_redacted, seeded with
  //       the user's question. Returns the top-K most relevant candidates.
  //   (b) Severity floor: the top-N most-severe open findings, ordered by
  //       (critical→low, then last_seen_at desc). This guarantees questions
  //       like "list the critical findings" surface the right rows even
  //       when their textual overlap with the query is small.
  //
  // The two lists are union'd (de-duped by id) and capped. Both queries
  // run inside withTenant(...), so Postgres RLS isolates the tenant.
  const [hybrid, floor] = await Promise.all([
    hybridSearchFindings(opts.tenantId, opts.userQuestion, {
      topK: HYBRID_TOP_K,
    }),
    withTenant(opts.tenantId, async (tx) =>
      // M1.6: safe projection — severity-floor preloads feed the agent prompt.
      tx
        .select(findingSafeColumns)
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.tenantId, opts.tenantId),
            eq(findingsTable.status, "open"),
            or(
              eq(findingsTable.severity, "critical"),
              eq(findingsTable.severity, "high"),
            ),
          ),
        )
        // Severity is a text column; sort by an explicit ordinal so
        // `critical` always wins ties with `high` regardless of last_seen_at.
        // Lower number = more severe → ASC.
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
  const preloadedFindingIds = findings.map((f) => f.id);
  void inArray; // reserved for future agent-side filtering; suppress unused warning

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
  let toolBudget = MAX_TOOL_CALLS;
  let finalText = "";
  // Track the effective model id across turns so the ledger records what
  // actually serviced the FINAL response. Cloud runtimes may override the
  // prompt-pinned CHAT_AGENT_MODEL with operator-configured LLM_DEFAULT_MODEL.
  let effectiveModelId = CHAT_AGENT_MODEL;

  // Loop: call model -> if tool_call, execute -> feed back -> call model
  // again. Bounded by MAX_TOOL_CALLS.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    // We only stream deltas once we know this turn is NOT a tool call —
    // when the budget is spent OR when this is the final turn. To keep
    // things simple, the in-loop call buffers (no onDelta), then if it's
    // the final, we re-emit by passing onDelta below. Cleaner: stream
    // always, but buffer; if it parses as a tool call, drop the deltas
    // (the SSE consumer never saw a partial JSON envelope because we
    // gate the user-visible callback on the parse result after the
    // stream completes).
    //
    // Streaming choice here: ALWAYS stream from the runtime (so cloud
    // providers don't pay an extra blocking round-trip), but only
    // forward to `opts.onDelta` once we've confirmed this turn is not
    // a tool-call JSON envelope.
    const buffered = await callLlm(history, nextUserPrompt);
    effectiveModelId = buffered.modelId;
    const text = buffered.text;
    const call = extractToolCall(text);
    if (call && toolBudget > 0) {
      toolBudget -= 1;
      const callId = `tc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
      opts.onToolCall?.({ call_id: callId, name: call.name, args: call.args });
      const result = await toolRegistry.call(call.name, call.args, {
        tenantId: opts.tenantId,
        userId: opts.userId,
        agent: "chat",
        // M1.6: when the policy revalidation pass rejects an arg payload
        // (canary in args, PHI in args, oversize, bad id format), this hook
        // creates an incident finding + ledger entry. The chat-agent is the
        // right side-effect owner because it knows the session context the
        // tool call originated from. See policy.ts + ARCHITECTURE.md §23.1.
        onPolicyViolation: async (info) =>
          recordToolPolicyViolation({
            tenantId: opts.tenantId,
            userId: opts.userId,
            tool: info.tool,
            violations: info.violations,
            canaryTripped: info.canaryTripped,
          }),
      });
      toolCalls.push({
        name: call.name,
        args: call.args,
        ok: result.ok,
        error: result.ok ? undefined : result.error,
      });
      if (result.ok) {
        opts.onToolResult?.({ call_id: callId, ok: true, result: result.result });
      } else {
        opts.onToolResult?.({
          call_id: callId,
          ok: false,
          error: result.error,
        });
      }
      // Append the FULL prior turn into history before swapping in the
      // tool-result prompt. Order matters: the original user prompt
      // (carrying <AVAILABLE_FINDINGS> + <USER_QUESTION>) must remain
      // visible to the next model call, otherwise the post-tool turn
      // sees only the model's tool-call envelope and the tool result —
      // not the question that triggered them. Earlier draft only pushed
      // the model envelope and silently dropped the user context;
      // architect review caught it before merge.
      history.push({ role: "user", text: nextUserPrompt });
      history.push({ role: "model", text });
      nextUserPrompt = `<TOOL_RESULT name="${call.name}" ok="${result.ok}">
${JSON.stringify(result.ok ? result.result : { error: result.error })}
</TOOL_RESULT>

Now produce your final answer per the system instructions.`;
      continue;
    }
    // Not a tool call (or budget spent). If we have an onDelta callback
    // and the text isn't empty, replay it as a single delta so the SSE
    // consumer sees the full message. (The runtime already streamed it
    // to us internally; we just didn't forward chunks during buffering
    // because we didn't yet know whether this turn was a tool call.)
    if (opts.onDelta && text) opts.onDelta(text);
    finalText = text;
    break;
  }

  const citations = extractCitations(finalText);
  return {
    text: finalText,
    citations,
    tool_calls: toolCalls,
    preloaded_finding_ids: preloadedFindingIds,
    agent_identity: {
      agent: "chat",
      agent_version: CHAT_AGENT_VERSION,
      model_id: effectiveModelId,
      prompt_hash: promptHash(),
      tool_versions: toolRegistry
        .list()
        .map((t) => `${t.name}@${t.version}`),
    },
  };
}
