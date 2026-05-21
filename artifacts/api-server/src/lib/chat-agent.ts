import { ai } from "@workspace/integrations-gemini-ai";
import { findingsTable, type Finding } from "@workspace/db";
import { eq, and } from "drizzle-orm";
import { withTenant } from "./db-context";
import { toolRegistry } from "./tools";
import {
  CHAT_AGENT_MODEL,
  CHAT_AGENT_SYSTEM_PROMPT,
  CHAT_AGENT_VERSION,
  promptHash,
} from "./prompts";

const MAX_TOOL_CALLS = 1;

export interface ChatTurnResult {
  text: string;
  citations: string[];
  tool_calls: Array<{
    name: string;
    args: Record<string, unknown>;
    ok: boolean;
    error?: string;
  }>;
  agent_identity: {
    agent: string;
    agent_version: string;
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

async function callGemini(
  contents: Array<{ role: "user" | "model"; parts: Array<{ text: string }> }>,
  onDelta?: (delta: string) => void,
): Promise<string> {
  const stream = await ai.models.generateContentStream({
    model: CHAT_AGENT_MODEL,
    contents,
    config: {
      systemInstruction: CHAT_AGENT_SYSTEM_PROMPT,
      maxOutputTokens: 1024,
      temperature: 0.2,
    },
  });
  let full = "";
  for await (const chunk of stream) {
    const t = chunk.text;
    if (t) {
      full += t;
      onDelta?.(t);
    }
  }
  return full;
}

export async function runChatTurn(
  opts: RunChatTurnOpts,
): Promise<ChatTurnResult> {
  // Step 1: load the redacted findings the agent is allowed to see.
  const findings = await withTenant(opts.tenantId, async (tx) =>
    tx
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, opts.tenantId),
          eq(findingsTable.status, "open"),
        ),
      )
      .limit(50),
  );

  const initialPrompt = `<AVAILABLE_FINDINGS>
${buildContext(findings)}
</AVAILABLE_FINDINGS>

<USER_QUESTION>
${opts.userQuestion}
</USER_QUESTION>

Respond per the system instructions.`;

  const contents: Array<{
    role: "user" | "model";
    parts: Array<{ text: string }>;
  }> = [{ role: "user", parts: [{ text: initialPrompt }] }];

  const toolCalls: ChatTurnResult["tool_calls"] = [];
  let toolBudget = MAX_TOOL_CALLS;
  let finalText = "";

  // Loop: call model -> if tool_call, execute -> feed back -> call model
  // again. Bounded by MAX_TOOL_CALLS.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    // Important: we only stream deltas once we know this turn is NOT a tool
    // call. To keep things simple, we buffer the first response, decide,
    // and stream the second (final) response.
    const text = await callGemini(
      contents,
      toolBudget === 0 ? opts.onDelta : undefined,
    );
    const call = extractToolCall(text);
    if (call && toolBudget > 0) {
      toolBudget -= 1;
      const callId = `tc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
      opts.onToolCall?.({ call_id: callId, name: call.name, args: call.args });
      const result = await toolRegistry.call(call.name, call.args, {
        tenantId: opts.tenantId,
        userId: opts.userId,
        agent: "chat",
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
      // Feed result back to the model.
      contents.push({ role: "model", parts: [{ text }] });
      contents.push({
        role: "user",
        parts: [
          {
            text: `<TOOL_RESULT name="${call.name}" ok="${result.ok}">
${JSON.stringify(result.ok ? result.result : { error: result.error })}
</TOOL_RESULT>

Now produce your final answer per the system instructions.`,
          },
        ],
      });
      continue;
    }
    finalText = text;
    // If the model emitted a tool_call but the budget is spent, surface as
    // plain text — don't execute. Cap loop here.
    break;
  }

  const citations = extractCitations(finalText);
  return {
    text: finalText,
    citations,
    tool_calls: toolCalls,
    agent_identity: {
      agent: "chat",
      agent_version: CHAT_AGENT_VERSION,
      model_id: CHAT_AGENT_MODEL,
      prompt_hash: promptHash(),
      tool_versions: toolRegistry
        .list()
        .map((t) => `${t.name}@${t.version}`),
    },
  };
}
