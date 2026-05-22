import { describe, expect, it } from "vitest";
import { AguiEventSchema, type AguiEvent } from "./sse";

// Contract test: every AG-UI event variant the server emits MUST parse cleanly
// through AguiEventSchema. SseStream.send() runs .parse() on the wire path,
// so any drift between a route's emitted shape and the schema would manifest
// as a runtime exception inside a streaming response. This suite locks the
// producer side: if a route adds a new event type or changes a field, either
// the schema is updated or this test fails first.
//
// The fixtures below are intentionally enumerated by hand rather than
// generated — they mirror every sse.send() call site in routes/chat.ts so
// review surfaces drift at the diff level too.

const ts = "2026-05-21T00:00:00.000Z";

const FIXTURES: AguiEvent[] = [
  // routes/chat.ts: session_started (both refusal path and normal path)
  { type: "session_started", session_id: "cs_abc", ts },

  // routes/chat.ts: user_message
  {
    type: "user_message",
    message_id: "cm_user_1",
    content: "List the critical findings",
    ts,
  },

  // routes/chat.ts: agent_thinking
  { type: "agent_thinking", ts },

  // routes/chat.ts: tool_call (from runChatTurn.onToolCall)
  {
    type: "tool_call",
    call_id: "tc_abc",
    tool: "get_finding",
    args: { id: "F-001" },
    ts,
  },

  // routes/chat.ts: tool_result (ok=true)
  {
    type: "tool_result",
    call_id: "tc_abc",
    ok: true,
    result: { id: "F-001", severity: "high" },
    ts,
  },

  // routes/chat.ts: tool_result (ok=false, with error)
  {
    type: "tool_result",
    call_id: "tc_abc",
    ok: false,
    error: "tool_not_allowed",
    ts,
  },

  // routes/chat.ts: agent_message_delta (post-scan final)
  {
    type: "agent_message_delta",
    message_id: "cm_agent_1",
    delta: "The critical findings are: [F:F-CANARY]",
    ts,
  },

  // routes/chat.ts: agent_message_complete (with citations)
  {
    type: "agent_message_complete",
    message_id: "cm_agent_1",
    citations: ["F-CANARY", "F-001"],
    ts,
  },

  // routes/chat.ts: agent_message_complete (no citations — refusal path)
  {
    type: "agent_message_complete",
    message_id: "cm_refusal_1",
    citations: [],
    ts,
  },

  // routes/chat.ts: ledger_appended (user_turn, agent_turn, input_phi_refused)
  {
    type: "ledger_appended",
    seq: 42,
    event_type: "chat.user_turn",
    hash: "deadbeef".padEnd(64, "0"),
    ts,
  },

  // routes/chat.ts: error (sanitized agent_error)
  { type: "error", error: "agent_error", ts },

  // routes/chat.ts: done
  { type: "done", ts },
];

describe("AguiEventSchema", () => {
  for (const fx of FIXTURES) {
    it(`accepts ${fx.type}`, () => {
      const parsed = AguiEventSchema.parse(fx);
      expect(parsed.type).toBe(fx.type);
      // Round-trip JSON to catch any non-serializable field shapes; the wire
      // path stringifies via JSON.stringify(parsed).
      const wire = JSON.parse(JSON.stringify(parsed));
      expect(AguiEventSchema.parse(wire)).toEqual(parsed);
    });
  }

  it("rejects an unknown event type", () => {
    expect(() =>
      AguiEventSchema.parse({ type: "unknown_event", ts } as unknown),
    ).toThrow();
  });

  it("rejects a known type with a missing required field", () => {
    expect(() =>
      AguiEventSchema.parse({ type: "ledger_appended", seq: 1, ts } as unknown),
    ).toThrow();
    expect(() =>
      AguiEventSchema.parse({
        type: "agent_message_delta",
        message_id: "x",
        ts,
      } as unknown),
    ).toThrow();
  });

  it("rejects a known type with a wrong field type", () => {
    expect(() =>
      AguiEventSchema.parse({
        type: "ledger_appended",
        seq: "not-a-number",
        event_type: "x",
        hash: "x",
        ts,
      } as unknown),
    ).toThrow();
    expect(() =>
      AguiEventSchema.parse({
        type: "agent_message_complete",
        message_id: "x",
        citations: "F-001",
        ts,
      } as unknown),
    ).toThrow();
  });

  it("rejects 'tool_result' missing ok flag", () => {
    expect(() =>
      AguiEventSchema.parse({
        type: "tool_result",
        call_id: "x",
        result: {},
        ts,
      } as unknown),
    ).toThrow();
  });
});
