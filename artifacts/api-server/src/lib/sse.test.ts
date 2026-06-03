import { describe, expect, it } from "vitest";
import type { Response } from "express";
import { EventType } from "@ag-ui/core";
import { SseStream } from "./sse";

// Producer contract test: SseStream is the single wire path for the chat route,
// and it now speaks the official AG-UI event vocabulary (@ag-ui/core) encoded
// via the official SSE encoder (@ag-ui/encoder). This suite locks the producer
// side — it drives every semantic helper the chat route calls and asserts the
// emitted events carry the right AG-UI `type` and fields. If a helper drifts,
// this fails before a malformed event ever reaches a streaming response.

interface CapturedEvent {
  type: string;
  [k: string]: unknown;
}

function fakeRes(): { res: Response; writes: string[]; headers: Record<string, string> } {
  const writes: string[] = [];
  const headers: Record<string, string> = {};
  const res = {
    setHeader(name: string, value: string) {
      headers[name] = value;
    },
    flushHeaders() {},
    on() {},
    write(chunk: string) {
      writes.push(chunk);
      return true;
    },
    end() {},
  } as unknown as Response;
  return { res, writes, headers };
}

// @ag-ui/encoder emits `data: <json>\n\n`; heartbeats are `: ...` comment lines.
function parseEvents(writes: string[]): CapturedEvent[] {
  const events: CapturedEvent[] = [];
  for (const w of writes) {
    for (const frame of w.split("\n\n")) {
      const dataLine = frame.split("\n").find((l) => l.startsWith("data: "));
      if (!dataLine) continue;
      events.push(JSON.parse(dataLine.slice(6)) as CapturedEvent);
    }
  }
  return events;
}

describe("SseStream (AG-UI producer contract)", () => {
  it("sets the AG-UI SSE content type", () => {
    const { res, headers } = fakeRes();
    new SseStream(res);
    expect(headers["Content-Type"]).toBe("text/event-stream");
  });

  it("emits RUN_STARTED with threadId + runId", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.runStarted("cs_abc", "run_1");
    const [ev] = parseEvents(writes);
    expect(ev).toMatchObject({
      type: EventType.RUN_STARTED,
      threadId: "cs_abc",
      runId: "run_1",
    });
  });

  it("emits RUN_FINISHED with optional result", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.runFinished("cs_abc", "run_1", { degraded: true, approx_output_tokens: 12 });
    const [ev] = parseEvents(writes);
    expect(ev).toMatchObject({
      type: EventType.RUN_FINISHED,
      threadId: "cs_abc",
      runId: "run_1",
      result: { degraded: true, approx_output_tokens: 12 },
    });
  });

  it("emits RUN_ERROR with a sanitized message", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.runError("agent_error");
    const [ev] = parseEvents(writes);
    expect(ev).toMatchObject({ type: EventType.RUN_ERROR, message: "agent_error" });
  });

  it("emits STEP_STARTED for the thinking step", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.stepStarted("agent_thinking");
    const [ev] = parseEvents(writes);
    expect(ev).toMatchObject({
      type: EventType.STEP_STARTED,
      stepName: "agent_thinking",
    });
  });

  it("emits an assistant message as START → CONTENT → END + citations CUSTOM", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.assistantMessage("cm_1", "The critical findings are: [F:F-CANARY]", [
      "F-CANARY",
    ]);
    const evs = parseEvents(writes);
    expect(evs.map((e) => e.type)).toEqual([
      EventType.TEXT_MESSAGE_START,
      EventType.TEXT_MESSAGE_CONTENT,
      EventType.TEXT_MESSAGE_END,
      EventType.CUSTOM,
    ]);
    expect(evs[0]).toMatchObject({ messageId: "cm_1", role: "assistant" });
    expect(evs[1]).toMatchObject({
      messageId: "cm_1",
      delta: "The critical findings are: [F:F-CANARY]",
    });
    expect(evs[2]).toMatchObject({ messageId: "cm_1" });
    expect(evs[3]).toMatchObject({
      name: "citations",
      value: { message_id: "cm_1", citations: ["F-CANARY"] },
    });
  });

  it("emits a tool call as START → ARGS(json) → END", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.toolCall("tc_abc", "get_finding", { id: "F-001" });
    const evs = parseEvents(writes);
    expect(evs.map((e) => e.type)).toEqual([
      EventType.TOOL_CALL_START,
      EventType.TOOL_CALL_ARGS,
      EventType.TOOL_CALL_END,
    ]);
    expect(evs[0]).toMatchObject({ toolCallId: "tc_abc", toolCallName: "get_finding" });
    expect(JSON.parse(evs[1]!.delta as string)).toEqual({ id: "F-001" });
    expect(evs[2]).toMatchObject({ toolCallId: "tc_abc" });
  });

  it("emits a tool result as TOOL_CALL_RESULT with json content (ok=true)", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.toolResult("tm_1", "tc_abc", { ok: true, result: { id: "F-001", severity: "high" } });
    const [ev] = parseEvents(writes);
    expect(ev).toMatchObject({
      type: EventType.TOOL_CALL_RESULT,
      messageId: "tm_1",
      toolCallId: "tc_abc",
      role: "tool",
    });
    expect(JSON.parse(ev!.content as string)).toEqual({
      ok: true,
      result: { id: "F-001", severity: "high" },
    });
  });

  it("emits a tool result with an error (ok=false)", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.toolResult("tm_2", "tc_abc", { ok: false, error: "tool_not_allowed" });
    const [ev] = parseEvents(writes);
    expect(JSON.parse(ev!.content as string)).toEqual({
      ok: false,
      error: "tool_not_allowed",
    });
  });

  it("emits user_message + ledger_appended over CUSTOM", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.userMessage("cm_user_1", "List the critical findings");
    sse.ledgerAppended({ seq: 42, eventType: "chat.user_turn", hash: "deadbeef".padEnd(64, "0") });
    const evs = parseEvents(writes);
    expect(evs[0]).toMatchObject({
      type: EventType.CUSTOM,
      name: "user_message",
      value: { message_id: "cm_user_1", content: "List the critical findings" },
    });
    expect(evs[1]).toMatchObject({
      type: EventType.CUSTOM,
      name: "ledger_appended",
      value: { seq: 42, event_type: "chat.user_turn" },
    });
  });

  it("drops events after close()", () => {
    const { res, writes } = fakeRes();
    const sse = new SseStream(res);
    sse.close();
    sse.runStarted("cs_abc", "run_1");
    expect(parseEvents(writes)).toHaveLength(0);
    expect(sse.isClosed()).toBe(true);
  });
});
