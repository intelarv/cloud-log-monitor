import type { Response } from "express";
import { EventType, type BaseEvent } from "@ag-ui/core";
import { EventEncoder } from "@ag-ui/encoder";

// AG-UI transport. The server speaks the official AG-UI event vocabulary
// (@ag-ui/core) and serializes every event through the official SSE encoder
// (@ag-ui/encoder → `data: <json>\n\n`). The dashboard consumes the same
// vocabulary via @ag-ui/core's `EventType`.
//
// Domain-specific signals that AG-UI has no first-class event for
// (ledger_appended, the persisted user-message id, post-scan citation lists)
// ride on AG-UI `CUSTOM` events with a stable `name`, which is the AG-UI
// sanctioned extension point.
//
// PHI-safety seam: every write goes through the single `send()` method, and
// the route layer is responsible for only ever handing this class
// already-redacted, post-PHI-scan text (see routes/chat.ts). The semantic
// helpers below mirror exactly the set of events the chat route emits so the
// producer contract is testable in one place (sse.test.ts).

export interface ToolResultPayload {
  ok: boolean;
  result?: unknown;
  error?: string;
}

export class SseStream {
  private closed = false;
  private heartbeat: NodeJS.Timeout | null = null;
  private readonly encoder = new EventEncoder();

  constructor(private readonly res: Response) {
    res.setHeader("Content-Type", this.encoder.getContentType());
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    // Disable proxy buffering so chunks reach the browser immediately.
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders?.();
    // 15s heartbeat keeps intermediaries from idle-closing the connection.
    // ": ..." is an SSE comment line, ignored by every conformant client.
    this.heartbeat = setInterval(() => {
      if (this.closed) return;
      this.res.write(": heartbeat\n\n");
    }, 15_000);
    res.on("close", () => this.close());
  }

  /**
   * Low-level: encode one AG-UI event and write it to the wire. Generic over
   * `T extends BaseEvent` so call sites can pass fully-typed event literals
   * (with their event-specific fields) without tripping excess-property checks.
   */
  send<T extends BaseEvent>(event: T): void {
    if (this.closed) return;
    this.res.write(this.encoder.encodeSSE(event));
  }

  // ---- Run lifecycle ----

  runStarted(threadId: string, runId: string): void {
    this.send({ type: EventType.RUN_STARTED, threadId, runId });
  }

  runFinished(threadId: string, runId: string, result?: unknown): void {
    this.send({
      type: EventType.RUN_FINISHED,
      threadId,
      runId,
      ...(result !== undefined ? { result } : {}),
    });
  }

  runError(message: string, code?: string): void {
    this.send({
      type: EventType.RUN_ERROR,
      message,
      ...(code ? { code } : {}),
    });
  }

  stepStarted(stepName: string): void {
    this.send({ type: EventType.STEP_STARTED, stepName });
  }

  // ---- Assistant text (single block; emitted post-PHI-scan) ----

  /**
   * Emit a complete assistant message as START → CONTENT → END. The chat route
   * buffers the model output, runs the PHI scan, and only then calls this with
   * the final (possibly SAFE_REFUSAL) text — no token deltas ever reach the
   * wire pre-scan. Citations ride on a CUSTOM event keyed to the same message.
   */
  assistantMessage(messageId: string, text: string, citations: string[]): void {
    this.send({
      type: EventType.TEXT_MESSAGE_START,
      messageId,
      role: "assistant",
    });
    this.send({ type: EventType.TEXT_MESSAGE_CONTENT, messageId, delta: text });
    this.send({ type: EventType.TEXT_MESSAGE_END, messageId });
    this.custom("citations", { message_id: messageId, citations });
  }

  // ---- Tool calls ----

  toolCall(
    toolCallId: string,
    toolCallName: string,
    args: unknown,
    parentMessageId?: string,
  ): void {
    this.send({
      type: EventType.TOOL_CALL_START,
      toolCallId,
      toolCallName,
      ...(parentMessageId ? { parentMessageId } : {}),
    });
    this.send({
      type: EventType.TOOL_CALL_ARGS,
      toolCallId,
      delta: JSON.stringify(args ?? {}),
    });
    this.send({ type: EventType.TOOL_CALL_END, toolCallId });
  }

  toolResult(
    messageId: string,
    toolCallId: string,
    payload: ToolResultPayload,
  ): void {
    this.send({
      type: EventType.TOOL_CALL_RESULT,
      messageId,
      toolCallId,
      content: JSON.stringify(payload),
      role: "tool",
    });
  }

  // ---- Domain signals over CUSTOM ----

  custom(name: string, value: unknown): void {
    this.send({ type: EventType.CUSTOM, name, value });
  }

  /** The persisted id of the user's turn (so the UI can reconcile on refetch). */
  userMessage(messageId: string, content: string): void {
    this.custom("user_message", { message_id: messageId, content });
  }

  /** A ledger row was committed for this turn. */
  ledgerAppended(entry: { seq: number; eventType: string; hash: string }): void {
    this.custom("ledger_appended", {
      seq: entry.seq,
      event_type: entry.eventType,
      hash: entry.hash,
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.heartbeat) clearInterval(this.heartbeat);
    try {
      this.res.end();
    } catch {
      // already closed
    }
  }

  isClosed(): boolean {
    return this.closed;
  }
}
