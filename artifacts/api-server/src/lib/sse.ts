import type { Response } from "express";
import { z } from "zod/v4";

// AG-UI envelope shape (compressed for M0). Real AG-UI has a much richer
// typed event vocabulary; we expose a minimal subset sufficient to drive the
// dashboard. Every event is validated through `AguiEventSchema.parse()`
// before being written to the wire, so the SSE protocol gets the same
// contract enforcement as the REST responses (which all go through their
// generated Zod schemas in routes/*).
export const AguiEventSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("session_started"),
    session_id: z.string(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("user_message"),
    message_id: z.string(),
    content: z.string(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("agent_thinking"),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("tool_call"),
    call_id: z.string(),
    tool: z.string(),
    args: z.record(z.string(), z.unknown()),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("tool_result"),
    call_id: z.string(),
    ok: z.boolean(),
    result: z.unknown().optional(),
    error: z.string().optional(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("agent_message_delta"),
    message_id: z.string(),
    delta: z.string(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("agent_message_complete"),
    message_id: z.string(),
    citations: z.array(z.string()),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("ledger_appended"),
    seq: z.number().int(),
    event_type: z.string(),
    hash: z.string(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("error"),
    error: z.string(),
    ts: z.string(),
  }),
  z.object({
    type: z.literal("done"),
    ts: z.string(),
  }),
]);

export type AguiEvent = z.infer<typeof AguiEventSchema>;

export class SseStream {
  private closed = false;
  private heartbeat: NodeJS.Timeout | null = null;

  constructor(private readonly res: Response) {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    // Disable proxy buffering so chunks reach the browser immediately.
    res.setHeader("X-Accel-Buffering", "no");
    res.flushHeaders?.();
    // 15s heartbeat keeps intermediaries from idle-closing the connection.
    this.heartbeat = setInterval(() => {
      if (this.closed) return;
      this.res.write(": heartbeat\n\n");
    }, 15_000);
    res.on("close", () => this.close());
  }

  send(event: AguiEvent): void {
    if (this.closed) return;
    // Validate before writing. A failure here means the server is about to
    // emit an event that doesn't match the contract — better to throw and let
    // the route's error handler emit a sanitized "agent_error" than to ship
    // malformed events to the client.
    const parsed = AguiEventSchema.parse(event);
    this.res.write(`event: ${parsed.type}\n`);
    this.res.write(`data: ${JSON.stringify(parsed)}\n\n`);
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
