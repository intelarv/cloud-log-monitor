import type { Response } from "express";

// AG-UI envelope shape (compressed for M0). Real AG-UI has typed event
// kinds — we expose a minimal subset sufficient to drive the dashboard.
export type AguiEvent =
  | { type: "session_started"; session_id: string; ts: string }
  | { type: "user_message"; message_id: string; content: string; ts: string }
  | { type: "agent_thinking"; ts: string }
  | {
      type: "tool_call";
      call_id: string;
      tool: string;
      args: Record<string, unknown>;
      ts: string;
    }
  | {
      type: "tool_result";
      call_id: string;
      ok: boolean;
      result?: unknown;
      error?: string;
      ts: string;
    }
  | { type: "agent_message_delta"; message_id: string; delta: string; ts: string }
  | {
      type: "agent_message_complete";
      message_id: string;
      citations: string[];
      ts: string;
    }
  | {
      type: "ledger_appended";
      seq: number;
      event_type: string;
      hash: string;
      ts: string;
    }
  | { type: "error"; error: string; ts: string }
  | { type: "done"; ts: string };

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
    this.res.write(`event: ${event.type}\n`);
    this.res.write(`data: ${JSON.stringify(event)}\n\n`);
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
