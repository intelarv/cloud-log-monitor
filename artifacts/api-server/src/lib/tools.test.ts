import { describe, it, expect } from "vitest";
import { z } from "zod";
import { ToolRegistry, type McpToolDef } from "./tools";

// Offline tests for the per-handler hard timeout (threat model §DoS). We use a
// fresh ToolRegistry with a tiny timeout and register a tool under an
// allow-listed name ("get_finding") so the policy allow-list + arg
// revalidation pass before the handler runs.

function makeTool(
  handler: McpToolDef<{ finding_id: string }, unknown>["handler"],
): McpToolDef<{ finding_id: string }, unknown> {
  return {
    name: "get_finding",
    version: "test-1.0.0",
    description: "test tool registered under an allow-listed name",
    inputSchema: z.object({ finding_id: z.string() }),
    handler,
  };
}

const ctx = { tenantId: "t_test", userId: "u_test", agent: "chat" as const };

describe("ToolRegistry handler timeout", () => {
  it("returns the result for a fast handler", async () => {
    const reg = new ToolRegistry({ handlerTimeoutMs: 1000 });
    reg.register(makeTool(async () => ({ value: 42 })));
    const res = await reg.call("get_finding", { finding_id: "F-1" }, ctx);
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.result).toEqual({ value: 42 });
  });

  it("maps a hanging handler to a timeout error", async () => {
    const reg = new ToolRegistry({ handlerTimeoutMs: 15 });
    reg.register(makeTool(() => new Promise(() => {})));
    const res = await reg.call("get_finding", { finding_id: "F-1" }, ctx);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe("timeout");
      expect(res.error).toMatch(/timed out/);
    }
  });

  it("maps a thrown handler error to exec_error (not timeout)", async () => {
    const reg = new ToolRegistry({ handlerTimeoutMs: 1000 });
    reg.register(
      makeTool(async () => {
        throw new Error("boom");
      }),
    );
    const res = await reg.call("get_finding", { finding_id: "F-1" }, ctx);
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe("exec_error");
      expect(res.error).toContain("boom");
    }
  });
});
