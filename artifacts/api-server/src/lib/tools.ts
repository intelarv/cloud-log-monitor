import { z } from "zod";
import { eq, and } from "drizzle-orm";
import { findingsTable, type Finding } from "@workspace/db";
import { withTenant } from "./db-context";
import { isToolAllowed, type AgentName } from "./policy";

// MCP-shaped tool definition. A real MCP server would advertise these via
// `list_tools` and execute them via `call_tool`. For M0 the registry is
// in-process; the shape matches MCP so the wire format can be added in M2
// without rewriting handlers. See ARCHITECTURE.md §23.16.
export interface McpToolDef<Args, Result> {
  name: string;
  version: string;
  description: string;
  inputSchema: z.ZodType<Args>;
  handler: (args: Args, ctx: ToolContext) => Promise<Result>;
}

export interface ToolContext {
  tenantId: string;
  userId: string;
  agent: AgentName;
}

const GetFindingArgs = z.object({
  finding_id: z.string().min(1).max(64),
});

// `get_finding` reads from the `findings_redacted` view (via the
// findings table — same data minus any future raw columns). RLS guarantees
// cross-tenant safety; the tool itself only adds the policy allow-list check.
export const getFindingTool: McpToolDef<
  z.infer<typeof GetFindingArgs>,
  Finding | null
> = {
  name: "get_finding",
  version: "1.0.0",
  description:
    "Read a single finding (redacted view) by id, scoped to the caller's tenant.",
  inputSchema: GetFindingArgs,
  handler: async (args, ctx) => {
    return withTenant(ctx.tenantId, async (tx) => {
      const [row] = await tx
        .select()
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.id, args.finding_id),
            eq(findingsTable.tenantId, ctx.tenantId),
          ),
        )
        .limit(1);
      return row ?? null;
    });
  },
};

export class ToolRegistry {
  private readonly tools = new Map<string, McpToolDef<unknown, unknown>>();

  register<A, R>(def: McpToolDef<A, R>): void {
    this.tools.set(def.name, def as McpToolDef<unknown, unknown>);
  }

  list(): { name: string; version: string; description: string }[] {
    return Array.from(this.tools.values()).map((t) => ({
      name: t.name,
      version: t.version,
      description: t.description,
    }));
  }

  // Invoke a tool with policy + schema validation. Returns either the result
  // or a structured error envelope mirroring MCP error semantics.
  async call(
    name: string,
    rawArgs: unknown,
    ctx: ToolContext,
  ): Promise<
    | { ok: true; result: unknown; tool: { name: string; version: string } }
    | { ok: false; error: string; code: "not_allowed" | "unknown_tool" | "bad_args" | "exec_error" }
  > {
    const def = this.tools.get(name);
    if (!def) return { ok: false, error: `unknown tool ${name}`, code: "unknown_tool" };
    if (!isToolAllowed(ctx.agent, name as "get_finding")) {
      return {
        ok: false,
        error: `agent ${ctx.agent} not allowed to call ${name}`,
        code: "not_allowed",
      };
    }
    const parsed = def.inputSchema.safeParse(rawArgs);
    if (!parsed.success) {
      return {
        ok: false,
        error: `invalid args: ${parsed.error.message}`,
        code: "bad_args",
      };
    }
    try {
      const result = await def.handler(parsed.data, ctx);
      return {
        ok: true,
        result,
        tool: { name: def.name, version: def.version },
      };
    } catch (err) {
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        code: "exec_error",
      };
    }
  }
}

export const toolRegistry: ToolRegistry = new ToolRegistry();
toolRegistry.register(getFindingTool);
