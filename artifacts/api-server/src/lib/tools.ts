import { z } from "zod";
import { eq, and } from "drizzle-orm";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
import { withTenant } from "./db-context";
import {
  isToolAllowed,
  validateToolArgs,
  type AgentName,
  type PolicyViolation,
  type ToolName,
} from "./policy";
import { hybridSearchFindings, type RetrieverSource } from "./search";
import { withTimeout, TimeoutError } from "./with-timeout";

// Default hard timeout for a single tool handler. Threat model §DoS:
// "Every tool handler MUST have a hard timeout." A well-behaved retrieval
// tool answers in well under a second; 10s is generous head-room that still
// turns a wedged handler into a deterministic refusal.
const DEFAULT_TOOL_TIMEOUT_MS = 10_000;

function envInt(name: string, def: number): number {
  const v = process.env[name];
  if (v === undefined) return def;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : def;
}

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
  /**
   * M1.6: optional callback invoked when the policy pass rejects an args
   * payload (canary in args, PHI in args, oversize, bad id format). The
   * caller is the side-effect owner — it ledger-writes the incident and
   * may insert a finding. Side-effect-free callers (tests, internal
   * verification) can omit it.
   */
  onPolicyViolation?: (info: {
    tool: ToolName;
    violations: PolicyViolation[];
    canaryTripped: boolean;
    rawArgs: unknown;
  }) => Promise<void> | void;
}

const GetFindingArgs = z.object({
  finding_id: z.string().min(1).max(64),
});

// `get_finding` reads from the `findings_redacted` view (via the
// findings table — same data minus any future raw columns). RLS guarantees
// cross-tenant safety; the tool itself only adds the policy allow-list check.
export const getFindingTool: McpToolDef<
  z.infer<typeof GetFindingArgs>,
  FindingSafe | null
> = {
  name: "get_finding",
  version: "1.1.0",
  description:
    "Read a single finding (redacted view) by id, scoped to the caller's tenant.",
  inputSchema: GetFindingArgs,
  handler: async (args, ctx) => {
    return withTenant(ctx.tenantId, async (tx) => {
      // M1.6: explicit safe projection — NEVER `.select()` over findings here.
      // `get_finding`'s result is fed back into the LLM prompt AND emitted to
      // the client via SSE, so pulling `rawEvidence` would bypass both the
      // PHI-in-prompt invariant and the break-glass gate.
      const [row] = await tx
        .select(findingSafeColumns)
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

export type ToolCallError =
  | "not_allowed"
  | "unknown_tool"
  | "bad_args"
  | "policy_violation"
  | "exec_error"
  | "timeout";

export type ToolCallResult =
  | { ok: true; result: unknown; tool: { name: string; version: string } }
  | {
      ok: false;
      error: string;
      code: ToolCallError;
      /** Populated only when `code === "policy_violation"`. */
      violations?: PolicyViolation[];
    };

export class ToolRegistry {
  private readonly tools = new Map<string, McpToolDef<unknown, unknown>>();
  private readonly handlerTimeoutMs: number;

  constructor(opts: { handlerTimeoutMs?: number } = {}) {
    this.handlerTimeoutMs = opts.handlerTimeoutMs ?? DEFAULT_TOOL_TIMEOUT_MS;
  }

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

  // Invoke a tool through the full guard chain:
  //   1. Tool exists? (`unknown_tool`)
  //   2. Agent allow-list (`not_allowed`)
  //   3. Zod parse — proves shape (`bad_args`)
  //   4. Policy revalidation — proves cross-cutting invariants
  //      (`policy_violation` — canary in args, PHI in args, oversize, bad
  //      id format). See ARCHITECTURE.md §23.1.
  //   5. Handler execution (`exec_error` on throw)
  //
  // Order matters: we Zod-parse before policy-validating so policy code can
  // assume well-typed args, but we DO NOT short-circuit policy on Zod
  // failure — the two failure modes are independent and we want a stable
  // signal for each.
  async call(
    name: string,
    rawArgs: unknown,
    ctx: ToolContext,
  ): Promise<ToolCallResult> {
    const def = this.tools.get(name);
    if (!def) return { ok: false, error: `unknown tool ${name}`, code: "unknown_tool" };
    if (!isToolAllowed(ctx.agent, name as ToolName)) {
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
    const policy = validateToolArgs(name as ToolName, parsed.data);
    if (!policy.ok) {
      // Fire the side-effect hook BEFORE returning so the ledger entry +
      // incident finding are recorded synchronously with the refusal. If the
      // hook throws we still surface the policy violation (don't swallow).
      try {
        await ctx.onPolicyViolation?.({
          tool: name as ToolName,
          violations: policy.violations,
          canaryTripped: policy.canaryTripped,
          rawArgs,
        });
      } catch {
        // intentional: incident-emission failure must not mask the original
        // policy violation. The thrower is responsible for its own logging.
      }
      return {
        ok: false,
        error: policy.violations.map((v) => v.message).join("; "),
        code: "policy_violation",
        violations: policy.violations,
      };
    }
    try {
      // Hard per-handler timeout (threat model §DoS). `Promise.resolve` guards
      // a handler that throws synchronously instead of returning a promise.
      const result = await withTimeout(
        Promise.resolve(def.handler(parsed.data, ctx)),
        this.handlerTimeoutMs,
        `tool:${def.name}`,
      );
      return {
        ok: true,
        result,
        tool: { name: def.name, version: def.version },
      };
    } catch (err) {
      if (err instanceof TimeoutError) {
        return {
          ok: false,
          error: `tool ${def.name} timed out after ${err.timeoutMs}ms`,
          code: "timeout",
        };
      }
      return {
        ok: false,
        error: err instanceof Error ? err.message : String(err),
        code: "exec_error",
      };
    }
  }
}

// `search_findings` (M1): hybrid BM25 + vector retrieval over the
// findings_redacted projection, fused with RRF, tenant-scoped via RLS. Returns
// a small candidate set with provenance (which retriever ranked each hit) so
// the agent can cite findings it didn't see in pre-loaded context.
// Note: `limit` carries a default, which makes the Zod *input* type allow
// undefined while the parsed *output* type is `number`. McpToolDef is
// invariant in Args, so we constrain the schema's input == output by making
// limit non-optional with a default applied client-side at the call site.
const SearchFindingsArgs = z.object({
  query: z.string().min(1).max(500),
  limit: z.number().int().min(1).max(20),
});

export interface SearchFindingsResultItem {
  id: string;
  classification: string;
  subclass: string | null;
  severity: string;
  source: string;
  redacted_snippet: string;
  retrievers: RetrieverSource[];
  score: number;
}

export const searchFindingsTool: McpToolDef<
  z.infer<typeof SearchFindingsArgs>,
  { results: SearchFindingsResultItem[] }
> = {
  name: "search_findings",
  version: "1.0.0",
  description:
    "Hybrid (BM25 + vector) search over the redacted findings view, scoped to the caller's tenant. Returns ranked candidate findings with retriever provenance.",
  inputSchema: SearchFindingsArgs,
  handler: async (args, ctx) => {
    const { fused, findings } = await hybridSearchFindings(
      ctx.tenantId,
      args.query,
      { topK: args.limit },
    );
    const byId = new Map(findings.map((f) => [f.id, f] as const));
    const results: SearchFindingsResultItem[] = fused
      .map((hit) => {
        const f = byId.get(hit.finding_id);
        if (!f) return null;
        const ev = f.redactedEvidence as { snippet?: string };
        return {
          id: f.id,
          classification: f.classification,
          subclass: f.subclass,
          severity: f.severity,
          source: f.source,
          redacted_snippet: ev.snippet ?? "",
          retrievers: hit.sources,
          score: hit.score,
        };
      })
      .filter((r): r is SearchFindingsResultItem => r != null);
    return { results };
  },
};

export const toolRegistry: ToolRegistry = new ToolRegistry({
  handlerTimeoutMs: envInt("TOOL_CALL_TIMEOUT_MS", DEFAULT_TOOL_TIMEOUT_MS),
});
toolRegistry.register(getFindingTool);
toolRegistry.register(searchFindingsTool);
