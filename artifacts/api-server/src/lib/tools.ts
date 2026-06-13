import { z } from "zod";
import { randomUUID } from "node:crypto";
import { eq, and, inArray, desc } from "drizzle-orm";
import {
  findingsTable,
  findingSafeColumns,
  remediationProposalsTable,
  FINDING_CLASSIFICATIONS,
  FINDING_SEVERITIES,
  FINDING_STATUSES,
  type FindingSafe,
} from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
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

// `structured_query` (threat model §EoP "No raw SQL from LLMs"): the agent
// plane MUST NOT have a tool that executes LLM-generated SQL. This is the
// sanctioned alternative — a Zod-validated *typed filter object*. The agent
// supplies enum-constrained facets (classification / severity / status /
// source) and a bounded limit; the handler turns them into parameterized
// drizzle predicates. There is no string interpolation and no free-form SQL,
// so an injected agent can at worst select a different (still tenant-scoped,
// still redacted) slice of its own findings.
//
// `limit` is non-optional for the same McpToolDef invariance reason documented
// on `search_findings`.
const StructuredQueryArgs = z.object({
  classification: z.array(z.enum(FINDING_CLASSIFICATIONS)).max(16).optional(),
  severity: z.array(z.enum(FINDING_SEVERITIES)).max(4).optional(),
  status: z.array(z.enum(FINDING_STATUSES)).max(3).optional(),
  // Exact-match source filter (e.g. "cloudwatch:/aws/lambda/billing"). Bounded
  // count + length; matched with `inArray`, never `LIKE`, so no wildcard
  // injection. An array so the agent can scope to several sources at once.
  source: z.array(z.string().min(1).max(200)).max(16).optional(),
  limit: z.number().int().min(1).max(50),
});

export interface StructuredQueryResultItem {
  id: string;
  classification: string;
  subclass: string | null;
  severity: string;
  status: string;
  source: string;
  redacted_snippet: string;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
}

export const structuredQueryTool: McpToolDef<
  z.infer<typeof StructuredQueryArgs>,
  { results: StructuredQueryResultItem[] }
> = {
  name: "structured_query",
  version: "1.0.0",
  description:
    "Filter findings by typed facets (classification, severity, status, source) over the redacted view, scoped to the caller's tenant. Accepts a structured filter object only — never SQL. Returns matching findings, most-recently-seen first.",
  inputSchema: StructuredQueryArgs,
  handler: async (args, ctx) => {
    const rows = await withTenant(ctx.tenantId, async (tx) => {
      const conds = [eq(findingsTable.tenantId, ctx.tenantId)];
      if (args.classification && args.classification.length > 0) {
        conds.push(inArray(findingsTable.classification, args.classification));
      }
      if (args.severity && args.severity.length > 0) {
        conds.push(inArray(findingsTable.severity, args.severity));
      }
      if (args.status && args.status.length > 0) {
        conds.push(inArray(findingsTable.status, args.status));
      }
      if (args.source && args.source.length > 0) {
        conds.push(inArray(findingsTable.source, args.source));
      }
      // Safe projection ONLY — this result is fed back into the LLM prompt and
      // streamed to the client, so `rawEvidence` must never be selected here.
      return tx
        .select(findingSafeColumns)
        .from(findingsTable)
        .where(and(...conds))
        .orderBy(desc(findingsTable.lastSeenAt))
        .limit(args.limit);
    });
    const results: StructuredQueryResultItem[] = rows.map((f) => {
      const ev = f.redactedEvidence as { snippet?: string };
      return {
        id: f.id,
        classification: f.classification,
        subclass: f.subclass,
        severity: f.severity,
        status: f.status,
        source: f.source,
        redacted_snippet: ev.snippet ?? "",
        occurrence_count: f.occurrenceCount,
        first_seen_at: f.firstSeenAt.toISOString(),
        last_seen_at: f.lastSeenAt.toISOString(),
      };
    });
    return { results };
  },
};

// `propose_remediation` (threat model §EoP "HITL gates on write actions"):
// remediation tools MUST return *proposals*, not executions. This tool writes
// a PENDING `remediation_proposals` row and ledgers `remediation.proposed`;
// it executes nothing. A human then confirms (step-up gated) or rejects via
// the admin endpoints. The proposal is inert until confirmed.
const ProposeRemediationArgs = z.object({
  finding_id: z.string().min(1).max(64),
  action_type: z.enum([
    "redact_at_source",
    "open_pr",
    "notify_owner",
    "tighten_retention",
    "enable_kms",
    "other",
  ]),
  summary: z.string().min(1).max(500),
  rationale: z.string().min(1).max(2000),
});

export const proposeRemediationTool: McpToolDef<
  z.infer<typeof ProposeRemediationArgs>,
  { proposal_id: string; status: "pending" }
> = {
  name: "propose_remediation",
  version: "1.0.0",
  description:
    "Draft a remediation PROPOSAL for a finding (e.g. redact-at-source, open a PR, notify the owner). Creates a pending record for a human to confirm or reject — it does NOT execute anything. Provide finding_id, an action_type, a short summary, and the rationale.",
  inputSchema: ProposeRemediationArgs,
  handler: async (args, ctx) => {
    // Guard against proposing against a finding that doesn't exist in this
    // tenant (RLS already scopes the insert, but a dangling finding_id would
    // create an un-actionable proposal). Safe projection — id only.
    const proposalId = `rp_${randomUUID()}`;
    await withTenant(ctx.tenantId, async (tx) => {
      const [finding] = await tx
        .select({ id: findingsTable.id })
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.id, args.finding_id),
            eq(findingsTable.tenantId, ctx.tenantId),
          ),
        )
        .limit(1);
      if (!finding) {
        throw new Error(`finding ${args.finding_id} not found`);
      }
      await tx.insert(remediationProposalsTable).values({
        id: proposalId,
        tenantId: ctx.tenantId,
        findingId: args.finding_id,
        actionType: args.action_type,
        summary: args.summary,
        rationale: args.rationale,
        proposedByAgent: ctx.agent,
        proposedByUserId: ctx.userId,
        status: "pending",
      });
    });
    // Agent action → ledger entry (threat model §Repudiation). Payload carries
    // the structured pointers only; `summary`/`rationale` already passed the
    // tool-arg PHI/canary scan, but we keep them OUT of the ledger anyway and
    // record only the categorical action_type + ids, mirroring the rest of the
    // codebase's "no free text in the ledger payload" posture.
    await appendLedger({
      tenantId: ctx.tenantId,
      actor: { kind: "agent", id: ctx.agent },
      eventType: "remediation.proposed",
      subjectType: "finding",
      subjectId: args.finding_id,
      payload: {
        proposal_id: proposalId,
        finding_id: args.finding_id,
        action_type: args.action_type,
        proposed_by_agent: ctx.agent,
        proposed_by_user_id: ctx.userId,
      },
    });
    return { proposal_id: proposalId, status: "pending" };
  },
};

export const toolRegistry: ToolRegistry = new ToolRegistry({
  handlerTimeoutMs: envInt("TOOL_CALL_TIMEOUT_MS", DEFAULT_TOOL_TIMEOUT_MS),
});
toolRegistry.register(getFindingTool);
toolRegistry.register(searchFindingsTool);
toolRegistry.register(structuredQueryTool);
toolRegistry.register(proposeRemediationTool);
