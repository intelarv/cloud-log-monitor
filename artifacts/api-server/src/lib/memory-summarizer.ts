// Opt-in LLM-generated cross-finding consolidation summaries.
//
// The deterministic consolidation pass (memory-eviction.ts Pass 1) collapses a
// group of OLD/RESOLVED findings sharing the same (classification, subclass,
// source) key down to one representative, evicting the duplicate embeddings.
// This module — when explicitly enabled — captures, for each collapsed group, a
// short natural-language summary of what that group represents, persisted to
// `memory_consolidation_summaries` and ledgered.
//
// WHY THIS IS A SEPARATE, OPT-IN SEAM (and what it deliberately breaks):
//   The eviction module is pure/deterministic-by-design so the credential-free
//   offline eval gate stays byte-identical. Summarization is the opposite — it
//   calls an LLM. So it is gated behind its OWN switch, `MEMORY_CONSOLIDATION_
//   SUMMARY`, on top of the existing memory job. When the switch is unset the
//   summarizer never runs, writes nothing, and makes no LLM call — boot and the
//   eval gate are byte-identical. Only when an operator opts in does the
//   (non-deterministic, LLM-dependent) summary generation happen.
//
// PHI posture (threat_model §Information Disclosure):
//   - INPUT is the REDACTED-only finding projection (the same redacted evidence
//     the agent already sees) plus structural metadata. Raw evidence is never
//     read here (the SELECT does not touch raw_evidence / raw_evidence_ref).
//   - OUTPUT is re-scanned with `scanForPhi` before it is persisted or
//     ledgered; any hit hard-fails the write for that group (ledgered
//     `memory.summary_failed`, reason only — never the offending text).
//   - The ledger carries counts + model_id only: no finding ids, no snippets,
//     no summary text, no PHI.
//
// Cost + idempotency:
//   - A per-run cap (`MEMORY_SUMMARY_MAX_GROUPS_PER_RUN`) bounds LLM calls.
//   - Each group stores a `member_signature` (hash of its sorted member ids);
//     a sweep skips any group whose signature is unchanged, so a steady-state
//     group is summarized once, not every cadence.
//   - Runs under the SAME leader lock + cadence as eviction (see
//     memory-eviction.ts), so only one pod summarizes per sweep.

import { createHash, randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import { type LlmAgentRuntime } from "./llm-runtime";
import { resolveLlmForDecisionPoint } from "./llm-decision-points";
import { scanForPhi } from "./redact";
import { CHAT_AGENT_MODEL } from "./prompts";
import {
  consolidationGroups,
  type ConsolidationGroup,
  type MemoryFinding,
  type MemoryPolicy,
} from "./memory-eviction";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface SummaryPolicy {
  /** Max consolidation groups summarized per tenant per sweep (LLM-cost cap). */
  maxGroupsPerRun: number;
  /** Max group members whose redacted snippet is sampled into the prompt. */
  maxMembersSampled: number;
  /** Model id hint passed to the runtime (cloud runtimes may override). */
  modelId: string;
}

function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
  label: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${label}=${raw} must be a positive number`);
  }
  return Math.floor(n);
}

function isTruthyFlag(raw: string | undefined): boolean {
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}

/** Parse env into a summary policy. Returns null (disabled) unless the opt-in
 *  `MEMORY_CONSOLIDATION_SUMMARY` flag is truthy. Pure: no I/O. */
export function getSummaryPolicyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): SummaryPolicy | null {
  if (!isTruthyFlag(env["MEMORY_CONSOLIDATION_SUMMARY"])) return null;
  return {
    maxGroupsPerRun: parsePositiveInt(
      env["MEMORY_SUMMARY_MAX_GROUPS_PER_RUN"],
      20,
      "MEMORY_SUMMARY_MAX_GROUPS_PER_RUN",
    ),
    maxMembersSampled: parsePositiveInt(
      env["MEMORY_SUMMARY_MAX_MEMBERS_SAMPLED"],
      8,
      "MEMORY_SUMMARY_MAX_MEMBERS_SAMPLED",
    ),
    modelId: env["MEMORY_SUMMARY_MODEL"]?.trim() || CHAT_AGENT_MODEL,
  };
}

// ---------------------------------------------------------------------------
// Pure helpers (no DB / no LLM)
// ---------------------------------------------------------------------------

/** Stable hash of a group's membership — sorted ids so order can't change it. */
export function memberSignature(memberIds: readonly string[]): string {
  const sorted = [...memberIds].sort();
  return createHash("sha256").update(sorted.join("\u0000")).digest("hex");
}

/** memory-eviction.ts `groupKey()` joins on NUL (`\u0000`) so values can't run
 *  together ambiguously — but Postgres `text` columns reject NUL bytes. Encode
 *  the in-memory group key to a NUL-free, collision-free token for storage +
 *  the ON CONFLICT identity. The readable parts (classification/subclass/source)
 *  are persisted in their own columns, so this token only needs to be stable. */
export function storedGroupKey(groupKey: string): string {
  return Buffer.from(groupKey, "utf8").toString("base64");
}

const MAX_SNIPPET_CHARS = 300;

/** Compact a redacted-evidence value into a bounded single-line snippet for the
 *  prompt. Input is already redacted; this only bounds size + flattens. */
function redactedSnippet(redactedEvidence: unknown): string {
  let s: string;
  try {
    s =
      typeof redactedEvidence === "string"
        ? redactedEvidence
        : JSON.stringify(redactedEvidence);
  } catch {
    s = "";
  }
  s = (s ?? "").replace(/\s+/g, " ").trim();
  return s.length > MAX_SNIPPET_CHARS ? s.slice(0, MAX_SNIPPET_CHARS) + "…" : s;
}

/** Build the LLM prompt for one consolidation group from REDACTED-only data. */
export function buildSummaryPrompt(
  group: ConsolidationGroup,
  redactedById: ReadonlyMap<string, unknown>,
  policy: SummaryPolicy,
): { systemPrompt: string; userPrompt: string } {
  const systemPrompt = [
    "You summarize a cluster of related healthcare-compliance log findings for a",
    "PHI/PII audit memory. Write ONE or TWO factual sentences describing what the",
    "cluster represents: the kind of finding, its source, how many occurrences,",
    "the time span, and the remediation status. Use ONLY the structured data",
    "provided — do not speculate, do not invent identifiers, and never include any",
    "personal data, secrets, or verbatim log content. Output plain prose only.",
  ].join(" ");

  const total = group.members.length;
  const sampled = group.members.slice(0, policy.maxMembersSampled);
  const severities = countBy(group.members.map((m) => m.severity));
  const statuses = countBy(group.members.map((m) => m.status));
  const lastSeen = group.members.map((m) => m.lastSeenAtMs);
  const occurrences = group.members.reduce(
    (acc, m) => acc + (m.occurrenceCount || 0),
    0,
  );

  const lines: string[] = [
    `Cluster of ${total} findings sharing classification/subclass/source.`,
    `classification: ${group.classification}`,
    `subclass: ${group.subclass ?? "(none)"}`,
    `source: ${group.source}`,
    `severity_breakdown: ${fmtCounts(severities)}`,
    `status_breakdown: ${fmtCounts(statuses)}`,
    `total_occurrences: ${occurrences}`,
    `earliest_last_seen: ${new Date(Math.min(...lastSeen)).toISOString()}`,
    `latest_last_seen: ${new Date(Math.max(...lastSeen)).toISOString()}`,
    "",
    `Sampled redacted snippets (${sampled.length} of ${total}):`,
  ];
  for (const m of sampled) {
    lines.push(`- [${m.severity}/${m.status}] ${redactedSnippet(redactedById.get(m.id))}`);
  }

  return { systemPrompt, userPrompt: lines.join("\n") };
}

function countBy(values: readonly string[]): Map<string, number> {
  const m = new Map<string, number>();
  for (const v of values) m.set(v, (m.get(v) ?? 0) + 1);
  return m;
}

function fmtCounts(m: ReadonlyMap<string, number>): string {
  return [...m.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
}

// ---------------------------------------------------------------------------
// Core summarization (testable, dependency-injected)
// ---------------------------------------------------------------------------

export interface SummarizeDeps {
  memoryPolicy: MemoryPolicy;
  summaryPolicy: SummaryPolicy;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
  /** Injectable LLM runtime for tests. Defaults to the process-wide runtime. */
  runtime?: LlmAgentRuntime;
}

export interface SummarizeResult {
  /** Tenants scanned. */
  tenants: number;
  /** Consolidation groups encountered (across tenants). */
  groups: number;
  /** Summaries written (created or refreshed). */
  summarized: number;
  /** Groups skipped because their membership signature was unchanged. */
  skipped: number;
  /** Groups/tenants that errored or whose LLM output failed the PHI scan. */
  failed: number;
}

interface SummaryRow {
  id: string;
  classification: string;
  subclass: string | null;
  severity: string;
  status: string;
  source: string;
  last_seen_ms: number | string;
  occurrence_count: number | string;
  redacted_evidence: unknown;
  [key: string]: unknown;
}

const MAX_SUMMARY_OUTPUT_TOKENS = 220;

/** Run one summarization sweep across all tenants. Mirrors the eviction sweep:
 *  enumerate tenants, operate inside `withTenant()` so RLS is enforced for the
 *  reads + the upsert. Reads the REDACTED projection only (never raw evidence).
 */
export async function summarizeConsolidationsOnce(
  deps: SummarizeDeps,
): Promise<SummarizeResult> {
  const { memoryPolicy, summaryPolicy } = deps;
  const now = deps.now ?? Date.now;
  // Injected runtime (tests) wins and keeps the policy's model id. With no
  // injection, resolve the summary point's own provider/model (M17); the
  // resolver honors the legacy MEMORY_SUMMARY_MODEL alias for this point.
  const resolved = deps.runtime
    ? { runtime: deps.runtime, modelId: summaryPolicy.modelId }
    : resolveLlmForDecisionPoint("summary", summaryPolicy.modelId);
  const runtime = resolved.runtime;
  const effectiveSummaryPolicy = { ...summaryPolicy, modelId: resolved.modelId };
  const result: SummarizeResult = {
    tenants: 0,
    groups: 0,
    summarized: 0,
    skipped: 0,
    failed: 0,
  };

  const tenantRows = await db.execute<{ tenant_id: string }>(
    sql`SELECT DISTINCT tenant_id FROM findings`,
  );

  for (const { tenant_id } of tenantRows.rows) {
    result.tenants++;
    try {
      const perTenant = await summarizeTenant(
        tenant_id,
        memoryPolicy,
        effectiveSummaryPolicy,
        runtime,
        now(),
      );
      result.groups += perTenant.groups;
      result.summarized += perTenant.summarized;
      result.skipped += perTenant.skipped;
      result.failed += perTenant.failed;

      if (perTenant.summarized > 0) {
        await appendLedger({
          tenantId: tenant_id,
          actor: { kind: "system", id: "memory_summarizer" },
          eventType: "memory.summarized",
          subjectType: "memory",
          // Counts + model_id ONLY. No finding ids, no snippets, no summary
          // text, no PHI.
          payload: {
            summarized: perTenant.summarized,
            skipped: perTenant.skipped,
            groups: perTenant.groups,
            model_id: effectiveSummaryPolicy.modelId,
          },
        });
      }
    } catch (err) {
      result.failed++;
      const errorName = err instanceof Error ? err.name : "unknown";
      logger.error(
        { error_name: errorName, tenant_id },
        "memory summarization failed for tenant; will retry next cadence",
      );
      await appendLedger({
        tenantId: tenant_id,
        actor: { kind: "system", id: "memory_summarizer" },
        eventType: "memory.summary_failed",
        subjectType: "memory",
        // error NAME only — never the raw err.
        payload: { error: errorName },
      });
    }
  }

  return result;
}

interface PerTenant {
  groups: number;
  summarized: number;
  skipped: number;
  failed: number;
}

async function summarizeTenant(
  tenantId: string,
  memoryPolicy: MemoryPolicy,
  summaryPolicy: SummaryPolicy,
  runtime: LlmAgentRuntime,
  nowMs: number,
): Promise<PerTenant> {
  const out: PerTenant = { groups: 0, summarized: 0, skipped: 0, failed: 0 };

  // Read the redacted projection only (NO raw_evidence / raw_evidence_ref).
  const { findings, redactedById, existing } = await withTenant(
    tenantId,
    async (tx) => {
      const rows = await tx.execute<SummaryRow>(sql`
        SELECT
          f.id,
          f.classification,
          f.subclass,
          f.severity,
          f.status,
          f.source,
          extract(epoch FROM f.last_seen_at) * 1000 AS last_seen_ms,
          f.occurrence_count,
          f.redacted_evidence
        FROM findings f
        WHERE f.tenant_id = ${tenantId}
      `);
      const findings: MemoryFinding[] = rows.rows.map((r) => ({
        id: r.id,
        classification: r.classification,
        subclass: r.subclass,
        source: r.source,
        severity: r.severity,
        status: r.status,
        lastSeenAtMs: Number(r.last_seen_ms),
        occurrenceCount: Number(r.occurrence_count),
      }));
      const redactedById = new Map<string, unknown>(
        rows.rows.map((r) => [r.id, r.redacted_evidence]),
      );
      const existingRows = await tx.execute<{
        group_key: string;
        member_signature: string;
      }>(sql`
        SELECT group_key, member_signature
        FROM memory_consolidation_summaries
        WHERE tenant_id = ${tenantId}
      `);
      const existing = new Map<string, string>(
        existingRows.rows.map((r) => [r.group_key, r.member_signature]),
      );
      return { findings, redactedById, existing };
    },
  );

  const groups = consolidationGroups(findings, memoryPolicy, nowMs);
  out.groups = groups.length;

  let budget = summaryPolicy.maxGroupsPerRun;
  for (const group of groups) {
    if (budget <= 0) break;
    const sig = memberSignature(group.members.map((m) => m.id));
    const dbKey = storedGroupKey(group.key);
    if (existing.get(dbKey) === sig) {
      out.skipped++;
      continue;
    }
    budget--;

    const { systemPrompt, userPrompt } = buildSummaryPrompt(
      group,
      redactedById,
      summaryPolicy,
    );

    const gen = await runtime.generate({
      systemPrompt,
      userPrompt,
      modelId: summaryPolicy.modelId,
      temperature: 0.2,
      maxOutputTokens: MAX_SUMMARY_OUTPUT_TOKENS,
    });
    const text = (gen.text ?? "").trim();

    // Defense-in-depth: the input was redacted-only, but re-scan the model
    // output before it is persisted/ledgered. Any hit hard-fails this group.
    if (text === "" || scanForPhi(text).length > 0) {
      out.failed++;
      await appendLedger({
        tenantId,
        actor: { kind: "system", id: "memory_summarizer" },
        eventType: "memory.summary_failed",
        subjectType: "memory",
        payload: { error: text === "" ? "empty_output" : "phi_in_output" },
      });
      continue;
    }

    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        INSERT INTO memory_consolidation_summaries (
          id, tenant_id, group_key, classification, subclass, source,
          representative_finding_id, consolidated_count, member_signature,
          summary, model_id, created_at, updated_at
        ) VALUES (
          ${randomUUID()}, ${tenantId}, ${dbKey}, ${group.classification},
          ${group.subclass}, ${group.source}, ${group.members[0].id},
          ${group.members.length}, ${sig}, ${text}, ${gen.modelId},
          now(), now()
        )
        ON CONFLICT (tenant_id, group_key) DO UPDATE SET
          classification = EXCLUDED.classification,
          subclass = EXCLUDED.subclass,
          source = EXCLUDED.source,
          representative_finding_id = EXCLUDED.representative_finding_id,
          consolidated_count = EXCLUDED.consolidated_count,
          member_signature = EXCLUDED.member_signature,
          summary = EXCLUDED.summary,
          model_id = EXCLUDED.model_id,
          updated_at = now()
      `);
    });
    out.summarized++;
  }

  return out;
}
