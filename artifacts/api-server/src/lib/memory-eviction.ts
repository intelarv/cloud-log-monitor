// Importance-decay eviction + consolidation for the agent's vector memory.
//
// `finding_embeddings` is a DERIVED cache: one pgvector row per finding,
// rebuilt from the redacted-only safe projection by `backfillEmbeddings`. It
// powers the vector leg of hybrid retrieval. Unlike the findings audit record
// (append-only, RLS-locked, never deleted) the embedding cache may be pruned
// freely — deleting a row only removes a finding from the *vector* retriever;
// the lexical/BM25 leg (Postgres FTS / OpenSearch) still retrieves it, and a
// break-glass reader still resolves its raw evidence. So eviction degrades
// recall for low-importance memories without ever touching the audit trail.
//
// This module bounds that cache two ways, both deterministic (no LLM):
//
//   1. CONSOLIDATION (group-dedup). Among OLD or RESOLVED findings that share
//      the same (classification, subclass, source) key, keep only the single
//      highest-importance representative's embedding and evict the duplicates.
//      Recent, open findings are never consolidated (they may be distinct live
//      incidents). This collapses the long tail of repetitive resolved noise.
//   2. COUNT CAP. After consolidation, keep at most
//      `MEMORY_MAX_EMBEDDINGS_PER_TENANT` embeddings per tenant — the top-N by
//      importance — and evict the rest.
//
// HARD FLOOR: a critical-severity, still-open finding is NEVER evicted by
// either pass, regardless of age or the cap. Those are exactly the memories an
// analyst is most likely to need the agent to recall.
//
// Importance is a pure, deterministic score (see computeImportance): severity
// weight, exponential recency decay on last_seen_at (configurable half-life),
// a log-damped occurrence-count bonus, minus a resolved/false-positive penalty.
//
// KEY INVARIANT — ONE policy, shared by create AND evict. The same
// `selectEvictions` eligibility is consulted by `backfillEmbeddings` (which
// refrains from CREATING an embedding for an ineligible finding) and by this
// job (which REMOVES embeddings for ineligible findings). Without the shared
// gate, boot backfill would immediately recreate whatever the last eviction
// removed (recreate thrash). With it, the two converge on the same steady
// state. No schema change — the cache table already exists.
//
// Safety posture (mirrors the raw-evidence tiering job):
//   - Default-INERT. Scheduled only when `MEMORY_MAX_EMBEDDINGS_PER_TENANT` is
//     set. Unset ⇒ nothing runs, backfill is byte-identical, the offline eval
//     gate and dev boot are unchanged.
//   - No PHI / no snippets / no finding ids in the ledger or logs — counts and
//     policy parameters only. (The embedding `content` is redacted-only to
//     begin with, but eviction never reads or logs it.)
//   - Leader-locked (its own Postgres advisory key) so only one pod evicts per
//     cadence in a multi-instance deployment; setInterval is `.unref()`ed.
//   - Read + compute + delete happen in ONE per-tenant transaction so the
//     eviction decision is consistent with the rows it deletes.

import { sql } from "drizzle-orm";
import { db, pool } from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
// Type-only import (erased at build) — the runtime use is a lazy dynamic import
// in runEvictOnce so the summarizer↔eviction dependency stays acyclic.
import type { SummaryPolicy } from "./memory-summarizer";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface MemoryPolicy {
  /** Max embedding rows kept per tenant (top-N by importance). */
  maxPerTenant: number;
  /** Recency half-life (days) for the exponential importance decay. */
  halfLifeDays: number;
  /** Scheduler cadence. */
  intervalMs: number;
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

function parsePositiveNumber(
  raw: string | undefined,
  fallback: number,
  label: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${label}=${raw} must be a positive number`);
  }
  return n;
}

/** Parse env into a memory policy. Returns null (disabled) when the opt-in
 *  `MEMORY_MAX_EMBEDDINGS_PER_TENANT` is unset — pruning the vector memory is
 *  consequential, so it never turns on implicitly. Pure: no I/O. */
export function getMemoryPolicyFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): MemoryPolicy | null {
  const maxRaw = env["MEMORY_MAX_EMBEDDINGS_PER_TENANT"]?.trim();
  if (!maxRaw) return null;
  const maxPerTenant = Number(maxRaw);
  if (!Number.isFinite(maxPerTenant) || maxPerTenant <= 0) {
    throw new Error(
      `MEMORY_MAX_EMBEDDINGS_PER_TENANT=${maxRaw} must be a positive number`,
    );
  }
  return {
    maxPerTenant: Math.floor(maxPerTenant),
    halfLifeDays: parsePositiveNumber(
      env["MEMORY_DECAY_HALF_LIFE_DAYS"],
      30,
      "MEMORY_DECAY_HALF_LIFE_DAYS",
    ),
    intervalMs: parsePositiveInt(
      env["MEMORY_EVICT_INTERVAL_MS"],
      6 * 60 * 60 * 1000,
      "MEMORY_EVICT_INTERVAL_MS",
    ),
  };
}

// ---------------------------------------------------------------------------
// Pure importance + selection (no DB, unit-testable)
// ---------------------------------------------------------------------------

/** The structural-only finding fields the importance + selection logic needs.
 *  Deliberately NO redacted/raw evidence — eviction reasons over metadata,
 *  never content. */
export interface MemoryFinding {
  id: string;
  classification: string;
  subclass: string | null;
  source: string;
  severity: string;
  status: string;
  /** last_seen_at as epoch milliseconds. */
  lastSeenAtMs: number;
  occurrenceCount: number;
}

const DAY_MS = 24 * 60 * 60 * 1000;

// Severity dominates the base score; the gaps are wide so a more-severe
// finding outranks a less-severe one until the recency decay is extreme.
const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 8,
  high: 4,
  medium: 2,
  low: 1,
};

// Each doubling of occurrences adds this much (log-damped so a noisy finding
// can't dominate purely on volume).
const OCCURRENCE_WEIGHT = 1;

// Subtracted from a resolved / false-positive finding's score. Large enough to
// rank a closed finding below an otherwise-comparable open one.
const RESOLVED_PENALTY = 4;

function isClosed(status: string): boolean {
  return status === "resolved" || status === "false_positive";
}

/** Pure, deterministic importance score. Higher = more worth keeping in the
 *  vector cache. Combines: severity weight, exponential recency decay on
 *  last_seen_at (half-life from policy), a log-damped occurrence bonus, minus a
 *  resolved/false-positive penalty. Future-dated `last_seen_at` (clock skew) is
 *  clamped to age 0 so it can't inflate the score. */
export function computeImportance(
  f: MemoryFinding,
  now: number,
  policy: MemoryPolicy,
): number {
  const ageDays = Math.max(0, (now - f.lastSeenAtMs) / DAY_MS);
  const recency = Math.pow(2, -ageDays / policy.halfLifeDays); // (0, 1]
  const base = (SEVERITY_WEIGHT[f.severity] ?? 1) * recency;
  const occurrence =
    OCCURRENCE_WEIGHT * Math.log2(1 + Math.max(0, f.occurrenceCount));
  const penalty = isClosed(f.status) ? RESOLVED_PENALTY : 0;
  return base + occurrence - penalty;
}

/** A finding the floor protects: critical AND still open. Never evicted. */
function isFloor(f: MemoryFinding): boolean {
  return f.severity === "critical" && f.status === "open";
}

/** Eligible for consolidation (group-dedup): closed OR aged past one half-life.
 *  Recent open findings are NOT consolidated — they may be distinct live
 *  incidents the analyst still cares to recall individually. */
function isConsolidatable(
  f: MemoryFinding,
  now: number,
  policy: MemoryPolicy,
): boolean {
  if (isClosed(f.status)) return true;
  const ageDays = (now - f.lastSeenAtMs) / DAY_MS;
  return ageDays >= policy.halfLifeDays;
}

export function groupKey(f: MemoryFinding): string {
  // NUL separators so values can't run together ambiguously.
  return `${f.classification}\u0000${f.subclass ?? ""}\u0000${f.source}`;
}

/** A consolidation group: ≥2 consolidatable, non-floor findings sharing the
 *  same (classification, subclass, source) key. `members` is ranked by
 *  importance descending (ties by id ascending) so `members[0]` is the
 *  representative whose embedding survives and the rest are the ones whose
 *  embeddings Pass 1 evicts. Used both by `selectEvictions` (single source of
 *  the grouping rule) and by the opt-in consolidation summarizer. */
export interface ConsolidationGroup {
  key: string;
  classification: string;
  subclass: string | null;
  source: string;
  /** Ranked importance-desc; index 0 is the kept representative. */
  members: MemoryFinding[];
}

/** Pure, deterministic. Return the consolidation groups (group-dedup buckets
 *  with ≥2 members) for a tenant's finding population, ranked. This is the
 *  SINGLE source of the Pass-1 grouping rule; `selectEvictions` consumes it to
 *  build its evict set and the summarizer consumes it to know what collapsed.
 *  Eligibility mirrors Pass 1: floor findings (critical+open) are excluded and
 *  only consolidatable findings (closed OR aged past one half-life) participate. */
export function consolidationGroups(
  findings: readonly MemoryFinding[],
  policy: MemoryPolicy,
  now: number,
): ConsolidationGroup[] {
  const imp = new Map<string, number>();
  for (const f of findings) imp.set(f.id, computeImportance(f, now, policy));
  const byImportanceDesc = (a: MemoryFinding, b: MemoryFinding): number =>
    (imp.get(b.id) ?? 0) - (imp.get(a.id) ?? 0) || a.id.localeCompare(b.id);

  const buckets = new Map<string, MemoryFinding[]>();
  for (const f of findings) {
    if (isFloor(f)) continue;
    if (!isConsolidatable(f, now, policy)) continue;
    const key = groupKey(f);
    const bucket = buckets.get(key);
    if (bucket) bucket.push(f);
    else buckets.set(key, [f]);
  }

  const groups: ConsolidationGroup[] = [];
  for (const [key, bucket] of buckets) {
    if (bucket.length <= 1) continue;
    const members = [...bucket].sort(byImportanceDesc);
    const rep = members[0];
    groups.push({
      key,
      classification: rep.classification,
      subclass: rep.subclass,
      source: rep.source,
      members,
    });
  }
  return groups;
}

/** Pure, deterministic. Given a tenant's full finding population, return the
 *  set of finding ids whose embedding should NOT exist (evict if present, don't
 *  create if absent). This is the SINGLE eligibility oracle shared by eviction
 *  and `backfillEmbeddings`.
 *
 *  Order of operations:
 *    1. group-dedup among consolidatable, non-floor findings (keep the highest-
 *       importance representative per (classification, subclass, source));
 *    2. count cap on the survivors (excluding floor findings, which are always
 *       kept): keep the top (maxPerTenant − floorCount) by importance;
 *    3. floor override: critical+open findings are removed from the evict set
 *       unconditionally (defensive — they are excluded from both passes above).
 *
 *  Ties break by `id` ascending so the selection is fully reproducible.
 */
export function selectEvictions(
  findings: readonly MemoryFinding[],
  policy: MemoryPolicy,
  now: number,
): Set<string> {
  const evict = new Set<string>();

  // Precompute importance once (sorts below reference it repeatedly).
  const imp = new Map<string, number>();
  for (const f of findings) imp.set(f.id, computeImportance(f, now, policy));
  const byImportanceDesc = (a: MemoryFinding, b: MemoryFinding): number =>
    (imp.get(b.id) ?? 0) - (imp.get(a.id) ?? 0) || a.id.localeCompare(b.id);

  // Pass 1 — consolidation (group-dedup). `consolidationGroups` is the single
  // source of the grouping rule; here we evict every non-representative member
  // (members are already ranked importance-desc, so index 0 is kept).
  for (const group of consolidationGroups(findings, policy, now)) {
    for (let i = 1; i < group.members.length; i++) {
      evict.add(group.members[i].id);
    }
  }

  // Pass 2 — count cap on the post-consolidation survivors. Floor findings are
  // always kept and consume cap budget so the cap reflects total rows kept.
  const floorCount = findings.filter(isFloor).length;
  const budget = Math.max(0, policy.maxPerTenant - floorCount);
  const survivors = findings.filter((f) => !evict.has(f.id) && !isFloor(f));
  if (survivors.length > budget) {
    const ranked = [...survivors].sort(byImportanceDesc);
    for (let i = budget; i < ranked.length; i++) evict.add(ranked[i].id);
  }

  // Pass 3 — floor override (defensive; floor findings were excluded above).
  for (const f of findings) if (isFloor(f) && evict.has(f.id)) evict.delete(f.id);

  return evict;
}

// ---------------------------------------------------------------------------
// Core eviction (testable, dependency-injected)
// ---------------------------------------------------------------------------

export interface EvictMemoryDeps {
  policy: MemoryPolicy;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
}

export interface EvictMemoryResult {
  /** Findings examined across all tenants. */
  scanned: number;
  /** Embedding rows deleted. */
  evicted: number;
  /** Tenants whose eviction errored (embeddings left intact, retried later). */
  failed: number;
}

interface MemoryRow {
  id: string;
  classification: string;
  subclass: string | null;
  severity: string;
  status: string;
  source: string;
  last_seen_ms: number | string;
  occurrence_count: number | string;
  has_embedding: boolean;
  [key: string]: unknown;
}

/** Run one eviction sweep across all tenants. Per-tenant scan mirrors
 *  `backfillEmbeddings`: enumerate tenants, then operate inside `withTenant()`
 *  so RLS stays enforced for every read + delete. Read + compute + delete share
 *  one transaction so the decision is consistent with the deleted rows. */
export async function evictMemoryOnce(
  deps: EvictMemoryDeps,
): Promise<EvictMemoryResult> {
  const { policy } = deps;
  const now = deps.now ?? Date.now;
  const result: EvictMemoryResult = { scanned: 0, evicted: 0, failed: 0 };

  const tenantRows = await db.execute<{ tenant_id: string }>(
    sql`SELECT DISTINCT tenant_id FROM findings`,
  );

  for (const { tenant_id } of tenantRows.rows) {
    try {
      const { deleted, scanned } = await withTenant(tenant_id, async (tx) => {
        const rows = await tx.execute<MemoryRow>(sql`
          SELECT
            f.id,
            f.classification,
            f.subclass,
            f.severity,
            f.status,
            f.source,
            extract(epoch FROM f.last_seen_at) * 1000 AS last_seen_ms,
            f.occurrence_count,
            (fe.finding_id IS NOT NULL) AS has_embedding
          FROM findings f
          LEFT JOIN finding_embeddings fe ON fe.finding_id = f.id
          WHERE f.tenant_id = ${tenant_id}
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
        const hasEmbedding = new Set(
          rows.rows.filter((r) => r.has_embedding).map((r) => r.id),
        );

        const evict = selectEvictions(findings, policy, now());
        // Only embeddings that actually exist can be deleted; an ineligible
        // finding with no cached row is handled by backfill (it won't create
        // one) — nothing to do here.
        const toDelete = [...evict].filter((id) => hasEmbedding.has(id));
        if (toDelete.length === 0) {
          return { deleted: 0, scanned: findings.length };
        }

        // Build the IN list as individual bound params. A JS array interpolated
        // into `= ANY(${ids})` fails at runtime in drizzle (replit.md gotcha),
        // so join per-id `${id}` chunks instead.
        const idList = sql.join(
          toDelete.map((id) => sql`${id}`),
          sql`, `,
        );
        // Defense-in-depth floor guard at DELETE time. `selectEvictions`
        // already excludes critical+open, but under READ COMMITTED a concurrent
        // transaction could flip a finding to critical+open after our SELECT and
        // before this DELETE. Re-checking the live finding row in the same
        // statement makes it impossible to evict a floor-protected embedding,
        // regardless of interleaving.
        const del = await tx.execute(sql`
          DELETE FROM finding_embeddings fe
          USING findings f
          WHERE fe.tenant_id = ${tenant_id}
            AND f.id = fe.finding_id
            AND fe.finding_id IN (${idList})
            AND NOT (f.severity = 'critical' AND f.status = 'open')
        `);
        return { deleted: del.rowCount ?? 0, scanned: findings.length };
      });

      result.scanned += scanned;
      result.evicted += deleted;

      if (deleted > 0) {
        await appendLedger({
          tenantId: tenant_id,
          actor: { kind: "system", id: "memory_eviction" },
          eventType: "memory.evicted",
          subjectType: "memory",
          // Counts + policy params ONLY. No finding ids, no snippets, no PHI.
          payload: {
            evicted: deleted,
            scanned,
            max_per_tenant: policy.maxPerTenant,
            half_life_days: policy.halfLifeDays,
          },
        });
      }
    } catch (err) {
      result.failed++;
      const errorName = err instanceof Error ? err.name : "unknown";
      logger.error(
        { error_name: errorName, tenant_id },
        "memory eviction failed for tenant; embeddings left intact, will retry next cadence",
      );
      await appendLedger({
        tenantId: tenant_id,
        actor: { kind: "system", id: "memory_eviction" },
        eventType: "memory.evict_failed",
        subjectType: "memory",
        // error NAME only — never the raw err (SDK/DB errors can embed values).
        payload: {
          error: errorName,
          max_per_tenant: policy.maxPerTenant,
          half_life_days: policy.halfLifeDays,
        },
      });
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Leader lock + scheduler
// ---------------------------------------------------------------------------
//
// Dedicated advisory-lock key, distinct from the ledger writer (…_0001n), the
// chain-verifier keys, and the raw-evidence tiering key (…_0013n). Same
// pool-checkout discipline as tiering: hold one connection across try-lock → fn
// → unlock so the pool can't hand the unlock to a connection that never owned
// the lock.
const MEMORY_EVICT_LOCK_KEY = 7331_4242_0000_0014n;

async function withLeaderLock<T>(fn: () => Promise<T>): Promise<T | "skipped"> {
  const client = await pool.connect();
  let unlockFailed: Error | null = null;
  try {
    const got = await client.query<{ got: boolean }>(
      "SELECT pg_try_advisory_lock($1::bigint) AS got",
      [MEMORY_EVICT_LOCK_KEY.toString()],
    );
    if (!got.rows[0]?.got) {
      logger.debug("memory eviction skipped — leader lock held elsewhere");
      return "skipped";
    }
    try {
      return await fn();
    } finally {
      try {
        await client.query("SELECT pg_advisory_unlock($1::bigint)", [
          MEMORY_EVICT_LOCK_KEY.toString(),
        ]);
      } catch (err) {
        unlockFailed = err as Error;
        logger.warn(
          { err },
          "failed to release memory eviction advisory lock; destroying pool client to avoid leaked session lock",
        );
      }
    }
  } finally {
    client.release(unlockFailed ?? undefined);
  }
}

async function runEvictOnce(
  policy: MemoryPolicy,
  summaryPolicy?: SummaryPolicy | null,
): Promise<void> {
  await withLeaderLock(async () => {
    try {
      const r = await evictMemoryOnce({ policy });
      if (r.evicted > 0 || r.failed > 0) {
        logger.info(r, "memory eviction run complete");
      } else {
        logger.debug(r, "memory eviction run complete (nothing to evict)");
      }
    } catch (err) {
      logger.error({ err }, "memory eviction run failed");
    }

    // Opt-in LLM consolidation summaries run in the SAME sweep, under the SAME
    // leader lock, right after eviction. Lazy import keeps the module graph
    // acyclic and loads nothing when the feature is off.
    if (summaryPolicy) {
      try {
        const { summarizeConsolidationsOnce } = await import(
          "./memory-summarizer"
        );
        const s = await summarizeConsolidationsOnce({
          memoryPolicy: policy,
          summaryPolicy,
        });
        if (s.summarized > 0 || s.failed > 0) {
          logger.info(s, "memory consolidation summarization complete");
        } else {
          logger.debug(
            s,
            "memory consolidation summarization complete (nothing new)",
          );
        }
      } catch (err) {
        logger.error({ err }, "memory consolidation summarization run failed");
      }
    }
  });
}

/** Start the periodic memory-eviction job. Returns a stop() handle.
 *
 *  Default-INERT: returns a no-op stop() (and schedules nothing) unless the
 *  opt-in `MEMORY_MAX_EMBEDDINGS_PER_TENANT` is set. `cfgOverride` is for tests;
 *  `undefined` reads env, explicit `null` forces disabled. */
export function startMemoryEviction(
  cfgOverride?: MemoryPolicy | null,
  summaryPolicy?: SummaryPolicy | null,
): () => void {
  const policy =
    cfgOverride === undefined ? getMemoryPolicyFromEnv() : cfgOverride;
  if (!policy) {
    logger.info(
      "memory eviction disabled (MEMORY_MAX_EMBEDDINGS_PER_TENANT unset)",
    );
    return () => {};
  }

  const timer = setInterval(
    () => void runEvictOnce(policy, summaryPolicy),
    policy.intervalMs,
  );
  timer.unref?.();
  logger.info(
    {
      maxPerTenant: policy.maxPerTenant,
      halfLifeDays: policy.halfLifeDays,
      intervalMs: policy.intervalMs,
      consolidationSummaries: summaryPolicy ? "on" : "off",
    },
    "memory eviction scheduled",
  );
  return () => clearInterval(timer);
}

// Exported for direct testing without spinning up setInterval.
export const __test__ = {
  withLeaderLock,
  runEvictOnce,
  isConsolidatable,
  isFloor,
  MEMORY_EVICT_LOCK_KEY,
};
