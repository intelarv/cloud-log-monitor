import { and, eq, inArray, sql } from "drizzle-orm";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
type Finding = FindingSafe;
import { withTenant } from "./db-context";
import { toPgVectorLiteral, type Embedder } from "./embeddings";
import { getEmbedder } from "./embedder-config";
import { isEmbeddingsPartitioned } from "./embeddings-partition-config";
import {
  getSearchProvider,
  type LexicalSearchProvider,
} from "./search-config";
import {
  getMemoryPolicyFromEnv,
  selectEvictions,
  type MemoryFinding,
  type MemoryPolicy,
} from "./memory-eviction";
import { logger } from "./logger";

// ---------------------------------------------------------------------------
// Hybrid retrieval over findings
// ---------------------------------------------------------------------------
//
// Two retrievers run in parallel and their per-document ranks are fused with
// Reciprocal Rank Fusion (Cormack & Lynam, 2009). RRF is parameter-light, has
// no need for score normalization, and is the standard choice when fusing
// BM25 + dense retrieval.
//
//   - BM25 / FTS: Postgres `tsvector` + `ts_rank_cd` over the generated
//     `search_tsv` column on findings. Lexical, exact-token matches.
//   - Vector: pgvector cosine distance against `finding_embeddings.embedding`.
//     Sub-word / fuzzy-token overlap with the M1 dev embedder; semantic
//     similarity when the production embedder is wired.
//
// Both retrievers run inside `withTenant(...)` so Postgres RLS isolates the
// caller's tenant — search cannot leak across tenants regardless of any bug
// in this file (threat_model.md §Info Disclosure).
//
// All retrieved rows are projections of the `findings_redacted` view's
// columns; this code never selects raw evidence (none exists in M1, but the
// shape is enforced).

const RRF_K = 60 as const; // Standard RRF smoothing constant.

export type RetrieverSource = "bm25" | "vector";

export interface RetrievalHit {
  finding_id: string;
  rank: number; // 1-based.
}

export interface FusedHit {
  finding_id: string;
  score: number;
  sources: RetrieverSource[];
}

/**
 * Reciprocal Rank Fusion. Pure function; no DB, no I/O. Tested directly.
 *
 * `rankings` is a map from source name to that source's ordered hit list
 * (rank-1 first). Returns the fused list sorted by descending score.
 *
 * Score formula: `score(d) = Σ_r 1 / (k + rank_r(d))` over retrievers `r`
 * where `d` appears.
 */
export function rrfFuse(
  rankings: ReadonlyMap<RetrieverSource, readonly RetrievalHit[]>,
  k: number = RRF_K,
): FusedHit[] {
  const acc = new Map<string, { score: number; sources: Set<RetrieverSource> }>();
  for (const [source, hits] of rankings) {
    for (const hit of hits) {
      const cur = acc.get(hit.finding_id) ?? {
        score: 0,
        sources: new Set<RetrieverSource>(),
      };
      cur.score += 1 / (k + hit.rank);
      cur.sources.add(source);
      acc.set(hit.finding_id, cur);
    }
  }
  return Array.from(acc.entries())
    .map(([finding_id, v]) => ({
      finding_id,
      score: v.score,
      sources: Array.from(v.sources).sort(),
    }))
    .sort((a, b) => b.score - a.score || a.finding_id.localeCompare(b.finding_id));
}

async function vectorSearch(
  tenantId: string,
  embedding: readonly number[],
  limit: number,
): Promise<RetrievalHit[]> {
  const literal = toPgVectorLiteral(embedding);
  return withTenant(tenantId, async (tx) => {
    // `<=>` is cosine distance in pgvector (0 = identical, 2 = opposite).
    // We cast the literal explicitly so the driver doesn't have to guess.
    // Stable secondary sort on finding_id so identical-distance rows (common
    // in tiny corpora and possible with the dev embedder) get a deterministic
    // rank — RRF fusion needs stable per-retriever ranks to be reproducible.
    const rows = await tx.execute<{ id: string }>(sql`
      SELECT fe.finding_id AS id
      FROM finding_embeddings fe
      WHERE fe.tenant_id = ${tenantId}
      ORDER BY fe.embedding <=> ${literal}::vector, fe.finding_id
      LIMIT ${limit}
    `);
    return rows.rows.map((r, i) => ({ finding_id: r.id, rank: i + 1 }));
  });
}

export interface HybridSearchResult {
  fused: FusedHit[];
  findings: Finding[]; // Hydrated rows in fused order.
}

/**
 * Run BM25 + vector retrieval in parallel, fuse with RRF, and hydrate the
 * top results from the findings table (RLS-scoped).
 *
 * `perRetrieverLimit` bounds each retriever; the fused list is then capped
 * at `topK`. Defaults err small so the model context stays cheap.
 */
export async function hybridSearchFindings(
  tenantId: string,
  query: string,
  opts: {
    topK?: number;
    perRetrieverLimit?: number;
    embedder?: Embedder;
    searchProvider?: LexicalSearchProvider;
  } = {},
): Promise<HybridSearchResult> {
  const topK = opts.topK ?? 10;
  const perRetrieverLimit = opts.perRetrieverLimit ?? 20;
  const embedder = opts.embedder ?? getEmbedder();
  const lexical = opts.searchProvider ?? getSearchProvider();

  const embedding = await embedder.embed(query);

  // The lexical leg is allowed to degrade. A managed search backend
  // (OpenSearch) is a separate failure domain from Postgres; if it is down or
  // slow, retrieval falls back to the vector leg rather than failing the whole
  // chat turn. The Postgres lexical provider shares the DB connection, so its
  // failures are effectively DB failures and the vector leg would fail too —
  // this fallback only meaningfully kicks in for external providers.
  const [bm25, vec] = await Promise.all([
    lexical.search(tenantId, query, perRetrieverLimit).catch((err) => {
      logger.warn(
        { err, provider: lexical.name, tenant_id: tenantId },
        "lexical search leg failed; degrading to vector-only retrieval",
      );
      return [] as readonly RetrievalHit[];
    }),
    vectorSearch(tenantId, embedding, perRetrieverLimit),
  ]);

  const fused = rrfFuse(
    new Map<RetrieverSource, readonly RetrievalHit[]>([
      ["bm25", bm25],
      ["vector", vec],
    ]),
  ).slice(0, topK);

  if (fused.length === 0) return { fused, findings: [] };

  // Hydrate. We re-query under tenant context (RLS-checked) so even if the
  // ID list were tampered with at the search layer, cross-tenant reads would
  // be blocked by the policy.
  const ids = fused.map((f) => f.finding_id);
  const findings = await withTenant(tenantId, async (tx) => {
    // M1.6: safe projection — search results flow into agent prompts.
    const rows = await tx
      .select(findingSafeColumns)
      .from(findingsTable)
      .where(
        and(eq(findingsTable.tenantId, tenantId), inArray(findingsTable.id, ids)),
      );
    // Preserve fused order.
    const byId = new Map(rows.map((r) => [r.id, r] as const));
    return fused
      .map((f) => byId.get(f.finding_id))
      .filter((r): r is Finding => r != null);
  });

  return { fused, findings };
}

// ---------------------------------------------------------------------------
// Embedding backfill
// ---------------------------------------------------------------------------
//
// Called at boot after `bootstrap()`. Ensures every finding has an embedding
// row. Idempotent: existing rows whose `embedder_version` matches the current
// embedder are skipped; mismatched rows are re-embedded (so swapping the
// embedder triggers a one-time re-index).
//
// Embeds **only the redacted snippet + structural metadata** — never raw
// evidence (there is none in M1, but the contract holds going forward).
export async function backfillEmbeddings(opts: {
  embedder?: Embedder;
  /** Memory-eviction policy. Shared eligibility oracle with the eviction job:
   *  when a policy is active, an embedding is NOT created for any finding the
   *  policy would immediately evict — otherwise boot backfill would just
   *  recreate what the last eviction removed (recreate thrash). `undefined`
   *  reads env (default-inert), explicit `null` disables the gate entirely so
   *  the path is byte-identical to the pre-eviction behavior. */
  memoryPolicy?: MemoryPolicy | null;
} = {}): Promise<{ inserted: number; updated: number; skipped: number }> {
  const embedder = opts.embedder ?? getEmbedder();
  const policy =
    opts.memoryPolicy === undefined ? getMemoryPolicyFromEnv() : opts.memoryPolicy;
  const now = Date.now();
  const result = { inserted: 0, updated: 0, skipped: 0 };

  // We list all tenants present in findings, then re-enter RLS context per
  // tenant. (M1 has one tenant; the loop generalizes cleanly.)
  const { db } = await import("@workspace/db");
  const tenantRows = await db.execute<{ tenant_id: string }>(
    sql`SELECT DISTINCT tenant_id FROM findings`,
  );

  for (const { tenant_id } of tenantRows.rows) {
    await withTenant(tenant_id, async (tx) => {
      const rows = await tx.execute<{
        id: string;
        classification: string;
        subclass: string | null;
        severity: string;
        status: string;
        source: string;
        snippet: string | null;
        last_seen_ms: number | string;
        occurrence_count: number | string;
        existing_version: string | null;
      }>(sql`
        SELECT
          f.id,
          f.classification,
          f.subclass,
          f.severity,
          f.status,
          f.source,
          f.redacted_evidence->>'snippet' AS snippet,
          extract(epoch FROM f.last_seen_at) * 1000 AS last_seen_ms,
          f.occurrence_count,
          fe.embedder_version AS existing_version
        FROM findings f
        LEFT JOIN finding_embeddings fe ON fe.finding_id = f.id
        WHERE f.tenant_id = ${tenant_id}
      `);

      // When a memory policy is active, compute the evict set over the tenant's
      // full finding population FIRST, then skip creating embeddings for any
      // ineligible finding. Checked BEFORE the version check so a stale-version
      // ineligible row is not re-embedded only to be evicted next cadence.
      const evictSet = policy
        ? selectEvictions(
            rows.rows.map(
              (r): MemoryFinding => ({
                id: r.id,
                classification: r.classification,
                subclass: r.subclass,
                source: r.source,
                severity: r.severity,
                status: r.status,
                lastSeenAtMs: Number(r.last_seen_ms),
                occurrenceCount: Number(r.occurrence_count),
              }),
            ),
            policy,
            now,
          )
        : null;

      for (const row of rows.rows) {
        if (evictSet && evictSet.has(row.id)) {
          result.skipped += 1;
          continue;
        }
        if (row.existing_version === embedder.version) {
          result.skipped += 1;
          continue;
        }
        // Compose the embedding text from redacted-only fields.
        const parts = [
          row.classification,
          row.subclass ?? "",
          row.severity,
          row.source,
          row.snippet ?? "",
        ];
        const content = parts.filter(Boolean).join(" \n ");
        const vec = await embedder.embed(content);
        const literal = toPgVectorLiteral(vec);
        // M12.2: the ON CONFLICT arbiter must match the live primary key. The
        // single-table layout has PK (finding_id); the LIST-partitioned layout
        // (EMBEDDINGS_TENANT_PARTITIONING) has composite PK (finding_id,
        // tenant_id) — a partitioned table cannot have a unique index on
        // finding_id alone. finding_id is globally unique 1:1 with findings, so
        // the two arbiters are semantically equivalent; only the index Postgres
        // can infer differs.
        const conflictTarget = isEmbeddingsPartitioned()
          ? sql`(finding_id, tenant_id)`
          : sql`(finding_id)`;
        await tx.execute(sql`
          INSERT INTO finding_embeddings (finding_id, tenant_id, content, embedding, embedder_version, updated_at)
          VALUES (${row.id}, ${tenant_id}, ${content}, ${literal}::vector, ${embedder.version}, now())
          ON CONFLICT ${conflictTarget} DO UPDATE
            SET content = EXCLUDED.content,
                embedding = EXCLUDED.embedding,
                embedder_version = EXCLUDED.embedder_version,
                updated_at = now()
        `);
        if (row.existing_version == null) result.inserted += 1;
        else result.updated += 1;
      }
    });
  }
  return result;
}

// ---------------------------------------------------------------------------
// External lexical-index reconciliation
// ---------------------------------------------------------------------------
//
// Called at boot after the embedding backfill. When the active lexical
// provider maintains its own external index (OpenSearch), this bulk-mirrors
// every existing finding's REDACTED safe projection into that index so a
// freshly-pointed cluster (or one that missed mid-run writes) converges.
// For the Postgres provider it is a no-op (the generated tsv is always in
// sync). Reads go through the safe projection — raw evidence is never read
// here, so PHI cannot reach the searchable tier.
const DEFAULT_REINDEX_BATCH_SIZE = 500;
const REINDEX_BATCH_MIN = 1;
const REINDEX_BATCH_MAX = 10000;

/** Resolve the reindex page size from `SEARCH_REINDEX_BATCH_SIZE`, clamped to a
 *  sane range. Misconfigured (blank / non-numeric / out-of-range) values fall
 *  back to the default rather than picking a pathological page size. */
export function resolveReindexBatchSize(
  env: NodeJS.ProcessEnv = process.env,
): number {
  const raw = env["SEARCH_REINDEX_BATCH_SIZE"]?.trim();
  if (!raw) return DEFAULT_REINDEX_BATCH_SIZE;
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    return DEFAULT_REINDEX_BATCH_SIZE;
  }
  if (n < REINDEX_BATCH_MIN || n > REINDEX_BATCH_MAX) {
    return DEFAULT_REINDEX_BATCH_SIZE;
  }
  return n;
}

export interface ReconcileSearchIndexOpts {
  searchProvider?: LexicalSearchProvider;
  /** Page size for the keyset scan + bulk mirror. Defaults to
   *  `SEARCH_REINDEX_BATCH_SIZE` (resolved via `resolveReindexBatchSize`). */
  batchSize?: number;
  /** Resume point from a prior interrupted run's last progress line. The scan
   *  processes tenants in a deterministic order (tenant_id ascending) and, within
   *  each tenant, findings ordered by id — so a resume point is the tenant the
   *  previous run was working on plus the last finding id it mirrored within that
   *  tenant. On resume the scan skips every tenant ordered BEFORE `tenantId`
   *  (already fully processed), continues `tenantId` at `id > sinceId`, and
   *  processes every later tenant from its start. Omit for a full reindex.
   *
   *  A single global id is intentionally NOT used: tenants are visited in
   *  tenant_id order, not id order, so a global `id > X` filter would both
   *  re-mirror earlier tenants' rows above X and (worse) skip a later tenant
   *  whose ids all fall below X, leaving those findings unsearchable. */
  resumeFrom?: { tenantId: string; sinceId: string };
  /** Per-batch progress callback (operator command uses it to print progress). */
  onProgress?: (p: {
    tenantId: string;
    indexed: number;
    lastId: string;
  }) => void;
}

// Decide, for a deterministic tenant processing order, each tenant's starting
// keyset cursor given an optional resume point. Pure + side-effect-free so the
// resume semantics can be unit-tested without a DB. Tenants must be passed in
// the same order the scan visits them (tenant_id ascending). With no resume
// point every tenant starts from the top (cursor null). With a resume point,
// tenants ordered before the resume tenant are dropped (already fully
// processed), the resume tenant continues at `id > sinceId`, and every later
// tenant starts from the top. If the resume tenant is absent from the list
// (e.g. deleted between runs) nothing is returned — the caller logs a warning.
export function planReindexResume(
  orderedTenantIds: ReadonlyArray<string>,
  resumeFrom?: { tenantId: string; sinceId: string } | null,
): Array<{ tenantId: string; cursor: string | null }> {
  if (!resumeFrom) {
    return orderedTenantIds.map((tenantId) => ({ tenantId, cursor: null }));
  }
  const out: Array<{ tenantId: string; cursor: string | null }> = [];
  let reached = false;
  for (const tenantId of orderedTenantIds) {
    if (!reached) {
      if (tenantId === resumeFrom.tenantId) {
        reached = true;
        out.push({ tenantId, cursor: resumeFrom.sinceId });
      }
      continue;
    }
    out.push({ tenantId, cursor: null });
  }
  return out;
}

// Reconcile in keyset-paginated batches ordered by finding id. Each batch is
// mirrored in a single bulk round-trip when the provider supports it (falls
// back to per-doc otherwise). Batching keeps memory bounded on large tenants,
// surfaces progress, and — combined with `resumeFrom` — makes an interrupted
// operator reindex resumable. Reads go through the safe projection; raw
// evidence is never read, so PHI cannot reach the searchable tier.
export async function reconcileSearchIndex(
  opts: ReconcileSearchIndexOpts = {},
): Promise<{ indexed: number; skipped: boolean }> {
  const provider = opts.searchProvider ?? getSearchProvider();
  if (!provider.maintainsExternalIndex) return { indexed: 0, skipped: true };

  const batchSize = opts.batchSize ?? resolveReindexBatchSize();
  const { db } = await import("@workspace/db");
  const tenantRows = await db.execute<{ tenant_id: string }>(
    sql`SELECT DISTINCT tenant_id FROM findings ORDER BY tenant_id`,
  );

  const tenantPlan = planReindexResume(
    tenantRows.rows.map((r) => r.tenant_id),
    opts.resumeFrom ?? null,
  );
  if (opts.resumeFrom && tenantPlan.length === 0) {
    logger.warn(
      { provider: provider.name, resumeTenant: opts.resumeFrom.tenantId },
      "Search index reconcile: resume tenant not found among current tenants; " +
        "nothing reindexed",
    );
  }

  let indexed = 0;
  for (const { tenantId: tenant_id, cursor: startCursor } of tenantPlan) {
    // Keyset cursor within this tenant, seeded by the resume plan (sinceId for
    // the resume tenant, null for a from-the-top scan).
    let cursor: string | null = startCursor;
    for (;;) {
      const batch: Array<{
        id: string;
        classification: string;
        subclass: string | null;
        severity: string;
        source: string;
        redactedEvidence: unknown;
      }> = await withTenant(tenant_id, async (tx) => {
        const where =
          cursor === null
            ? eq(findingsTable.tenantId, tenant_id)
            : and(
                eq(findingsTable.tenantId, tenant_id),
                sql`${findingsTable.id} > ${cursor}`,
              );
        return tx
          .select(findingSafeColumns)
          .from(findingsTable)
          .where(where)
          .orderBy(findingsTable.id)
          .limit(batchSize);
      });
      if (batch.length === 0) break;

      const docs = batch.map((r) => {
        const ev = r.redactedEvidence as { snippet?: string };
        return {
          findingId: r.id,
          tenantId: tenant_id,
          classification: r.classification,
          subclass: r.subclass,
          severity: r.severity,
          source: r.source,
          snippet: ev.snippet ?? "",
        };
      });

      if (provider.indexFindingBulk) {
        await provider.indexFindingBulk(docs);
      } else {
        for (const d of docs) await provider.indexFinding(d);
      }

      indexed += docs.length;
      cursor = batch[batch.length - 1]!.id;
      opts.onProgress?.({ tenantId: tenant_id, indexed, lastId: cursor });
      logger.info(
        { provider: provider.name, tenant: tenant_id, indexed, lastId: cursor },
        "Search index reconcile progress",
      );

      if (batch.length < batchSize) break;
    }
  }
  logger.info(
    { provider: provider.name, indexed, batchSize },
    "Search index reconcile complete",
  );
  return { indexed, skipped: false };
}
