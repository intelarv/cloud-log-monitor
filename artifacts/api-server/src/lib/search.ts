import { and, eq, inArray, sql } from "drizzle-orm";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
type Finding = FindingSafe;
import { withTenant } from "./db-context";
import { toPgVectorLiteral, type Embedder } from "./embeddings";
import { getEmbedder } from "./embedder-config";

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

async function bm25Search(
  tenantId: string,
  query: string,
  limit: number,
): Promise<RetrievalHit[]> {
  return withTenant(tenantId, async (tx) => {
    // `websearch_to_tsquery` parses Google-style queries; empty/no-match
    // queries return zero rows rather than erroring.
    const rows = await tx.execute<{ id: string }>(sql`
      SELECT id
      FROM findings
      WHERE tenant_id = ${tenantId}
        AND search_tsv @@ websearch_to_tsquery('english', ${query})
      ORDER BY ts_rank_cd(search_tsv, websearch_to_tsquery('english', ${query})) DESC,
               last_seen_at DESC,
               id
      LIMIT ${limit}
    `);
    return rows.rows.map((r, i) => ({ finding_id: r.id, rank: i + 1 }));
  });
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
  } = {},
): Promise<HybridSearchResult> {
  const topK = opts.topK ?? 10;
  const perRetrieverLimit = opts.perRetrieverLimit ?? 20;
  const embedder = opts.embedder ?? getEmbedder();

  const embedding = await embedder.embed(query);

  const [bm25, vec] = await Promise.all([
    bm25Search(tenantId, query, perRetrieverLimit),
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
} = {}): Promise<{ inserted: number; updated: number; skipped: number }> {
  const embedder = opts.embedder ?? getEmbedder();
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
        source: string;
        snippet: string | null;
        existing_version: string | null;
      }>(sql`
        SELECT
          f.id,
          f.classification,
          f.subclass,
          f.severity,
          f.source,
          f.redacted_evidence->>'snippet' AS snippet,
          fe.embedder_version AS existing_version
        FROM findings f
        LEFT JOIN finding_embeddings fe ON fe.finding_id = f.id
        WHERE f.tenant_id = ${tenant_id}
      `);

      for (const row of rows.rows) {
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
        await tx.execute(sql`
          INSERT INTO finding_embeddings (finding_id, tenant_id, content, embedding, embedder_version, updated_at)
          VALUES (${row.id}, ${tenant_id}, ${content}, ${literal}::vector, ${embedder.version}, now())
          ON CONFLICT (finding_id) DO UPDATE
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
