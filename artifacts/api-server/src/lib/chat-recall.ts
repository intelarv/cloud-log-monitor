// M19 — Semantic memory recall for the chat agent (opt-in
// CHAT_MEMORY_SEMANTIC_RECALL). DB + embedding glue around the pure
// assembleRecallWindow helper in chat-memory.ts.
//
// Write path: after a chat message is persisted, embed its (already-PHI-safe)
// content and upsert one row into chat_message_embeddings, tagged with the
// current embedder version.
// Read path: embed the current user query and cosine-rank the session's prior
// messages, returning the ids of the most-relevant ones (current embedder
// version only — mixing dims/embedders would degrade ranking).
//
// PHI posture: chat_messages.content is already safe (input refused / output
// scanned before persistence), and the shared embedder is PhiGuard-wrapped, so
// no raw PHI reaches the vector tier. Both paths are best-effort callers'
// concern — recall must never break a chat turn; callers wrap in try/catch and
// fall back to the recency window.

import { sql } from "drizzle-orm";

import { withTenant } from "./db-context";
import { toPgVectorLiteral, type Embedder } from "./embeddings";
import { getEmbedder } from "./embedder-config";
import { isChatEmbeddingsPartitioned } from "./embeddings-partition-config";
import {
  rrfFuse,
  type RetrievalHit,
  type RetrieverSource,
} from "./search";

/**
 * Embed a single chat message and upsert it into chat_message_embeddings.
 * Idempotent on message_id. The embedder defaults to the boot-initialized
 * shared instance; tests inject one explicitly.
 */
export async function embedAndStoreChatMessage(args: {
  tenantId: string;
  sessionId: string;
  messageId: string;
  content: string;
  embedder?: Embedder;
}): Promise<void> {
  const embedder = args.embedder ?? getEmbedder();
  const vec = await embedder.embed(args.content);
  const literal = toPgVectorLiteral(vec);
  // The single-table layout has PK (message_id); the LIST-partitioned layout
  // (CHAT_EMBEDDINGS_TENANT_PARTITIONING) has composite PK (message_id,
  // tenant_id) — a partitioned table cannot have a unique index on message_id
  // alone. message_id is globally unique 1:1 with chat_messages, so the two
  // arbiters are semantically equivalent; only the index Postgres can infer
  // differs.
  const conflictTarget = isChatEmbeddingsPartitioned()
    ? sql`(message_id, tenant_id)`
    : sql`(message_id)`;
  await withTenant(args.tenantId, async (tx) => {
    await tx.execute(sql`
      INSERT INTO chat_message_embeddings (message_id, session_id, tenant_id, embedding, embedder_version, updated_at)
      VALUES (${args.messageId}, ${args.sessionId}, ${args.tenantId}, ${literal}::vector, ${embedder.version}, now())
      ON CONFLICT ${conflictTarget} DO UPDATE
        SET session_id = EXCLUDED.session_id,
            embedding = EXCLUDED.embedding,
            embedder_version = EXCLUDED.embedder_version,
            updated_at = now()
    `);
  });
}

/**
 * Return the ids of the `k` prior messages in this session most semantically
 * similar to `query`, nearest first. Scoped to (tenant, session) and to the
 * CURRENT embedder version so stale-version rows (embedded under a different
 * provider/dim) are never mixed in. Returns [] when nothing is embedded yet —
 * the caller falls back to the recency window.
 */
export async function semanticRecallMessageIds(args: {
  tenantId: string;
  sessionId: string;
  query: string;
  k: number;
  embedder?: Embedder;
}): Promise<string[]> {
  if (args.k <= 0 || args.query.trim() === "") return [];
  const embedder = args.embedder ?? getEmbedder();
  const vec = await embedder.embed(args.query);
  const literal = toPgVectorLiteral(vec);
  return withTenant(args.tenantId, async (tx) => {
    // `<=>` is cosine distance (0 = identical). Stable secondary sort on
    // message_id so identical-distance rows (common with the dev embedder) get
    // a deterministic order.
    const rows = await tx.execute<{ id: string }>(sql`
      SELECT cme.message_id AS id
      FROM chat_message_embeddings cme
      WHERE cme.tenant_id = ${args.tenantId}
        AND cme.session_id = ${args.sessionId}
        AND cme.embedder_version = ${embedder.version}
      ORDER BY cme.embedding <=> ${literal}::vector, cme.message_id
      LIMIT ${args.k}
    `);
    return rows.rows.map((r) => r.id);
  });
}

/**
 * Lexical (BM25/FTS) leg of hybrid chat recall. Return the ids of the `k` prior
 * messages in this session whose content best matches `query` under Postgres
 * full-text ranking (`ts_rank_cd` over the generated `search_tsv` column),
 * best-match first. Scoped to (tenant, session) and RLS-isolated. Returns []
 * for an empty/no-match query — the caller falls back to the recency window.
 *
 * Mirrors `PostgresLexicalSearchProvider` (search-config.ts) but over
 * chat_messages instead of findings.
 */
export async function lexicalRecallMessageIds(args: {
  tenantId: string;
  sessionId: string;
  query: string;
  k: number;
}): Promise<string[]> {
  if (args.k <= 0 || args.query.trim() === "") return [];
  return withTenant(args.tenantId, async (tx) => {
    const rows = await tx.execute<{ id: string }>(sql`
      SELECT id
      FROM chat_messages
      WHERE tenant_id = ${args.tenantId}
        AND session_id = ${args.sessionId}
        AND search_tsv @@ websearch_to_tsquery('english', ${args.query})
      ORDER BY ts_rank_cd(search_tsv, websearch_to_tsquery('english', ${args.query})) DESC,
               created_at DESC,
               id
      LIMIT ${args.k}
    `);
    return rows.rows.map((r) => r.id);
  });
}

/**
 * Hybrid chat recall (opt-in CHAT_MEMORY_HYBRID_RECALL): run the dense (vector)
 * and lexical (BM25) legs over the session's prior messages and fuse their
 * rankings with Reciprocal Rank Fusion (the same `rrfFuse` the findings
 * retriever uses), returning the top-`k` fused message ids.
 *
 * The two legs run concurrently and independently; either returning [] (e.g.
 * nothing embedded yet, or no lexical match) just leaves that leg out of the
 * fusion. Returns [] only when BOTH legs are empty, so the caller falls back to
 * the recency window. `rrfFuse` is keyed on a generic id string (its field is
 * named `finding_id` for the findings retriever; here it carries a message id).
 */
export async function hybridRecallMessageIds(args: {
  tenantId: string;
  sessionId: string;
  query: string;
  k: number;
  embedder?: Embedder;
}): Promise<string[]> {
  if (args.k <= 0 || args.query.trim() === "") return [];
  const [vec, lex] = await Promise.all([
    semanticRecallMessageIds(args),
    lexicalRecallMessageIds({
      tenantId: args.tenantId,
      sessionId: args.sessionId,
      query: args.query,
      k: args.k,
    }),
  ]);
  if (vec.length === 0 && lex.length === 0) return [];

  const toHits = (ids: string[]): RetrievalHit[] =>
    ids.map((id, i) => ({ finding_id: id, rank: i + 1 }));
  const rankings = new Map<RetrieverSource, readonly RetrievalHit[]>([
    ["vector", toHits(vec)],
    ["bm25", toHits(lex)],
  ]);
  return rrfFuse(rankings)
    .slice(0, args.k)
    .map((h) => h.finding_id);
}
