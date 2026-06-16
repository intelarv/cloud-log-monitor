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
  await withTenant(args.tenantId, async (tx) => {
    await tx.execute(sql`
      INSERT INTO chat_message_embeddings (message_id, session_id, tenant_id, embedding, embedder_version, updated_at)
      VALUES (${args.messageId}, ${args.sessionId}, ${args.tenantId}, ${literal}::vector, ${embedder.version}, now())
      ON CONFLICT (message_id) DO UPDATE
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
