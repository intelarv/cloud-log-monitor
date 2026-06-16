import { describe, it, expect, beforeAll } from "vitest";
import { sql } from "drizzle-orm";
import {
  db,
  chatSessionsTable,
  chatMessagesTable,
  bootstrap,
} from "@workspace/db";
import { withTenant } from "./db-context";
import { FeatureHashEmbedder, toPgVectorLiteral } from "./embeddings";
import {
  embedAndStoreChatMessage,
  semanticRecallMessageIds,
} from "./chat-recall";
import { uniq, uniqueTenant } from "../test-support/ledger-harness";

// Offline, credential-free embedder — same one the app defaults to. Dim 256
// matches the chat_message_embeddings vector dim provisioned by bootstrap.
const embedder = new FeatureHashEmbedder({ dim: 256 });

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

/** Seed a chat session and its messages for a fresh tenant. Returns ids. */
async function seedSession(
  tenantId: string,
  messages: Array<{ role: "user" | "assistant"; content: string }>,
): Promise<{ sessionId: string; messageIds: string[] }> {
  const sessionId = `cs_${uniq()}`;
  const messageIds: string[] = [];
  await withTenant(tenantId, async (tx) => {
    await tx.insert(chatSessionsTable).values({
      id: sessionId,
      tenantId,
      userId: `u_${uniq()}`,
    });
    for (const m of messages) {
      const id = `cm_${uniq()}`;
      messageIds.push(id);
      await tx.insert(chatMessagesTable).values({
        id,
        sessionId,
        tenantId,
        role: m.role,
        content: m.content,
        citations: [],
        agentIdentity: null,
      });
    }
  });
  return { sessionId, messageIds };
}

async function countEmbeddings(tenantId: string, messageId: string): Promise<number> {
  return withTenant(tenantId, async (tx) => {
    const r = await tx.execute<{ n: number }>(sql`
      SELECT COUNT(*)::int AS n FROM chat_message_embeddings
      WHERE tenant_id = ${tenantId} AND message_id = ${messageId}
    `);
    return Number(r.rows[0]?.n ?? 0);
  });
}

describe("embedAndStoreChatMessage", () => {
  it("stores one row per message and is idempotent on message_id", async () => {
    const tenantId = uniqueTenant("recall");
    const { sessionId, messageIds } = await seedSession(tenantId, [
      { role: "user", content: "what kms keys are missing" },
    ]);
    const mid = messageIds[0]!;

    await embedAndStoreChatMessage({
      tenantId,
      sessionId,
      messageId: mid,
      content: "what kms keys are missing",
      embedder,
    });
    expect(await countEmbeddings(tenantId, mid)).toBe(1);

    // Re-embedding the same message must upsert, not duplicate.
    await embedAndStoreChatMessage({
      tenantId,
      sessionId,
      messageId: mid,
      content: "what kms keys are missing (edited)",
      embedder,
    });
    expect(await countEmbeddings(tenantId, mid)).toBe(1);
  });
});

describe("semanticRecallMessageIds", () => {
  it("ranks the most semantically-similar prior message first", async () => {
    const tenantId = uniqueTenant("recall");
    const { sessionId, messageIds } = await seedSession(tenantId, [
      { role: "user", content: "tell me about retention policy gaps" },
      { role: "assistant", content: "the weather is sunny and warm today" },
      { role: "user", content: "which log groups lack kms encryption keys" },
    ]);
    for (let i = 0; i < messageIds.length; i++) {
      await embedAndStoreChatMessage({
        tenantId,
        sessionId,
        messageId: messageIds[i]!,
        content: [
          "tell me about retention policy gaps",
          "the weather is sunny and warm today",
          "which log groups lack kms encryption keys",
        ][i]!,
        embedder,
      });
    }

    const ids = await semanticRecallMessageIds({
      tenantId,
      sessionId,
      query: "log groups missing kms encryption keys",
      k: 1,
      embedder,
    });
    expect(ids).toEqual([messageIds[2]]);
  });

  it("returns [] for a non-positive k or an empty query (caller falls back)", async () => {
    const tenantId = uniqueTenant("recall");
    const { sessionId, messageIds } = await seedSession(tenantId, [
      { role: "user", content: "anything" },
    ]);
    await embedAndStoreChatMessage({
      tenantId,
      sessionId,
      messageId: messageIds[0]!,
      content: "anything",
      embedder,
    });
    expect(
      await semanticRecallMessageIds({ tenantId, sessionId, query: "x", k: 0, embedder }),
    ).toEqual([]);
    expect(
      await semanticRecallMessageIds({ tenantId, sessionId, query: "   ", k: 5, embedder }),
    ).toEqual([]);
  });

  it("excludes rows embedded under a different embedder_version", async () => {
    const tenantId = uniqueTenant("recall");
    const { sessionId, messageIds } = await seedSession(tenantId, [
      { role: "user", content: "kms encryption keys missing" },
    ]);
    const mid = messageIds[0]!;
    // Insert a row directly under a STALE embedder version (valid 256-dim vec).
    const staleVec = toPgVectorLiteral(await embedder.embed("kms encryption keys missing"));
    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        INSERT INTO chat_message_embeddings (message_id, session_id, tenant_id, embedding, embedder_version, updated_at)
        VALUES (${mid}, ${sessionId}, ${tenantId}, ${staleVec}::vector, ${"stale-embedder@old:256"}, now())
      `);
    });

    // Current-version recall must not see the stale row.
    const ids = await semanticRecallMessageIds({
      tenantId,
      sessionId,
      query: "kms encryption keys missing",
      k: 5,
      embedder,
    });
    expect(ids).toEqual([]);
  });

  it("is scoped to the (tenant, session) pair", async () => {
    const tenantId = uniqueTenant("recall");
    const a = await seedSession(tenantId, [{ role: "user", content: "session a content" }]);
    const b = await seedSession(tenantId, [{ role: "user", content: "session b content" }]);
    await embedAndStoreChatMessage({
      tenantId,
      sessionId: a.sessionId,
      messageId: a.messageIds[0]!,
      content: "session a content",
      embedder,
    });
    await embedAndStoreChatMessage({
      tenantId,
      sessionId: b.sessionId,
      messageId: b.messageIds[0]!,
      content: "session b content",
      embedder,
    });

    const ids = await semanticRecallMessageIds({
      tenantId,
      sessionId: a.sessionId,
      query: "session b content",
      k: 5,
      embedder,
    });
    expect(ids).toEqual([a.messageIds[0]]);
  });
});
