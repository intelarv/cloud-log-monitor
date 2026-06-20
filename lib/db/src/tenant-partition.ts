import { createHash } from "node:crypto";
import { sql } from "drizzle-orm";
import { db } from "./db";

// M12.2: per-tenant pgvector partition provisioning.
//
// finding_embeddings is LIST-partitioned by tenant_id when the system is booted
// with EMBEDDINGS_TENANT_PARTITIONING on (see setup-sql.ts). Every tenant is
// served by the DEFAULT partition until an operator provisions a *dedicated*
// partition for it with this helper — at which point that tenant's vectors live
// in their own physical table (per-tenant pgvector namespace, threat_model
// §Info Disclosure) with its own ivfflat index and deny-by-default RLS.
//
// Ordering note: Postgres refuses to create a new partition while the DEFAULT
// partition already holds rows that would belong to it. Provision the partition
// BEFORE the boot embedding backfill seats that tenant's rows (or clear the
// tenant's cached rows first); the embeddings are a derived cache so a rebuild
// is always safe.

// tenant_id is an untrusted string; restrict to a conservative charset so it is
// safe to inline as a SQL literal (no quotes can appear) and so the derived
// identifier stays bounded.
const SAFE_TENANT_ID = /^[A-Za-z0-9_.:-]{1,128}$/;

export interface ProvisionPartitionResult {
  created: boolean;
  partition: string;
}

/**
 * True iff `finding_embeddings` is actually a LIST-partitioned table in the
 * live DB (i.e. it has a composite PK `(finding_id, tenant_id)`), as opposed to
 * the single-table layout. Reads the catalog, so it reflects reality regardless
 * of the EMBEDDINGS_TENANT_PARTITIONING env value. Callers use this to keep the
 * embedding upsert's ON CONFLICT arbiter consistent with the table that boot
 * actually left in place (the partitioning conversion is one-way, so the env
 * flag alone can drift from the schema).
 */
export async function isFindingEmbeddingsPartitionedInDb(): Promise<boolean> {
  const res = await db.execute<{ ok: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM pg_partitioned_table pt
      JOIN pg_class c ON c.oid = pt.partrelid
      WHERE c.relname = 'finding_embeddings'
    ) AS ok
  `);
  return res.rows[0]?.ok ?? false;
}

function partitionName(tenantId: string): string {
  // Deterministic, always-safe identifier (md5 hex is [0-9a-f]). Avoids any
  // identifier-length / charset issues from the raw tenant id.
  const suffix = createHash("md5").update(tenantId).digest("hex").slice(0, 16);
  return `finding_embeddings_t_${suffix}`;
}

/**
 * Create a dedicated finding_embeddings partition for `tenantId` (idempotent).
 * Requires finding_embeddings to already be partitioned (EMBEDDINGS_TENANT_
 * PARTITIONING on); throws a clear error otherwise. Default-inert: never called
 * unless an operator opts a tenant into a dedicated namespace.
 */
export async function provisionTenantEmbeddingPartition(
  tenantId: string,
): Promise<ProvisionPartitionResult> {
  if (!SAFE_TENANT_ID.test(tenantId)) {
    throw new Error(
      `provisionTenantEmbeddingPartition: unsafe tenantId ${JSON.stringify(
        tenantId,
      )} (allowed: [A-Za-z0-9_.:-], 1-128 chars)`,
    );
  }

  const partitioned = await isFindingEmbeddingsPartitionedInDb();
  if (!partitioned) {
    throw new Error(
      "provisionTenantEmbeddingPartition: finding_embeddings is not " +
        "partitioned. Set EMBEDDINGS_TENANT_PARTITIONING and restart so the " +
        "table is recreated as partitioned before provisioning per-tenant " +
        "partitions.",
    );
  }

  const part = partitionName(tenantId);
  const exists = await db.execute<{ ok: boolean }>(sql`
    SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = ${part}) AS ok
  `);
  if (exists.rows[0]?.ok) return { created: false, partition: part };

  // Safe to inline: `part` is md5-hex; the tenant literal cannot contain quotes
  // (SAFE_TENANT_ID excludes them). Partition bounds + DDL identifiers cannot be
  // bound parameters, so raw SQL is required here.
  const lit = `'${tenantId}'`;
  await db.execute(
    sql.raw(
      `CREATE TABLE ${part} PARTITION OF finding_embeddings FOR VALUES IN (${lit})`,
    ),
  );
  await db.execute(
    sql.raw(
      `CREATE INDEX ${part}_vec_idx ON ${part} USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10)`,
    ),
  );
  await db.execute(sql.raw(`ALTER TABLE ${part} ENABLE ROW LEVEL SECURITY`));
  await db.execute(sql.raw(`ALTER TABLE ${part} FORCE ROW LEVEL SECURITY`));
  return { created: true, partition: part };
}

// ---------------------------------------------------------------------------
// chat_message_embeddings per-tenant partitioning (mirrors the
// finding_embeddings helpers above). Same posture: the table is LIST-partitioned
// by tenant_id when booted with CHAT_EMBEDDINGS_TENANT_PARTITIONING on; every
// tenant is served by the DEFAULT partition until an operator provisions a
// dedicated partition with provisionTenantChatEmbeddingPartition. The same
// ordering note applies — provision BEFORE that tenant's rows land in DEFAULT
// (chat embeddings are a derived cache, so clearing + rebuilding is safe).
// ---------------------------------------------------------------------------

/**
 * True iff `chat_message_embeddings` is actually a LIST-partitioned table in the
 * live DB (composite PK `(message_id, tenant_id)`), as opposed to the single
 * table. Reads the catalog, so it reflects reality regardless of the
 * CHAT_EMBEDDINGS_TENANT_PARTITIONING env value (the partitioning conversion is
 * one-way, so the env flag alone can drift from the schema). Callers use this to
 * keep the chat-embedding upsert's ON CONFLICT arbiter consistent with the table
 * boot actually left in place.
 */
export async function isChatEmbeddingsPartitionedInDb(): Promise<boolean> {
  const res = await db.execute<{ ok: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM pg_partitioned_table pt
      JOIN pg_class c ON c.oid = pt.partrelid
      WHERE c.relname = 'chat_message_embeddings'
    ) AS ok
  `);
  return res.rows[0]?.ok ?? false;
}

function chatPartitionName(tenantId: string): string {
  const suffix = createHash("md5").update(tenantId).digest("hex").slice(0, 16);
  return `chat_message_embeddings_t_${suffix}`;
}

/**
 * Create a dedicated chat_message_embeddings partition for `tenantId`
 * (idempotent). Requires chat_message_embeddings to already be partitioned
 * (CHAT_EMBEDDINGS_TENANT_PARTITIONING on); throws a clear error otherwise.
 * Default-inert: never called unless an operator opts a tenant into a dedicated
 * namespace.
 */
export async function provisionTenantChatEmbeddingPartition(
  tenantId: string,
): Promise<ProvisionPartitionResult> {
  if (!SAFE_TENANT_ID.test(tenantId)) {
    throw new Error(
      `provisionTenantChatEmbeddingPartition: unsafe tenantId ${JSON.stringify(
        tenantId,
      )} (allowed: [A-Za-z0-9_.:-], 1-128 chars)`,
    );
  }

  const partitioned = await isChatEmbeddingsPartitionedInDb();
  if (!partitioned) {
    throw new Error(
      "provisionTenantChatEmbeddingPartition: chat_message_embeddings is not " +
        "partitioned. Set CHAT_EMBEDDINGS_TENANT_PARTITIONING and restart so " +
        "the table is recreated as partitioned before provisioning per-tenant " +
        "partitions.",
    );
  }

  const part = chatPartitionName(tenantId);
  const exists = await db.execute<{ ok: boolean }>(sql`
    SELECT EXISTS (SELECT 1 FROM pg_class WHERE relname = ${part}) AS ok
  `);
  if (exists.rows[0]?.ok) return { created: false, partition: part };

  const lit = `'${tenantId}'`;
  await db.execute(
    sql.raw(
      `CREATE TABLE ${part} PARTITION OF chat_message_embeddings FOR VALUES IN (${lit})`,
    ),
  );
  await db.execute(
    sql.raw(
      `CREATE INDEX ${part}_vec_idx ON ${part} USING ivfflat (embedding vector_cosine_ops) WITH (lists = 10)`,
    ),
  );
  await db.execute(sql.raw(`ALTER TABLE ${part} ENABLE ROW LEVEL SECURITY`));
  await db.execute(sql.raw(`ALTER TABLE ${part} FORCE ROW LEVEL SECURITY`));
  return { created: true, partition: part };
}
