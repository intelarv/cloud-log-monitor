import {
  isFindingEmbeddingsPartitionedInDb,
  isChatEmbeddingsPartitionedInDb,
} from "@workspace/db";
import { logger } from "./logger";

// ---------------------------------------------------------------------------
// M12.2: per-tenant pgvector partitioning switch.
//
// finding_embeddings can be LIST-partitioned by tenant_id so each tenant's
// vectors live in their own physical namespace (threat_model §Info Disclosure
// "per-tenant pgvector namespaces"). The switch is read once at boot and
// exposed to the embedding upsert path so it can pick the correct ON CONFLICT
// arbiter (the partitioned table has a composite PK (finding_id, tenant_id);
// the single table has PK (finding_id)).
//
// Default-inert: unset ⇒ single-table layout, byte-identical to pre-M12.2 (the
// dev/eval default). Like SEARCH_PROVIDER / RAW_EVIDENCE_PROVIDER there is no
// DEPLOYMENT_TARGET shortcut — moving to a partitioned layout recreates the
// embeddings table, so it is always an explicit opt-in.
// ---------------------------------------------------------------------------

const TRUTHY = new Set(["1", "true", "on", "yes"]);
const FALSY = new Set(["", "0", "false", "off", "no"]);

let partitioned = false;

/** Parse env into the boolean switch. Pure: no I/O. Throws on an
 *  unrecognized value rather than silently treating it as off. */
export function loadEmbeddingsPartitioningFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = env["EMBEDDINGS_TENANT_PARTITIONING"]?.trim().toLowerCase();
  if (raw === undefined) return false;
  if (TRUTHY.has(raw)) return true;
  if (FALSY.has(raw)) return false;
  throw new Error(
    `EMBEDDINGS_TENANT_PARTITIONING=${raw} is not a boolean ` +
      `(use one of: ${[...TRUTHY].join(", ")} / ${[...FALSY].filter(Boolean).join(", ")}).`,
  );
}

/** Read env and set the module-level switch once at boot. Returns the value.
 *  This is the operator INTENT (what bootstrap will try to create); the runtime
 *  truth is reconciled against the catalog afterwards by
 *  `reconcileEmbeddingsPartitioningFromDb` (the partitioning conversion is
 *  one-way, so the env flag alone can drift from the actual schema). */
export function initEmbeddingsPartitioningFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  partitioned = loadEmbeddingsPartitioningFromEnv(env);
  if (partitioned) {
    logger.info(
      "finding_embeddings: per-tenant LIST partitioning ENABLED (M12.2)",
    );
  }
  return partitioned;
}

/**
 * Reconcile the runtime switch with the ACTUAL finding_embeddings layout in the
 * DB (read after bootstrap). bootstrap only converts single→partitioned, never
 * back, so a DB that was once partitioned but is now booted with the env flag
 * off would otherwise leave the switch=false while the table still has the
 * composite PK — and the embedding upsert's ON CONFLICT (finding_id) arbiter
 * would fail at runtime against (finding_id, tenant_id). Trusting the catalog
 * keeps the arbiter consistent with the table no matter what. Logs a warning on
 * a mismatch so the drift is visible to operators. Returns the reconciled value.
 */
export async function reconcileEmbeddingsPartitioningFromDb(): Promise<boolean> {
  const actual = await isFindingEmbeddingsPartitionedInDb();
  if (actual !== partitioned) {
    logger.warn(
      { envIntent: partitioned, actualLayout: actual },
      "finding_embeddings: EMBEDDINGS_TENANT_PARTITIONING intent differs from " +
        "the live table layout; trusting the catalog. The partitioning " +
        "conversion is one-way — to go from partitioned back to single, DROP " +
        "TABLE finding_embeddings and restart (it is a derived cache).",
    );
  }
  partitioned = actual;
  return partitioned;
}

/** True when finding_embeddings is partitioned (composite PK). */
export function isEmbeddingsPartitioned(): boolean {
  return partitioned;
}

/** Test-only: force the switch state. */
export function __setEmbeddingsPartitionedForTest(value: boolean): void {
  partitioned = value;
}

// ---------------------------------------------------------------------------
// chat_message_embeddings per-tenant partitioning switch (mirrors the
// finding_embeddings switch above). chat_message_embeddings can be
// LIST-partitioned by tenant_id so each tenant's chat-recall vectors live in
// their own physical namespace. The switch is read once at boot and exposed to
// the chat-embedding upsert path so it can pick the correct ON CONFLICT arbiter
// (the partitioned table has composite PK (message_id, tenant_id); the single
// table has PK (message_id)).
//
// Default-inert: unset ⇒ single-table layout, byte-identical to M19 (the
// dev/eval default). Like EMBEDDINGS_TENANT_PARTITIONING there is no
// DEPLOYMENT_TARGET shortcut — moving to a partitioned layout recreates the
// chat-embeddings table, so it is always an explicit opt-in.
// ---------------------------------------------------------------------------

let chatPartitioned = false;

/** Parse env into the boolean switch. Pure: no I/O. Throws on an
 *  unrecognized value rather than silently treating it as off. */
export function loadChatEmbeddingsPartitioningFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  const raw = env["CHAT_EMBEDDINGS_TENANT_PARTITIONING"]?.trim().toLowerCase();
  if (raw === undefined) return false;
  if (TRUTHY.has(raw)) return true;
  if (FALSY.has(raw)) return false;
  throw new Error(
    `CHAT_EMBEDDINGS_TENANT_PARTITIONING=${raw} is not a boolean ` +
      `(use one of: ${[...TRUTHY].join(", ")} / ${[...FALSY].filter(Boolean).join(", ")}).`,
  );
}

/** Read env and set the module-level switch once at boot. Returns the value.
 *  This is the operator INTENT; the runtime truth is reconciled against the
 *  catalog afterwards by `reconcileChatEmbeddingsPartitioningFromDb` (the
 *  partitioning conversion is one-way, so the env flag can drift from the
 *  actual schema). */
export function initChatEmbeddingsPartitioningFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): boolean {
  chatPartitioned = loadChatEmbeddingsPartitioningFromEnv(env);
  if (chatPartitioned) {
    logger.info(
      "chat_message_embeddings: per-tenant LIST partitioning ENABLED",
    );
  }
  return chatPartitioned;
}

/**
 * Reconcile the runtime switch with the ACTUAL chat_message_embeddings layout in
 * the DB (read after bootstrap). bootstrap only converts single→partitioned,
 * never back, so a DB that was once partitioned but is now booted with the env
 * flag off would otherwise leave the switch=false while the table still has the
 * composite PK — and the chat-embedding upsert's ON CONFLICT (message_id)
 * arbiter would fail at runtime against (message_id, tenant_id). Trusting the
 * catalog keeps the arbiter consistent. Logs a warning on a mismatch. Returns
 * the reconciled value.
 */
export async function reconcileChatEmbeddingsPartitioningFromDb(): Promise<boolean> {
  const actual = await isChatEmbeddingsPartitionedInDb();
  if (actual !== chatPartitioned) {
    logger.warn(
      { envIntent: chatPartitioned, actualLayout: actual },
      "chat_message_embeddings: CHAT_EMBEDDINGS_TENANT_PARTITIONING intent " +
        "differs from the live table layout; trusting the catalog. The " +
        "partitioning conversion is one-way — to go from partitioned back to " +
        "single, DROP TABLE chat_message_embeddings and restart (it is a " +
        "derived cache).",
    );
  }
  chatPartitioned = actual;
  return chatPartitioned;
}

/** True when chat_message_embeddings is partitioned (composite PK). */
export function isChatEmbeddingsPartitioned(): boolean {
  return chatPartitioned;
}

/** Test-only: force the switch state. */
export function __setChatEmbeddingsPartitionedForTest(value: boolean): void {
  chatPartitioned = value;
}
