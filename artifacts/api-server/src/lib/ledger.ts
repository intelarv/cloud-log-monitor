import { sql, desc, asc, eq, gt, gte, lt, and, inArray } from "drizzle-orm";
import {
  db,
  ledgerEntriesTable,
  computeLedgerHash,
  GENESIS_PREV_HASH,
  type Actor,
  type LedgerEntry,
} from "@workspace/db";
import { maybeEmitAlertFromLedger } from "./alerts";
import { maybeEnqueueReviewFromLedger } from "./agents/supervisor";
import { dispatchAlertFromLedger } from "./channels";

// Single arbitrary 64-bit key for the ledger writer advisory lock. Only one
// process can hold this lock at a time; serializes all ledger writes across
// the cluster. See ARCHITECTURE.md §23.2.
const LEDGER_LOCK_KEY = 7331_4242_0000_0001n;

export interface LedgerWriteInput {
  tenantId: string | null;
  actor: Actor;
  eventType: string;
  subjectType?: string;
  subjectId?: string;
  payload: Record<string, unknown>;
  /**
   * Optional per-step idempotency key. When set, the write is deduped: if a
   * ledger row already carries this key, the existing row is returned and NO
   * new row (and NO post-commit fan-out) is produced. Lets a retried activity
   * (e.g. the Temporal review steps) re-run safely without writing a duplicate
   * audit entry. NOT part of the ledger hash, so the chain stays byte-identical.
   * Omit (the default) for ordinary one-shot writes — those keep the original
   * always-insert behavior, so the eval gate / in-process path are unchanged.
   */
  idempotencyKey?: string;
}

/** Look up a ledger row by its idempotency key, or null if none exists. Used by
 *  retryable activities to recover a step's recorded outcome (e.g. the agent
 *  verdict in the entry payload) without re-running the side effect. The ledger
 *  has no RLS (reads are global inside the trust boundary), so this uses the
 *  base `db` handle. The unique `ledger_idempotency_key_uniq` index backs it. */
export async function getLedgerEntryByIdempotencyKey(
  idempotencyKey: string,
): Promise<LedgerEntry | null> {
  const [row] = await db
    .select()
    .from(ledgerEntriesTable)
    .where(eq(ledgerEntriesTable.idempotencyKey, idempotencyKey))
    .limit(1);
  return row ?? null;
}

// Append a single ledger entry. Runs inside a transaction that:
//   1. Acquires the ledger advisory xact lock (releases on commit/rollback).
//   2. Reads the current head (prev_hash).
//   3. Computes the new hash over canonical-JSON(prev_hash || entry-without-hash).
//   4. Inserts the row.
// The transaction wraps everything so a crash between hash computation and
// insert leaves the chain unchanged.
/** Result of an idempotency-aware ledger write.
 *  `deduped=false` ⇒ this call performed the INSERT (the caller "won" the race);
 *  `deduped=true`  ⇒ a row with this key already existed and was returned as-is.
 *  Callers that pair a ledger write with another non-idempotent side effect (a
 *  per-tenant budget charge) MUST gate that side effect on `deduped===false` so
 *  it runs exactly once even when two attempts execute the step concurrently:
 *  the global advisory lock serializes the two writes, so exactly one observes
 *  `deduped===false`. */
export interface AppendLedgerResult {
  row: LedgerEntry;
  deduped: boolean;
}

export async function appendLedger(
  input: LedgerWriteInput,
): Promise<LedgerEntry> {
  return (await appendLedgerWithStatus(input)).row;
}

/** Like `appendLedger`, but also reports whether the write was deduped. Use this
 *  (not `appendLedger`) whenever a NON-idempotent side effect must fire exactly
 *  once alongside the ledger entry under retry/concurrency — gate the side
 *  effect on `deduped===false`. See `AppendLedgerResult`. */
export async function appendLedgerWithStatus(
  input: LedgerWriteInput,
): Promise<AppendLedgerResult> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(${LEDGER_LOCK_KEY}::bigint)`,
    );
    // Idempotency dedupe: if this key already landed a row, return it and skip
    // the insert + post-commit fan-out. Safe to check inside the lock — the
    // single global advisory lock serializes all writers, so there is no race
    // between this read and a concurrent same-key insert.
    if (input.idempotencyKey !== undefined) {
      const [existing] = await tx
        .select()
        .from(ledgerEntriesTable)
        .where(eq(ledgerEntriesTable.idempotencyKey, input.idempotencyKey))
        .limit(1);
      if (existing) return { row: existing, deduped: true as const };
    }
    const [head] = await tx
      .select({ hash: ledgerEntriesTable.hash })
      .from(ledgerEntriesTable)
      .orderBy(desc(ledgerEntriesTable.seq))
      .limit(1);
    const prevHash = head?.hash ?? GENESIS_PREV_HASH;
    const ts = new Date();
    const hash = computeLedgerHash(prevHash, {
      ts,
      tenantId: input.tenantId,
      actor: input.actor,
      eventType: input.eventType,
      subjectType: input.subjectType,
      subjectId: input.subjectId,
      payload: input.payload,
    });
    const [row] = await tx
      .insert(ledgerEntriesTable)
      .values({
        ts,
        tenantId: input.tenantId,
        actor: input.actor,
        eventType: input.eventType,
        subjectType: input.subjectType ?? null,
        subjectId: input.subjectId ?? null,
        payload: input.payload,
        prevHash,
        hash,
        idempotencyKey: input.idempotencyKey ?? null,
      })
      .returning();
    return { row, deduped: false as const };
  }).then(({ row, deduped }) => {
    // On a dedupe hit the row already ran its post-commit hooks when it was
    // first written; re-running them would double-alert / double-enqueue /
    // double-dispatch, so return the existing row untouched.
    if (deduped) return { row, deduped };
    // Post-commit alert hook. Runs OUTSIDE the transaction so a flaky
    // logger or alert sink can never roll back a ledger write. See §25.
    try {
      maybeEmitAlertFromLedger(row);
    } catch {
      // Alerting is best-effort; the ledger row is already durable.
    }
    // M5: post-commit fan-out to the multi-agent supervisor on
    // `finding.created`. Fire-and-forget — the supervisor's own work is
    // queued + bounded; a slow LLM cannot block ledger writes.
    try {
      maybeEnqueueReviewFromLedger(row);
    } catch {
      // Same best-effort guarantee as alerting; the ledger row is durable.
    }
    // M6: post-commit fan-out to configured notification channels (Slack /
    // webhook). Fire-and-forget — adapter HTTP calls cannot block ledger
    // writes. Self-recursion is guarded inside `dispatchAlertFromLedger`
    // (channel.* events do not re-dispatch). Inert if no channel adapters
    // are configured.
    try {
      dispatchAlertFromLedger(row);
    } catch {
      // Same best-effort guarantee.
    }
    return { row, deduped };
  });
}

// Ledger event types written once per agent review attempt (initial + every
// fix-and-replay). The agent review orchestration keys each of these on a stable
// `{workflowId}:attempt:{N}:{step}` idempotency key, so they reconstruct the
// per-finding re-run history from the immutable ledger alone.
export const REVIEW_ATTEMPT_EVENT_TYPES = [
  "agent.triage_complete",
  "agent.verifier_complete",
  "agent.review_skipped_budget",
  "agent.review_failed",
] as const;

/** All review-related ledger entries for one finding, oldest-first. Tenant-scoped
 *  by explicit predicate (the ledger table has no RLS — see routes/findings.ts).
 *  Powers the finding detail view's review re-run timeline. */
export async function listFindingReviewEntries(
  tenantId: string,
  findingId: string,
): Promise<LedgerEntry[]> {
  return db
    .select()
    .from(ledgerEntriesTable)
    .where(
      and(
        eq(ledgerEntriesTable.tenantId, tenantId),
        eq(ledgerEntriesTable.subjectType, "finding"),
        eq(ledgerEntriesTable.subjectId, findingId),
        inArray(ledgerEntriesTable.eventType, [...REVIEW_ATTEMPT_EVENT_TYPES]),
      ),
    )
    .orderBy(asc(ledgerEntriesTable.seq))
    .limit(500);
}

/** Recover the 1-based review attempt number from a review step's idempotency
 *  key (`{workflowId}:attempt:{N}:{step}`), or null if it carries no attempt
 *  segment. The attempt is not stored in the payload, so this is the only
 *  reconstruction path for grouping ledger entries into per-attempt timelines. */
export function parseReviewAttempt(idempotencyKey: string | null): number | null {
  if (!idempotencyKey) return null;
  const m = idempotencyKey.match(/:attempt:(\d+):/);
  return m ? Number(m[1]) : null;
}

export interface VerifyResult {
  ok: boolean;
  walked: number;
  head_seq: number;
  head_hash: string;
  errors: string[];
}

// Walk the ledger from `startSeq` forward, seeded with `seedPrevHash`, and
// recompute every hash. Stops collecting errors after `maxErrors` for bounded
// memory. Shared by full-chain and windowed verifies.
async function walkFrom(
  startSeq: number,
  seedPrevHash: string,
  maxErrors: number,
): Promise<VerifyResult> {
  const errors: string[] = [];
  let prevHash = seedPrevHash;
  let walked = 0;
  let headSeq = startSeq > 1 ? startSeq - 1 : 0;
  let headHash = seedPrevHash;
  const batchSize = 500;
  let lastSeq = startSeq - 1;
  // Loop in batches so verifying a large ledger doesn't OOM.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const batch = await db
      .select()
      .from(ledgerEntriesTable)
      .where(gt(ledgerEntriesTable.seq, lastSeq))
      .orderBy(asc(ledgerEntriesTable.seq))
      .limit(batchSize);
    if (batch.length === 0) break;
    for (const row of batch) {
      walked++;
      headSeq = row.seq;
      if (row.prevHash !== prevHash) {
        errors.push(
          `seq ${row.seq}: prev_hash mismatch (expected ${prevHash}, got ${row.prevHash})`,
        );
      }
      const recomputed = computeLedgerHash(row.prevHash, {
        ts: row.ts,
        tenantId: row.tenantId,
        actor: row.actor as Actor,
        eventType: row.eventType,
        subjectType: row.subjectType ?? undefined,
        subjectId: row.subjectId ?? undefined,
        payload: row.payload as Record<string, unknown>,
      });
      if (recomputed !== row.hash) {
        errors.push(
          `seq ${row.seq}: hash mismatch (recomputed ${recomputed}, stored ${row.hash})`,
        );
      }
      prevHash = row.hash;
      headHash = row.hash;
      if (errors.length >= maxErrors) {
        return { ok: false, walked, head_seq: headSeq, head_hash: headHash, errors };
      }
      lastSeq = row.seq;
    }
    if (batch.length < batchSize) break;
  }
  return {
    ok: errors.length === 0,
    walked,
    head_seq: headSeq,
    head_hash: headHash,
    errors,
  };
}

// Walk the entire ledger from seq=1. Used at startup, via
// GET /admin/ledger/verify, and by the periodic full-chain check (§23.2).
export async function verifyChain(maxErrors = 50): Promise<VerifyResult> {
  return walkFrom(1, GENESIS_PREV_HASH, maxErrors);
}

// Walk the ledger starting at the first row with ts >= sinceTs, seeded with
// the hash of the immediately-prior row (so the window's prev_hash linkage
// is itself verified). Used by the rolling 24h chain-verifier (§23.2 / §25).
// If no rows fall in the window, returns ok with walked=0.
export async function verifyChainSince(
  sinceTs: Date,
  maxErrors = 50,
): Promise<VerifyResult> {
  const [first] = await db
    .select({ seq: ledgerEntriesTable.seq })
    .from(ledgerEntriesTable)
    .where(gte(ledgerEntriesTable.ts, sinceTs))
    .orderBy(asc(ledgerEntriesTable.seq))
    .limit(1);
  if (!first) {
    return {
      ok: true,
      walked: 0,
      head_seq: 0,
      head_hash: GENESIS_PREV_HASH,
      errors: [],
    };
  }
  // Seed prevHash from the immediately preceding *existing* row, not
  // `first.seq - 1` — Postgres `bigserial` may have legitimate gaps from
  // rollbacks / cache loss / crash recovery, and a gap is not corruption.
  // If no prior row exists at all, `first` is the genesis-window row and
  // GENESIS_PREV_HASH is the correct seed.
  let seedPrev = GENESIS_PREV_HASH;
  let startSeq = first.seq;
  const [prior] = await db
    .select({ seq: ledgerEntriesTable.seq, hash: ledgerEntriesTable.hash })
    .from(ledgerEntriesTable)
    .where(lt(ledgerEntriesTable.seq, first.seq))
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (prior) {
    seedPrev = prior.hash;
    // walkFrom will pick up rows with seq > prior.seq — which is correct
    // for non-contiguous sequences (the gap is benign, the chain is still
    // linked by prev_hash → hash regardless of seq numbering).
    startSeq = prior.seq + 1;
  }
  return walkFrom(startSeq, seedPrev, maxErrors);
}
