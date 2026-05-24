import { sql, desc, asc, gt, gte, lt } from "drizzle-orm";
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
}

// Append a single ledger entry. Runs inside a transaction that:
//   1. Acquires the ledger advisory xact lock (releases on commit/rollback).
//   2. Reads the current head (prev_hash).
//   3. Computes the new hash over canonical-JSON(prev_hash || entry-without-hash).
//   4. Inserts the row.
// The transaction wraps everything so a crash between hash computation and
// insert leaves the chain unchanged.
export async function appendLedger(
  input: LedgerWriteInput,
): Promise<LedgerEntry> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(${LEDGER_LOCK_KEY}::bigint)`,
    );
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
      })
      .returning();
    return row;
  }).then((row) => {
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
    return row;
  });
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
