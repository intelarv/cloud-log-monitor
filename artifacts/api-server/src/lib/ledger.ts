import { sql, desc, asc, gt } from "drizzle-orm";
import {
  db,
  ledgerEntriesTable,
  computeLedgerHash,
  GENESIS_PREV_HASH,
  type Actor,
  type LedgerEntry,
} from "@workspace/db";

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
  });
}

export interface VerifyResult {
  ok: boolean;
  walked: number;
  head_seq: number;
  head_hash: string;
  errors: string[];
}

// Walk the ledger from seq=1 forward and recompute every hash. Stops collecting
// errors after `maxErrors` for bounded memory. Used both at startup and via
// GET /admin/ledger/verify.
export async function verifyChain(maxErrors = 50): Promise<VerifyResult> {
  const errors: string[] = [];
  let prevHash = GENESIS_PREV_HASH;
  let walked = 0;
  let headSeq = 0;
  let headHash = GENESIS_PREV_HASH;
  const batchSize = 500;
  let lastSeq = 0;
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
