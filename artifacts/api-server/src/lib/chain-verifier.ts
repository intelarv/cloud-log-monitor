// Periodic ledger chain verifier. Closes the M1.8 gap: §23.2 promises
// hourly window walks + weekly full walks with `ledger.chain_invalid`
// emitted on mismatch, but until M1.8 the only verification ran at boot
// and via GET /admin/ledger/verify.
//
// Design:
//   - Each scheduled run calls `verifyChainSince(now-24h)` or `verifyChain()`.
//   - Each run is gated by a Postgres advisory lock (per-scope key) so in
//     multi-instance deployments only one pod walks per cadence (M1.9).
//   - On mismatch, append a `ledger.chain_invalid` event whose post-commit
//     hook (lib/alerts.ts) emits an `alert=true` stderr line for the log
//     shipper to route per §25.
//   - Emissions are deduplicated against the most recent chain_invalid for
//     the same {scope, head_seq} so a persistently-broken chain alerts once,
//     not every hour (M1.9).
//   - The verifier's own ledger writes continue the (now-broken) chain
//     forward; auditors see the mismatch at the tampered seq AND the
//     `ledger.chain_invalid` attestation that we detected it.
//   - setInterval handles are `.unref()`ed so they never keep the process
//     alive past a graceful shutdown.
//   - Crash recovery is implicit: the verifier re-checks every period; a
//     missed run cannot leave a mismatch undetected longer than `windowMs`.

import { desc, eq, and, sql } from "drizzle-orm";
import { db, pool, ledgerEntriesTable } from "@workspace/db";
import { logger } from "./logger";
import { appendLedger, verifyChain, verifyChainSince } from "./ledger";
import type { VerifyResult } from "./ledger";
import {
  createCheckpoint,
  verifyCheckpoints,
  type CheckpointVerifyResult,
} from "./notarization";

export interface ChainVerifierSchedule {
  /** Rolling 24h-window walk cadence. Default 1h. */
  windowMs: number;
  /** Full-chain walk cadence. Default 7d. */
  fullMs: number;
  /** Window size for the rolling walk. Default 24h. */
  lookbackMs: number;
  /** Cadence for creating + verifying external notarization checkpoints
   *  (M2). Default 5min in dev — production §23.2 spec is "every 1,000
   *  entries OR daily, whichever first"; this is a time-only approximation
   *  that's fine for the dev write rate. */
  checkpointMs: number;
}

const DEFAULT_SCHEDULE: ChainVerifierSchedule = {
  windowMs: 60 * 60 * 1000,
  fullMs: 7 * 24 * 60 * 60 * 1000,
  lookbackMs: 24 * 60 * 60 * 1000,
  checkpointMs: 5 * 60 * 1000,
};

// Per-scope advisory-lock keys. Distinct from LEDGER_LOCK_KEY in ledger.ts
// and from each other so the rolling + full walks can run concurrently if
// their cadences ever align. Single 64-bit keyspace; arbitrary fixed values.
const LOCK_KEYS: Record<Scope, bigint> = {
  rolling_24h: 7331_4242_0000_0010n,
  full: 7331_4242_0000_0011n,
  checkpoint: 7331_4242_0000_0012n,
};

type Scope = "rolling_24h" | "full" | "checkpoint";

// Stable corruption fingerprint for dedupe. `head_seq` is NOT a stable key
// because every chain_invalid append itself advances the head — the next
// verifier run sees a new head_seq and would re-alert forever. The first
// error string is stable: while the chain is broken at seq 12, every run
// reports `"seq 12: hash mismatch ..."` as errors[0]. As soon as the
// corruption is repaired (or rolls out of the rolling window), the
// signature changes or disappears and a new break would re-alert.
function corruptionSignature(r: VerifyResult): string {
  return r.errors[0] ?? "<unknown>";
}

// Best-effort dedupe: if the most recent chain_invalid event *for this
// scope* already reports the same corruption signature, skip the append.
// Scoped per-{rolling_24h, full} so a full-walk alert doesn't silence the
// hourly one (or vice versa). Race-safe enough: even if two verifiers slip
// past the advisory lock, the worst case is one extra ledger row.
async function isDuplicateChainInvalid(
  scope: Scope,
  signature: string,
): Promise<boolean> {
  const [last] = await db
    .select({ payload: ledgerEntriesTable.payload })
    .from(ledgerEntriesTable)
    .where(
      and(
        eq(ledgerEntriesTable.eventType, "ledger.chain_invalid"),
        sql`payload->>'scope' = ${scope}`,
      ),
    )
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (!last) return false;
  const p = last.payload as { signature?: string };
  return p.signature === signature;
}

async function emitInvalid(scope: Scope, r: VerifyResult): Promise<void> {
  const signature = corruptionSignature(r);
  if (await isDuplicateChainInvalid(scope, signature)) {
    logger.warn(
      { scope, signature, error_count: r.errors.length },
      "chain verifier mismatch already alerted for this signature; skipping duplicate emit",
    );
    return;
  }
  // Cap the payload: full error list is in the structured log already
  // (see logger.error below); the ledger row carries only counts +
  // first few errors so it stays well under the 8KB soft cap.
  await appendLedger({
    tenantId: null,
    actor: { kind: "system", id: "chain_verifier" },
    eventType: "ledger.chain_invalid",
    subjectType: "ledger",
    subjectId: String(r.head_seq),
    payload: {
      scope,
      signature,
      walked: r.walked,
      head_seq: r.head_seq,
      head_hash: r.head_hash,
      error_count: r.errors.length,
      first_errors: r.errors.slice(0, 5),
    },
  });
}

// Acquire a session-level advisory lock for the duration of `fn`. If the
// lock can't be acquired (another pod is verifying), skip silently — the
// next cadence tick will try again. Postgres advisory locks are
// per-connection, so we must check out a dedicated client from the pool
// and hold it across try-lock → fn → unlock, otherwise the pool can hand
// the unlock to a different connection that never owned the lock.
async function withLeaderLock<T>(
  scope: Scope,
  fn: () => Promise<T>,
): Promise<T | "skipped"> {
  const key = LOCK_KEYS[scope];
  const client = await pool.connect();
  let unlockFailed: Error | null = null;
  try {
    const got = await client.query<{ got: boolean }>(
      "SELECT pg_try_advisory_lock($1::bigint) AS got",
      [key.toString()],
    );
    if (!got.rows[0]?.got) {
      logger.debug({ scope }, "chain verifier skipped — leader lock held elsewhere");
      return "skipped";
    }
    try {
      return await fn();
    } finally {
      try {
        await client.query("SELECT pg_advisory_unlock($1::bigint)", [
          key.toString(),
        ]);
      } catch (err) {
        unlockFailed = err as Error;
        logger.warn(
          { err, scope },
          "failed to release chain-verifier advisory lock; destroying pool client to avoid leaked session lock",
        );
      }
    }
  } finally {
    // If unlock failed, advisory locks are session-scoped — returning the
    // client to the pool would leak the lock for the lifetime of that
    // connection. Pass the error to release() so node-postgres destroys
    // the connection instead of recycling it.
    client.release(unlockFailed ?? undefined);
  }
}

async function runOnce(
  kind: Scope,
  fn: () => Promise<VerifyResult>,
): Promise<void> {
  await withLeaderLock(kind, async () => {
    try {
      const r = await fn();
      if (r.ok) {
        logger.debug(
          { kind, walked: r.walked, head_seq: r.head_seq },
          "chain verifier ok",
        );
        return;
      }
      logger.error(
        {
          kind,
          walked: r.walked,
          head_seq: r.head_seq,
          error_count: r.errors.length,
          errors: r.errors,
        },
        "chain verifier detected mismatch — emitting ledger.chain_invalid",
      );
      await emitInvalid(kind, r);
    } catch (err) {
      // Verifier failures are themselves operational concerns but not chain
      // integrity events — surface as ERROR, do NOT append a chain_invalid
      // (that would muddy the security signal).
      logger.error({ err, kind }, "chain verifier run failed");
    }
  });
}

// M2: checkpoint dedupe. Mirrors `isDuplicateChainInvalid`. A persistent
// checkpoint mismatch (e.g. someone overwrote a ledger row that an old
// checkpoint pinned) should alert ONCE per signature, not every cadence
// tick — same reasoning as for chain_invalid: the verifier's own append
// advances the head, so head_seq is not stable; the first-mismatch string
// IS stable.
function checkpointSignature(r: CheckpointVerifyResult): string {
  return r.first_mismatches[0] ?? "<unknown>";
}

async function isDuplicateCheckpointMismatch(
  signature: string,
): Promise<boolean> {
  const [last] = await db
    .select({ payload: ledgerEntriesTable.payload })
    .from(ledgerEntriesTable)
    .where(eq(ledgerEntriesTable.eventType, "ledger.checkpoint_mismatch"))
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (!last) return false;
  const p = last.payload as { signature?: string };
  return p.signature === signature;
}

async function runCheckpointOnce(): Promise<void> {
  await withLeaderLock("checkpoint", async () => {
    // (1) Sign current head into a new checkpoint (no-op if unchanged).
    // Architect-flagged: verify MUST run even if create errors (e.g. a
    // transient insert race). Wrap create in its own try so a creation
    // failure cannot mask an existing-checkpoint mismatch.
    try {
      const created = await createCheckpoint();
      if (created.kind === "created") {
        await appendLedger({
          tenantId: null,
          actor: { kind: "system", id: "notarizer" },
          eventType: "ledger.checkpoint_created",
          subjectType: "ledger_checkpoint",
          subjectId: String(created.checkpoint.id),
          payload: {
            seq: created.checkpoint.seq,
            head_hash: created.checkpoint.headHash,
            signing_key_id: created.checkpoint.signingKeyId,
          },
        });
        logger.debug(
          {
            id: created.checkpoint.id,
            seq: created.checkpoint.seq,
            key: created.checkpoint.signingKeyId,
          },
          "notarization checkpoint created",
        );
      }
    } catch (err) {
      logger.error(
        { err },
        "notarization create step failed; continuing to verify existing checkpoints",
      );
    }

    try {
      // (2) Verify all existing checkpoints against the live ledger.
      const r = await verifyCheckpoints();
      if (r.ok) {
        logger.debug(
          { walked: r.walked },
          "notarization checkpoints verified ok",
        );
        return;
      }
      const signature = checkpointSignature(r);
      logger.error(
        {
          walked: r.walked,
          mismatch_count: r.mismatch_count,
          first_mismatches: r.first_mismatches,
        },
        "notarization mismatch — emitting ledger.checkpoint_mismatch",
      );
      if (await isDuplicateCheckpointMismatch(signature)) {
        logger.warn(
          { signature, mismatch_count: r.mismatch_count },
          "checkpoint mismatch already alerted for this signature; skipping duplicate emit",
        );
        return;
      }
      await appendLedger({
        tenantId: null,
        actor: { kind: "system", id: "notarizer" },
        eventType: "ledger.checkpoint_mismatch",
        subjectType: "ledger",
        subjectId: "checkpoint",
        payload: {
          signature,
          walked: r.walked,
          mismatch_count: r.mismatch_count,
          first_mismatches: r.first_mismatches,
        },
      });
    } catch (err) {
      // Same policy as chain-verifier: operational failure ≠ integrity
      // event. Don't synthesize a checkpoint_mismatch on DB blips.
      logger.error({ err }, "notarization run failed");
    }
  });
}

/** Start the periodic chain verifier. Returns a stop() handle for tests. */
export function startChainVerifier(
  schedule: Partial<ChainVerifierSchedule> = {},
): () => void {
  const s = { ...DEFAULT_SCHEDULE, ...schedule };
  const intervals: ReturnType<typeof setInterval>[] = [];

  const windowTimer = setInterval(
    () =>
      void runOnce("rolling_24h", () =>
        verifyChainSince(new Date(Date.now() - s.lookbackMs)),
      ),
    s.windowMs,
  );
  const fullTimer = setInterval(
    () => void runOnce("full", () => verifyChain()),
    s.fullMs,
  );
  const checkpointTimer = setInterval(
    () => void runCheckpointOnce(),
    s.checkpointMs,
  );
  intervals.push(windowTimer, fullTimer, checkpointTimer);

  // Never keep the process alive on shutdown.
  for (const t of intervals) t.unref?.();

  logger.info(
    {
      windowMs: s.windowMs,
      fullMs: s.fullMs,
      lookbackMs: s.lookbackMs,
      checkpointMs: s.checkpointMs,
    },
    "chain verifier scheduled",
  );

  return () => {
    for (const t of intervals) clearInterval(t);
  };
}

// Exported for direct testing without spinning up setInterval. Also exposes
// the leader-lock + dedupe helpers so unit tests can assert their behavior
// without standing up a second DB connection.
export const __test__ = {
  runOnce,
  runCheckpointOnce,
  emitInvalid,
  withLeaderLock,
  isDuplicateChainInvalid,
  isDuplicateCheckpointMismatch,
  LOCK_KEYS,
};

