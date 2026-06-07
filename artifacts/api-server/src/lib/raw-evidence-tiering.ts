// Tiered storage lifecycle for raw evidence.
//
// Through M10.3 raw PHI is written to its final tier AT INGEST TIME: the
// inline `findings.raw_evidence` jsonb column (dev / database store) OR the
// configured external WORM object store (S3 Object Lock / GCS retention /
// Azure Blob immutability), recorded as `{first,latest}` URIs in
// `raw_evidence_ref`. There was no lifecycle that MOVED an already-stored
// inline payload out of the hot tier afterwards.
//
// This module closes that gap. When an operator switches an existing
// deployment from the inline DB store to an external WORM store, every
// finding ingested BEFORE the switch still carries its raw PHI inline in the
// hot `raw_evidence` column. This job ages those rows out: once a finding's
// `last_seen_at` is older than `RAW_EVIDENCE_TIER_AGE_DAYS`, the inline
// `{first,latest}` snapshots are written to the external store as immutable
// objects, the finding's `raw_evidence_ref` is seated, and the inline column
// is nulled — so the raw PHI no longer lives in the searchable/operational
// hot tier. The break-glass read path already resolves `raw_evidence_ref`
// first and falls back to the inline column (see resolveRawEvidence), so a
// tiered finding stays fully readable through the same single gated path.
//
// Safety posture (matches the rest of the raw-evidence surface):
//   - Default-INERT. The job is scheduled only when BOTH (a) the operator
//     opts in with `RAW_EVIDENCE_TIER_AGE_DAYS`, AND (b) an EXTERNAL store is
//     configured. With the inline DB store (dev default) there is no WORM
//     tier to age into, so nothing runs and the offline eval gate / boot path
//     are byte-identical.
//   - Get-after-put. The inline copy (often the ONLY copy of that PHI) is
//     nulled only after the WORM objects are confirmed readable, so a write
//     or durability glitch can never destroy the sole copy.
//   - LOUD on failure. A put/get/verify failure leaves the inline column
//     intact and ledgers `raw_evidence.tier_failed` (alertable) so on-call
//     learns durable migration is degraded; the next cadence retries.
//   - No PHI / no object URIs in the ledger or logs — finding id + provider
//     name only (the URIs live in `raw_evidence_ref`, out of findingSafeColumns).
//   - Leader-locked (single Postgres advisory lock) so only one pod tiers per
//     cadence in a multi-instance deployment; setInterval is `.unref()`ed.

import { sql } from "drizzle-orm";
import { db, pool } from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import {
  getRawEvidenceStoreOrNull,
  type RawEvidenceStore,
} from "./raw-evidence-store";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface RawEvidenceTieringConfig {
  /** Findings whose `last_seen_at` is older than this are eligible to tier. */
  ageMs: number;
  /** Scheduler cadence. */
  intervalMs: number;
  /** Max findings migrated per tenant per run (bounds object-store I/O). */
  batchSize: number;
}

function parsePositiveInt(
  raw: string | undefined,
  fallback: number,
  label: string,
): number {
  if (raw === undefined || raw.trim() === "") return fallback;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`${label}=${raw} must be a positive number`);
  }
  return Math.floor(n);
}

/** Parse env into a tiering config. Returns null (disabled) when the opt-in
 *  `RAW_EVIDENCE_TIER_AGE_DAYS` is unset — moving raw PHI out of the hot tier
 *  is consequential, so it never turns on implicitly. Pure: no I/O. */
export function loadRawEvidenceTieringConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): RawEvidenceTieringConfig | null {
  const ageDaysRaw = env["RAW_EVIDENCE_TIER_AGE_DAYS"]?.trim();
  if (!ageDaysRaw) return null;
  const ageDays = Number(ageDaysRaw);
  if (!Number.isFinite(ageDays) || ageDays <= 0) {
    throw new Error(
      `RAW_EVIDENCE_TIER_AGE_DAYS=${ageDaysRaw} must be a positive number of days`,
    );
  }
  return {
    ageMs: ageDays * 24 * 60 * 60 * 1000,
    intervalMs: parsePositiveInt(
      env["RAW_EVIDENCE_TIER_INTERVAL_MS"],
      60 * 60 * 1000,
      "RAW_EVIDENCE_TIER_INTERVAL_MS",
    ),
    batchSize: parsePositiveInt(
      env["RAW_EVIDENCE_TIER_BATCH_SIZE"],
      100,
      "RAW_EVIDENCE_TIER_BATCH_SIZE",
    ),
  };
}

// ---------------------------------------------------------------------------
// Core migration (testable, dependency-injected)
// ---------------------------------------------------------------------------

export interface TierRawEvidenceDeps {
  ageMs: number;
  batchSize: number;
  /** `undefined` → module-registered store (or none); explicit value for tests. */
  store?: RawEvidenceStore | null;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
}

export interface TierRawEvidenceResult {
  /** Candidate findings examined this run. */
  scanned: number;
  /** Findings whose inline raw was migrated to the external store + nulled. */
  tiered: number;
  /** Findings whose migration failed (inline copy preserved, retried later). */
  failed: number;
  /** True when the run short-circuited because no external store is active. */
  skippedNoStore: boolean;
}

/** The inline `raw_evidence` payload is `{first,latest}` occurrence snapshots
 *  (post-M3). Tolerate the pre-fix flat shape (a single occurrence object) by
 *  treating it as both first and latest, mirroring the ingest migration path. */
function normalizeInline(inline: unknown): { first: unknown; latest: unknown } {
  if (inline && typeof inline === "object") {
    const o = inline as Record<string, unknown>;
    if ("first" in o || "latest" in o) {
      const first = "first" in o ? o.first : o.latest;
      const latest = "latest" in o ? o.latest : o.first;
      return { first, latest };
    }
  }
  return { first: inline, latest: inline };
}

type RawEvidenceRefRow = { first?: string; latest?: string } | null;

/** Read the current `raw_evidence_ref` for a finding (RLS-scoped, no lock). */
async function readRef(
  tenantId: string,
  findingId: string,
): Promise<RawEvidenceRefRow> {
  return withTenant(tenantId, async (tx) => {
    const r = await tx.execute<{ raw_evidence_ref: RawEvidenceRefRow }>(sql`
      SELECT raw_evidence_ref FROM findings
      WHERE id = ${findingId} AND tenant_id = ${tenantId}
    `);
    return r.rows[0]?.raw_evidence_ref ?? null;
  });
}

/** Migrate ONE finding's inline raw evidence to the external store. Returns
 *  true if the inline column was actually nulled (i.e. the row was migrated),
 *  false if a concurrent change meant there was nothing safe to migrate (the
 *  WORM objects we wrote are harmless — immutable, and the next cadence
 *  re-tiers). Throws on any object-store failure so the caller ledgers
 *  `tier_failed` and preserves the inline copy.
 *
 *  Concurrency with ingest (the subtle part): once an operator switches an
 *  existing deployment from the inline DB store to an external store, ingest
 *  leaves a legacy finding's inline `raw_evidence` UNTOUCHED on every re-hit
 *  (see ingest.ts — the inline merge is gated on `!externalRaw`) while it
 *  advances `raw_evidence_ref.latest` to each NEW occurrence's WORM object. So
 *  a legacy row can carry BOTH a stale inline `{first,latest}` (pre-switch
 *  occurrences) AND an ingest-maintained `raw_evidence_ref` whose `latest`
 *  points at a more RECENT occurrence. A naive "write inline → overwrite ref →
 *  null inline" would clobber that newer ref and orphan the post-switch
 *  occurrence pointers. We avoid that:
 *   - `first` slot: the inline first occurrence is the TRUE earliest (legacy
 *     rows predate the switch; ingest's set-once ref.first only knows about
 *     post-switch occurrences), so the migrated inline first always wins it.
 *   - `latest` slot: prefer an ingest-seated `ref.latest` (newer) when present,
 *     else the migrated inline latest. Whichever uri lands in the slot is
 *     get-verified readable BEFORE we null the inline copy.
 *   - Optimistic guard: if ingest advanced `ref.latest` between our verify and
 *     the finalize, the uri we verified is stale — we skip (retry next cadence)
 *     rather than commit an unverified/older latest or clobber the newer ref.
 */
async function tierOneFinding(args: {
  store: RawEvidenceStore;
  tenantId: string;
  findingId: string;
  inline: unknown;
}): Promise<boolean> {
  const { store, tenantId, findingId, inline } = args;
  const { first, latest } = normalizeInline(inline);

  // The inline first occurrence is data ONLY the inline column holds — always
  // migrate + verify it.
  const firstUri = await store.put({ findingId, tenantId, evidence: first });
  await store.get({ tenantId, uri: firstUri });

  // Decide the `latest` slot. If ingest already seated a (newer) ref.latest,
  // verify that object and reuse it; otherwise migrate the inline latest. The
  // committed uri is always get-verified before any inline null.
  const preRef = await readRef(tenantId, findingId);
  let latestUri: string;
  if (preRef?.latest) {
    await store.get({ tenantId, uri: preRef.latest });
    latestUri = preRef.latest;
  } else if (JSON.stringify(first) === JSON.stringify(latest)) {
    latestUri = firstUri;
  } else {
    latestUri = await store.put({ findingId, tenantId, evidence: latest });
    await store.get({ tenantId, uri: latestUri });
  }

  const ref = { first: firstUri, latest: latestUri };
  const updated = await withTenant(tenantId, async (tx) => {
    const cur = await tx.execute<{ raw_evidence_ref: RawEvidenceRefRow }>(sql`
      SELECT raw_evidence_ref FROM findings
      WHERE id = ${findingId} AND tenant_id = ${tenantId}
        AND raw_evidence IS NOT NULL
      FOR UPDATE
    `);
    // Concurrent re-hit nulled inline already (or row gone) — nothing to do.
    if (cur.rows.length === 0) return 0;
    // Optimistic concurrency: bail if ingest advanced ref.latest out from under
    // the verify above. Next cadence re-reads the now-current latest.
    const nowLatest = cur.rows[0].raw_evidence_ref?.latest ?? null;
    if (nowLatest !== (preRef?.latest ?? null)) return 0;
    const r = await tx.execute(sql`
      UPDATE findings
      SET raw_evidence_ref = ${JSON.stringify(ref)}::jsonb,
          raw_evidence = NULL
      WHERE id = ${findingId}
        AND tenant_id = ${tenantId}
        AND raw_evidence IS NOT NULL
    `);
    return r.rowCount ?? 0;
  });

  return updated > 0;
}

/** Run one tiering sweep across all tenants. Inert (skippedNoStore) unless an
 *  EXTERNAL raw-evidence store is registered. Per-tenant scan mirrors
 *  `backfillEmbeddings`: enumerate tenants holding inline raw, then operate
 *  inside `withTenant()` so RLS stays enforced for every read + write. */
export async function tierRawEvidenceOnce(
  deps: TierRawEvidenceDeps,
): Promise<TierRawEvidenceResult> {
  const store =
    deps.store === undefined ? getRawEvidenceStoreOrNull() : deps.store;
  const now = deps.now ?? Date.now;
  const result: TierRawEvidenceResult = {
    scanned: 0,
    tiered: 0,
    failed: 0,
    skippedNoStore: false,
  };

  // Default-inert: only an external WORM store can receive tiered objects.
  if (!store || !store.external) {
    result.skippedNoStore = true;
    return result;
  }

  const cutoff = new Date(now() - deps.ageMs);

  const tenantRows = await db.execute<{ tenant_id: string }>(
    sql`SELECT DISTINCT tenant_id FROM findings WHERE raw_evidence IS NOT NULL`,
  );

  for (const { tenant_id } of tenantRows.rows) {
    const candidates = await withTenant(tenant_id, async (tx) => {
      const r = await tx.execute<{ id: string; raw_evidence: unknown }>(sql`
        SELECT id, raw_evidence
        FROM findings
        WHERE tenant_id = ${tenant_id}
          AND raw_evidence IS NOT NULL
          AND last_seen_at < ${cutoff}
        ORDER BY last_seen_at ASC
        LIMIT ${deps.batchSize}
      `);
      return r.rows;
    });

    for (const row of candidates) {
      result.scanned++;
      try {
        const migrated = await tierOneFinding({
          store,
          tenantId: tenant_id,
          findingId: row.id,
          inline: row.raw_evidence,
        });
        if (!migrated) {
          // A concurrent re-hit changed the row out from under us; nothing was
          // nulled. Not a failure — the next cadence picks it up. No ledger.
          logger.debug(
            { finding_id: row.id },
            "raw-evidence tiering skipped finding (row changed concurrently)",
          );
          continue;
        }
        result.tiered++;
        await appendLedger({
          tenantId: tenant_id,
          actor: { kind: "system", id: "raw_evidence_tiering" },
          eventType: "raw_evidence.tiered",
          subjectType: "finding",
          subjectId: row.id,
          // finding id + provider only. The object URIs live in
          // raw_evidence_ref (out of findingSafeColumns); raw PHI never here.
          payload: { finding_id: row.id, provider: store.name },
        });
      } catch (err) {
        result.failed++;
        // Log the error NAME only — never the raw `err`. Object-store SDK
        // errors can embed the failing object URI (bucket + tenant/finding key)
        // in their message/metadata, and the hard rule for this surface is no
        // object URIs in logs OR the ledger (the URIs live in raw_evidence_ref,
        // out of findingSafeColumns). The name (AccessDenied / Timeout / …) is
        // the URI-free diagnostic on-call needs; matches the ledger payload.
        const errorName = err instanceof Error ? err.name : "unknown";
        logger.error(
          { error_name: errorName, finding_id: row.id, provider: store.name },
          "raw-evidence tiering failed for finding; inline copy preserved, will retry next cadence",
        );
        await appendLedger({
          tenantId: tenant_id,
          actor: { kind: "system", id: "raw_evidence_tiering" },
          eventType: "raw_evidence.tier_failed",
          subjectType: "finding",
          subjectId: row.id,
          payload: {
            finding_id: row.id,
            provider: store.name,
            error: errorName,
          },
        });
      }
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Leader lock + scheduler
// ---------------------------------------------------------------------------
//
// Single dedicated advisory-lock key, distinct from the chain-verifier keys
// (chain-verifier.ts: 0x10/0x11/0x12) and the ledger writer lock. Same
// pool-checkout discipline as chain-verifier: hold one connection across
// try-lock → fn → unlock so the pool can't hand the unlock to a different
// connection that never owned the lock.
const TIERING_LOCK_KEY = 7331_4242_0000_0013n;

async function withLeaderLock<T>(fn: () => Promise<T>): Promise<T | "skipped"> {
  const client = await pool.connect();
  let unlockFailed: Error | null = null;
  try {
    const got = await client.query<{ got: boolean }>(
      "SELECT pg_try_advisory_lock($1::bigint) AS got",
      [TIERING_LOCK_KEY.toString()],
    );
    if (!got.rows[0]?.got) {
      logger.debug("raw-evidence tiering skipped — leader lock held elsewhere");
      return "skipped";
    }
    try {
      return await fn();
    } finally {
      try {
        await client.query("SELECT pg_advisory_unlock($1::bigint)", [
          TIERING_LOCK_KEY.toString(),
        ]);
      } catch (err) {
        unlockFailed = err as Error;
        logger.warn(
          { err },
          "failed to release raw-evidence tiering advisory lock; destroying pool client to avoid leaked session lock",
        );
      }
    }
  } finally {
    client.release(unlockFailed ?? undefined);
  }
}

async function runTierOnce(cfg: RawEvidenceTieringConfig): Promise<void> {
  await withLeaderLock(async () => {
    try {
      const r = await tierRawEvidenceOnce({
        ageMs: cfg.ageMs,
        batchSize: cfg.batchSize,
      });
      if (r.tiered > 0 || r.failed > 0) {
        logger.info(r, "raw-evidence tiering run complete");
      } else {
        logger.debug(r, "raw-evidence tiering run complete (nothing to tier)");
      }
    } catch (err) {
      logger.error({ err }, "raw-evidence tiering run failed");
    }
  });
}

/** Start the periodic raw-evidence tiering job. Returns a stop() handle.
 *
 *  Default-INERT: returns a no-op stop() (and schedules nothing) unless BOTH
 *  the opt-in env is set AND an external store is active. `cfgOverride` is for
 *  tests; `undefined` reads env, explicit `null` forces disabled. */
export function startRawEvidenceTiering(
  cfgOverride?: RawEvidenceTieringConfig | null,
): () => void {
  const cfg =
    cfgOverride === undefined ? loadRawEvidenceTieringConfigFromEnv() : cfgOverride;
  if (!cfg) {
    logger.info(
      "raw-evidence tiering disabled (RAW_EVIDENCE_TIER_AGE_DAYS unset)",
    );
    return () => {};
  }

  const store = getRawEvidenceStoreOrNull();
  if (!store || !store.external) {
    logger.warn(
      { provider: store?.name ?? "none" },
      "RAW_EVIDENCE_TIER_AGE_DAYS is set but no EXTERNAL raw-evidence store is " +
        "configured; tiering inert (the inline DB store has no WORM tier to age into)",
    );
    return () => {};
  }

  const timer = setInterval(() => void runTierOnce(cfg), cfg.intervalMs);
  timer.unref?.();
  logger.info(
    {
      ageMs: cfg.ageMs,
      intervalMs: cfg.intervalMs,
      batchSize: cfg.batchSize,
      provider: store.name,
    },
    "raw-evidence tiering scheduled",
  );
  return () => clearInterval(timer);
}

// Exported for direct testing without spinning up setInterval.
export const __test__ = {
  withLeaderLock,
  runTierOnce,
  tierOneFinding,
  normalizeInline,
  TIERING_LOCK_KEY,
};
