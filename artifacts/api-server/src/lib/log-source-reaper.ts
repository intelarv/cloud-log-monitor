// M8 (reaper): stuck-cursor detector for pull-based log sources.
//
// A real cloud log source (CloudWatch / Cloud Logging / Azure Monitor) commits
// its read position to `log_source_checkpoints` after every successful poll
// batch (see cloud-log-sources.ts / polling-log-source.ts). If a poller wedges
// — a crashed loop, an expired credential the adapter keeps retrying, a quota
// wall, a network partition — the cursor stops advancing and ingest silently
// goes quiet. For a compliance system "we stopped seeing logs and nobody
// noticed" is a real gap (missed PHI detections), but it is invisible at the
// finding level (no findings simply looks like a calm period).
//
// This job periodically scans the checkpoint table and emits a warning-level
// `ingest.source_stalled` ledger event (→ alert/channel route) for any cursor
// whose `updated_at` is older than the operator-configured stall threshold.
//
// Safety posture (mirrors the memory-eviction / raw-evidence-tiering jobs):
//   - Default-INERT. Scheduled only when `INGEST_SOURCE_STALL_AFTER_MS` is set.
//     Unset ⇒ nothing runs; dev boot + the offline eval gate are byte-identical
//     (and with no cloud source configured the checkpoint table is empty anyway).
//   - No PHI. The checkpoint table holds only source names + cursor positions;
//     the ledger payload carries the source name + idle duration + threshold.
//   - Leader-locked (its own Postgres advisory key) so only one pod reaps per
//     cadence in a multi-instance deployment; setInterval is `.unref()`ed.
//   - EDGE-TRIGGERED. A perpetually-idle source must not storm the alert channel
//     every cadence, so we latch which sources have already alerted and re-emit
//     only when a stalled cursor first crosses the threshold; the latch clears
//     when the cursor advances again (re-arming the alert for the next episode).
//     In-memory by design — a best-effort de-dup, not an audit record; every
//     emitted stall is independently ledgered, and a process restart simply
//     re-learns the state on the next scan.

import { sql } from "drizzle-orm";
import { db, pool } from "@workspace/db";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import type { WorkflowEngine } from "./agents/workflow-engine";

// Temporal cron cadence for the reaper (5-field cron). Only consulted on the
// WORKFLOW_ENGINE=temporal path — the in-process path honors the env-configured
// `intervalMs` instead (see startLogSourceReaper). Every 5 minutes mirrors the
// notarizer cron; under Temporal the cron IS the production cadence knob.
const LOG_SOURCE_REAPER_CRON = "*/5 * * * *";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface ReaperConfig {
  /** A cursor whose `updated_at` is older than this is considered stalled. */
  staleAfterMs: number;
  /** Scan cadence. */
  intervalMs: number;
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

/** Parse env into a reaper config. Returns null (disabled) when the opt-in
 *  `INGEST_SOURCE_STALL_AFTER_MS` is unset — surfacing stalls is consequential
 *  (it alerts), so it never turns on implicitly. The check interval defaults to
 *  the stall threshold (so a stall is noticed within ~2× the threshold) but can
 *  be set independently. Pure: no I/O. */
export function getReaperConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): ReaperConfig | null {
  const staleRaw = env["INGEST_SOURCE_STALL_AFTER_MS"]?.trim();
  if (!staleRaw) return null;
  const staleAfterMs = parsePositiveInt(
    staleRaw,
    0,
    "INGEST_SOURCE_STALL_AFTER_MS",
  );
  return {
    staleAfterMs,
    intervalMs: parsePositiveInt(
      env["INGEST_SOURCE_STALL_CHECK_INTERVAL_MS"],
      staleAfterMs,
      "INGEST_SOURCE_STALL_CHECK_INTERVAL_MS",
    ),
  };
}

// ---------------------------------------------------------------------------
// Edge-trigger latch
// ---------------------------------------------------------------------------

/** Sources currently latched as "already alerted stalled", keyed by
 *  source_name. A stalled cursor adds its key (and alerts once); a cursor that
 *  has advanced past the threshold again removes its key (re-arming the alert).
 *  In-memory + best-effort by design — see the module header. Exported only so
 *  tests can reset it between cases. */
export const stalledSourceLatch = new Set<string>();

// ---------------------------------------------------------------------------
// Core scan (testable, dependency-injected)
// ---------------------------------------------------------------------------

export interface ReapDeps {
  config: ReaperConfig;
  /** Injectable clock for tests. Defaults to Date.now. */
  now?: () => number;
  /** Injectable ledger writer for tests (e.g. to simulate a transient append
   *  failure and assert the latch is NOT set). Defaults to the real writer. */
  appendLedger?: typeof appendLedger;
}

export interface ReapResult {
  /** Checkpoints examined. */
  scanned: number;
  /** Newly-stalled cursors that alerted this run (edge-triggered). */
  stalled: number;
  /** Previously-stalled cursors that have since recovered (latch cleared). */
  recovered: number;
}

interface CheckpointRow {
  source_name: string;
  tenant_id: string;
  updated_ms: number | string;
  [key: string]: unknown;
}

/** Run one stall scan over `log_source_checkpoints`. Edge-triggered: emits
 *  `ingest.source_stalled` only for cursors that have newly crossed the stall
 *  threshold since the last scan, and clears the latch for cursors that have
 *  advanced again. */
export async function reapStalledSourcesOnce(
  deps: ReapDeps,
): Promise<ReapResult> {
  const now = deps.now ?? Date.now;
  const append = deps.appendLedger ?? appendLedger;
  const { staleAfterMs } = deps.config;
  const result: ReapResult = { scanned: 0, stalled: 0, recovered: 0 };

  const rows = await db.execute<CheckpointRow>(sql`
    SELECT
      source_name,
      tenant_id,
      extract(epoch FROM updated_at) * 1000 AS updated_ms
    FROM log_source_checkpoints
  `);
  result.scanned = rows.rows.length;

  const cutoff = now() - staleAfterMs;
  for (const row of rows.rows) {
    const updatedMs = Number(row.updated_ms);
    const isStalled = updatedMs < cutoff;
    const alreadyAlerted = stalledSourceLatch.has(row.source_name);

    if (isStalled && !alreadyAlerted) {
      // Rising edge — emit the durable alert FIRST, then latch. Latching only
      // after a successful append is load-bearing: if `appendLedger` throws
      // (transient ledger/DB blip) we must NOT latch, or the next scan would
      // see `alreadyAlerted=true` and suppress re-emission, leaving this stall
      // episode permanently invisible (no `ingest.source_stalled` ever
      // written). Leaving it unlatched on failure means the next scan retries
      // the alert — at-least-once, the correct posture for a missed-PHI signal.
      const idleMs = now() - updatedMs;
      await append({
        tenantId: row.tenant_id,
        actor: { kind: "system", id: "log_source_reaper" },
        eventType: "ingest.source_stalled",
        subjectType: "log_source",
        subjectId: row.source_name,
        // Source name + idle duration + policy threshold only. No PHI: the
        // checkpoint table never holds payload content.
        payload: {
          source_name: row.source_name,
          idle_ms: idleMs,
          stale_after_ms: staleAfterMs,
        },
      });
      stalledSourceLatch.add(row.source_name);
      result.stalled++;
    } else if (!isStalled && alreadyAlerted) {
      // Cursor advanced again — clear the latch so the next stall re-alerts.
      stalledSourceLatch.delete(row.source_name);
      result.recovered++;
    }
  }

  return result;
}

// ---------------------------------------------------------------------------
// Leader lock + scheduler
// ---------------------------------------------------------------------------
//
// Dedicated advisory-lock key, distinct from the ledger writer (…_0001n), the
// chain-verifier keys (…_0010n–_0012n), the raw-evidence tiering key (…_0013n),
// and the memory-eviction key (…_0014n). Same pool-checkout discipline: hold one
// connection across try-lock → fn → unlock so the pool can't hand the unlock to
// a connection that never owned the lock.
const REAPER_LOCK_KEY = 7331_4242_0000_0015n;

async function withLeaderLock<T>(fn: () => Promise<T>): Promise<T | "skipped"> {
  const client = await pool.connect();
  let unlockFailed: Error | null = null;
  try {
    const got = await client.query<{ got: boolean }>(
      "SELECT pg_try_advisory_lock($1::bigint) AS got",
      [REAPER_LOCK_KEY.toString()],
    );
    if (!got.rows[0]?.got) {
      logger.debug("log-source reaper skipped — leader lock held elsewhere");
      return "skipped";
    }
    try {
      return await fn();
    } finally {
      try {
        await client.query("SELECT pg_advisory_unlock($1::bigint)", [
          REAPER_LOCK_KEY.toString(),
        ]);
      } catch (err) {
        unlockFailed = err as Error;
        logger.warn(
          { err },
          "failed to release log-source reaper advisory lock; destroying pool client to avoid leaked session lock",
        );
      }
    }
  } finally {
    client.release(unlockFailed ?? undefined);
  }
}

async function runReapOnce(config: ReaperConfig): Promise<void> {
  await withLeaderLock(async () => {
    try {
      const r = await reapStalledSourcesOnce({ config });
      if (r.stalled > 0 || r.recovered > 0) {
        logger.info(r, "log-source reaper run complete");
      } else {
        logger.debug(r, "log-source reaper run complete (no stalled sources)");
      }
    } catch (err) {
      logger.error({ err }, "log-source reaper run failed");
    }
  });
}

/** Env-driven reaper cycle bound as the Temporal `runCycle` activity (see
 *  log-source-reaper-steps.ts). The Temporal worker runs in its own process and
 *  re-reads the opt-in config itself; this no-ops when the reaper is disabled,
 *  so registering the workflow on the cluster is harmless when
 *  `INGEST_SOURCE_STALL_AFTER_MS` is unset — same default-inert posture the
 *  remediation-executor activity uses. The in-process path does NOT call this;
 *  it runs `runReapOnce(config)` directly with the config captured in
 *  startLogSourceReaper's closure. */
export async function runReapCycleFromEnv(): Promise<void> {
  const config = getReaperConfigFromEnv();
  if (!config) return;
  await runReapOnce(config);
}

/** Schedule the periodic stuck-cursor reaper through the WorkflowEngine seam,
 *  mirroring `startNotarizer`. Returns a stop() handle.
 *
 *  Default-INERT: returns a no-op stop() (and schedules nothing) unless the
 *  opt-in `INGEST_SOURCE_STALL_AFTER_MS` is set. `cfgOverride` is for tests;
 *  `undefined` reads env, explicit `null` forces disabled.
 *
 *  In-process: a leader-locked setInterval, byte-identical to the pre-seam timer
 *  this replaces (the `run` callback is the same `runReapOnce(config)`). Under
 *  WORKFLOW_ENGINE=temporal: a durable cron workflow (`logSourceReaperWorkflow`),
 *  so the reaper gains the same single-execution + crash-resume guarantees as
 *  the notarizer + review paths. The `cfgOverride` only affects the in-process
 *  cadence (tests); the Temporal cadence is LOG_SOURCE_REAPER_CRON. */
export function startLogSourceReaper(
  engine: WorkflowEngine,
  cfgOverride?: ReaperConfig | null,
): () => void {
  const config =
    cfgOverride === undefined ? getReaperConfigFromEnv() : cfgOverride;
  if (!config) {
    logger.info(
      "log-source reaper disabled (INGEST_SOURCE_STALL_AFTER_MS unset)",
    );
    return () => {};
  }

  const stop = engine.schedulePeriodic({
    name: "log-source-reaper",
    intervalMs: config.intervalMs,
    cronSchedule: LOG_SOURCE_REAPER_CRON,
    workflowType: "logSourceReaperWorkflow",
    run: () => runReapOnce(config),
  });
  logger.info(
    {
      engine: engine.kind,
      staleAfterMs: config.staleAfterMs,
      intervalMs: config.intervalMs,
    },
    "log-source reaper scheduled via workflow engine",
  );
  return stop;
}

// Exported for direct testing without spinning up setInterval.
export const __test__ = {
  withLeaderLock,
  runReapOnce,
  REAPER_LOCK_KEY,
};
