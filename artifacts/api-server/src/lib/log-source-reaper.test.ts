import { describe, it, expect, beforeAll, beforeEach } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import {
  db,
  ledgerEntriesTable,
  logSourceCheckpointsTable,
  bootstrap,
} from "@workspace/db";
import {
  getReaperConfigFromEnv,
  reapStalledSourcesOnce,
  startLogSourceReaper,
  stalledSourceLatch,
  type ReaperConfig,
} from "./log-source-reaper";
import { appendLedger as realAppendLedger } from "./ledger";
import { uniq, uniqueTenant, ledgerHeadSeq } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

// Each test starts from a clean in-memory latch so edge-trigger assertions
// don't bleed across cases (the latch is module-global by design).
beforeEach(() => {
  stalledSourceLatch.clear();
});

const MIN = 60_000;

/** Insert a checkpoint with an explicit `updated_at` so we can place a cursor
 *  arbitrarily far in the past without waiting. Returns the source name. */
async function seedCheckpoint(opts: {
  tenantId: string;
  ageMs: number;
  now?: number;
}): Promise<string> {
  const sourceName = `reaper-${uniq()}`;
  const now = opts.now ?? Date.now();
  const updatedAt = new Date(now - opts.ageMs);
  await db.insert(logSourceCheckpointsTable).values({
    sourceName,
    tenantId: opts.tenantId,
    lastEventTs: now - opts.ageMs,
    updatedAt,
  });
  return sourceName;
}

/** Move an existing checkpoint's `updated_at` (simulate the cursor advancing or
 *  going stale). */
async function setCheckpointAge(sourceName: string, ageMs: number, now = Date.now()) {
  await db
    .update(logSourceCheckpointsTable)
    .set({ updatedAt: new Date(now - ageMs) })
    .where(eq(logSourceCheckpointsTable.sourceName, sourceName));
}

async function stalledLedgerRowsFor(
  sourceName: string,
  sinceSeq: number,
): Promise<{ tenantId: string | null; payload: unknown }[]> {
  const rows = await db
    .select({
      tenantId: ledgerEntriesTable.tenantId,
      payload: ledgerEntriesTable.payload,
    })
    .from(ledgerEntriesTable)
    .where(
      and(
        gt(ledgerEntriesTable.seq, sinceSeq),
        eq(ledgerEntriesTable.eventType, "ingest.source_stalled"),
        eq(ledgerEntriesTable.subjectId, sourceName),
      ),
    );
  return rows;
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

describe("getReaperConfigFromEnv", () => {
  it("returns null (disabled) when INGEST_SOURCE_STALL_AFTER_MS is unset/empty", () => {
    expect(getReaperConfigFromEnv({})).toBeNull();
    expect(
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "" }),
    ).toBeNull();
    expect(
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "   " }),
    ).toBeNull();
  });

  it("defaults the check interval to the stall threshold", () => {
    expect(
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "300000" }),
    ).toEqual({ staleAfterMs: 300000, intervalMs: 300000 });
  });

  it("parses an independent check interval and floors both", () => {
    expect(
      getReaperConfigFromEnv({
        INGEST_SOURCE_STALL_AFTER_MS: "300000.9",
        INGEST_SOURCE_STALL_CHECK_INTERVAL_MS: "60000.5",
      }),
    ).toEqual({ staleAfterMs: 300000, intervalMs: 60000 });
  });

  it("throws on a non-positive / non-numeric threshold or interval", () => {
    expect(() =>
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "0" }),
    ).toThrow(/positive number/);
    expect(() =>
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "-1" }),
    ).toThrow(/positive number/);
    expect(() =>
      getReaperConfigFromEnv({ INGEST_SOURCE_STALL_AFTER_MS: "abc" }),
    ).toThrow(/positive number/);
    expect(() =>
      getReaperConfigFromEnv({
        INGEST_SOURCE_STALL_AFTER_MS: "300000",
        INGEST_SOURCE_STALL_CHECK_INTERVAL_MS: "-5",
      }),
    ).toThrow(/positive number/);
  });
});

// ---------------------------------------------------------------------------
// startLogSourceReaper inertness
// ---------------------------------------------------------------------------

describe("startLogSourceReaper (default-inert)", () => {
  it("schedules nothing and returns a no-op stop when config is null", () => {
    const stop = startLogSourceReaper(null);
    expect(typeof stop).toBe("function");
    // No throw on stop().
    stop();
  });
});

// ---------------------------------------------------------------------------
// reapStalledSourcesOnce — core edge-triggered scan
// ---------------------------------------------------------------------------

describe("reapStalledSourcesOnce", () => {
  const config: ReaperConfig = { staleAfterMs: 5 * MIN, intervalMs: 5 * MIN };

  it("does not alert a fresh cursor (under the stall threshold)", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    const src = await seedCheckpoint({ tenantId: tenant, ageMs: 1 * MIN });

    const res = await reapStalledSourcesOnce({ config });
    expect(res.scanned).toBeGreaterThanOrEqual(1);
    expect(stalledSourceLatch.has(src)).toBe(false);
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(0);
  });

  it("emits exactly one ingest.source_stalled when a cursor first crosses the threshold", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    const src = await seedCheckpoint({ tenantId: tenant, ageMs: 10 * MIN });

    const res = await reapStalledSourcesOnce({ config });
    expect(res.stalled).toBeGreaterThanOrEqual(1);
    expect(stalledSourceLatch.has(src)).toBe(true);

    const rows = await stalledLedgerRowsFor(src, before);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tenantId).toBe(tenant);
    const payload = rows[0]!.payload as {
      source_name: string;
      idle_ms: number;
      stale_after_ms: number;
    };
    expect(payload.source_name).toBe(src);
    expect(payload.stale_after_ms).toBe(config.staleAfterMs);
    expect(payload.idle_ms).toBeGreaterThanOrEqual(10 * MIN - 5000);
  });

  it("is edge-triggered: a still-stalled cursor does not re-alert on the next scan", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    const src = await seedCheckpoint({ tenantId: tenant, ageMs: 10 * MIN });

    await reapStalledSourcesOnce({ config });
    await reapStalledSourcesOnce({ config });
    await reapStalledSourcesOnce({ config });

    // Despite three scans, the rising edge fired exactly once.
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(1);
    expect(stalledSourceLatch.has(src)).toBe(true);
  });

  it("does NOT latch when the ledger append fails, so the next scan re-alerts", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    const src = await seedCheckpoint({ tenantId: tenant, ageMs: 10 * MIN });

    // First scan: the ledger writer throws a transient failure. The source must
    // stay UNLATCHED so the stall episode is not permanently suppressed.
    let calls = 0;
    const flakyAppend = (async (...args: Parameters<typeof realAppendLedger>) => {
      calls++;
      if (calls === 1) throw new Error("transient ledger blip");
      return realAppendLedger(...args);
    }) as typeof realAppendLedger;

    await expect(
      reapStalledSourcesOnce({ config, appendLedger: flakyAppend }),
    ).rejects.toThrow(/transient ledger blip/);
    expect(stalledSourceLatch.has(src)).toBe(false);
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(0);

    // Second scan (writer healthy): the same still-stalled cursor re-alerts —
    // at-least-once delivery for the missed-PHI signal.
    const r2 = await reapStalledSourcesOnce({ config, appendLedger: flakyAppend });
    expect(r2.stalled).toBeGreaterThanOrEqual(1);
    expect(stalledSourceLatch.has(src)).toBe(true);
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(1);
  });

  it("clears the latch when the cursor advances again, re-arming the alert", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    const src = await seedCheckpoint({ tenantId: tenant, ageMs: 10 * MIN });

    // Stall episode 1.
    const r1 = await reapStalledSourcesOnce({ config });
    expect(r1.stalled).toBeGreaterThanOrEqual(1);
    expect(stalledSourceLatch.has(src)).toBe(true);

    // Cursor advances (fresh) → next scan clears the latch (recovery edge).
    await setCheckpointAge(src, 0);
    const r2 = await reapStalledSourcesOnce({ config });
    expect(r2.recovered).toBeGreaterThanOrEqual(1);
    expect(stalledSourceLatch.has(src)).toBe(false);

    // Stall again → a brand-new rising edge re-alerts.
    await setCheckpointAge(src, 10 * MIN);
    const r3 = await reapStalledSourcesOnce({ config });
    expect(r3.stalled).toBeGreaterThanOrEqual(1);

    // Two distinct stall episodes ⇒ two ledger events.
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(2);
  });

  it("honors an injected clock", async () => {
    const tenant = uniqueTenant("reaper");
    const before = await ledgerHeadSeq();
    // Cursor 3 minutes old vs a 5-minute threshold ⇒ fresh under real clock.
    const realNow = Date.now();
    const src = await seedCheckpoint({
      tenantId: tenant,
      ageMs: 3 * MIN,
      now: realNow,
    });

    // Fresh under the real clock ⇒ src does not latch or alert.
    await reapStalledSourcesOnce({ config, now: () => realNow });
    expect(stalledSourceLatch.has(src)).toBe(false);
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(0);

    // Advance the injected clock 10 minutes ⇒ now stale.
    await reapStalledSourcesOnce({
      config,
      now: () => realNow + 10 * MIN,
    });
    expect(stalledSourceLatch.has(src)).toBe(true);
    expect(await stalledLedgerRowsFor(src, before)).toHaveLength(1);
  });
});
