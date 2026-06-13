// M8: Shared base for pull-based cloud log source adapters.
//
// `CloudwatchLogSource` (cloud-log-sources.ts) shipped first and is left
// untouched as the proven reference impl. GCP Cloud Logging and Azure
// Monitor reuse the exact same machinery — poll loop, exponential backoff,
// lifecycle ledger rows, interruptible sleep, per-group cursor with a
// CONTIGUOUS-success watermark, and bounded per-group concurrency — so that
// logic lives here once. A concrete adapter only implements `fetchGroup`
// (the cloud-specific "list events newer than this cursor" call); the base
// owns everything else.
//
// Per ARCHITECTURE.md §3 / §17.2 the system is interface-first (`LogSource`
// is the seam). Per threat_model "System ↔ Log Sources" log content is
// attacker-controlled — the base never inspects `payload` bytes beyond
// wrapping them in a LogRecord for the ingest pipeline to detect+redact.
//
// Default-inert: this module loads no cloud SDK by itself; subclasses
// lazy-import their SDK only when actually constructed+started, which only
// happens when an operator sets `LOG_SOURCE`.

import { appendLedger } from "./ledger";
import { logger } from "./logger";
import type { LogRecord, LogSource, LogSourceType } from "./log-source";
import { DbCheckpointStore, type CheckpointStore } from "./cloud-log-sources";

/** One fetched, not-yet-published event. `ts` is the source-side event time
 *  in ms epoch — the value the cursor watermark advances over. */
export interface CollectedRecord {
  ts: number;
  record: LogRecord;
  sourceRecordId: string;
}

export interface PollingLogSourceOpts {
  readonly tenantId: string;
  /** Logical groups to poll (CloudWatch log groups, GCP log ids, Azure
   *  tables). Each gets its own independent cursor. */
  readonly groups: ReadonlyArray<string>;
  /** Publish into the bus. Wired to `logBus.publish("raw.logs", r)` at boot. */
  readonly publish: (record: LogRecord) => Promise<unknown>;
  /** Tick interval. Default 5s. */
  readonly pollIntervalMs?: number;
  /** Lookback window on the very first poll of a group with no stored cursor.
   *  Default 5min. */
  readonly lookbackMsOnFirstPoll?: number;
  /** Initial backoff after a loop-level error; doubles per consecutive
   *  failure, capped at `maxBackoffMs`. Default 1s. */
  readonly initialBackoffMs?: number;
  /** Backoff cap. Default 60s. */
  readonly maxBackoffMs?: number;
  /** Max groups polled concurrently per tick. Default 1 (sequential — same
   *  ordering as the original CloudWatch source). Bounded so a wide fan-out
   *  of log groups can't open an unbounded number of in-flight SDK calls. */
  readonly maxConcurrentGroups?: number;
  /** Test injection: bypass the DB-backed checkpoint store. */
  readonly checkpointStore?: CheckpointStore;
}

/** Tiny non-crypto hash — disambiguates same-ms events when a source elides a
 *  stable record id. Not used for any security decision. Mirrors the helper in
 *  cloud-log-sources.ts so adapters built on this base can synthesize a
 *  `sourceRecordId` the same way CloudWatch does. */
export function shortHash(s: string): string {
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16);
}

export abstract class PollingLogSource implements LogSource {
  abstract readonly name: string;
  /** LogRecord.sourceType stamped on every emitted record. */
  protected abstract readonly sourceType: LogSourceType;
  /** Short provider label for ledger payloads + log lines. */
  protected abstract readonly provider: string;

  /** Fetch events for one group newer than `startTimeMs` (the base passes the
   *  stored cursor + 1ms, so it is effectively exclusive of the cursor). The
   *  adapter handles its own cloud-specific pagination/limit; the base sorts,
   *  publishes with a contiguous-success watermark, and persists the cursor. */
  protected abstract fetchGroup(
    group: string,
    startTimeMs: number,
  ): Promise<CollectedRecord[]>;

  private running = false;
  private stopRequested = false;
  private loopPromise: Promise<void> | null = null;
  private wakeUp: (() => void) | null = null;

  protected readonly store: CheckpointStore;
  protected readonly pollIntervalMs: number;
  protected readonly lookbackMsOnFirstPoll: number;
  private readonly initialBackoffMs: number;
  private readonly maxBackoffMs: number;
  private readonly maxConcurrentGroups: number;

  constructor(protected readonly baseOpts: PollingLogSourceOpts) {
    if (baseOpts.groups.length === 0) {
      throw new Error("PollingLogSource: at least one group required");
    }
    this.store = baseOpts.checkpointStore ?? new DbCheckpointStore();
    this.pollIntervalMs = baseOpts.pollIntervalMs ?? 5000;
    this.lookbackMsOnFirstPoll = baseOpts.lookbackMsOnFirstPoll ?? 5 * 60 * 1000;
    this.initialBackoffMs = baseOpts.initialBackoffMs ?? 1000;
    this.maxBackoffMs = baseOpts.maxBackoffMs ?? 60_000;
    this.maxConcurrentGroups = Math.max(1, baseOpts.maxConcurrentGroups ?? 1);
  }

  async start(): Promise<void> {
    if (this.running) return;
    // Append-then-flip (same invariant as CloudwatchLogSource): emit the
    // lifecycle row BEFORE setting running=true so a ledger failure at boot
    // leaves a clean not-started state the caller can retry, never a
    // running=true/loop=null zombie.
    await appendLedger({
      tenantId: this.baseOpts.tenantId,
      actor: { kind: "system", id: "ingest" },
      eventType: "ingest.source_started",
      subjectType: "log_source",
      subjectId: this.name,
      payload: {
        provider: this.provider,
        groups: this.baseOpts.groups,
        poll_interval_ms: this.pollIntervalMs,
        max_concurrent_groups: this.maxConcurrentGroups,
      },
    });
    this.running = true;
    this.stopRequested = false;
    this.loopPromise = this.runLoop();
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.stopRequested = true;
    if (this.wakeUp) this.wakeUp();
    try {
      await this.loopPromise;
    } finally {
      this.running = false;
      this.loopPromise = null;
      await appendLedger({
        tenantId: this.baseOpts.tenantId,
        actor: { kind: "system", id: "ingest" },
        eventType: "ingest.source_stopped",
        subjectType: "log_source",
        subjectId: this.name,
        payload: { provider: this.provider, groups: this.baseOpts.groups },
      });
    }
  }

  /** Public for tests: drive exactly one poll across all groups and return
   *  totals. Groups are polled with bounded concurrency (`maxConcurrentGroups`,
   *  default 1 = sequential). */
  async pollOnce(): Promise<{ published: number; fetched: number }> {
    let published = 0;
    let fetched = 0;
    const queue = [...this.baseOpts.groups];
    const worker = async (): Promise<void> => {
      for (;;) {
        const group = queue.shift();
        if (group === undefined) return;
        const r = await this.pollGroup(group);
        published += r.published;
        fetched += r.fetched;
      }
    };
    const workers = Math.min(this.maxConcurrentGroups, this.baseOpts.groups.length);
    await Promise.all(Array.from({ length: workers }, () => worker()));
    return { published, fetched };
  }

  private async pollGroup(
    group: string,
  ): Promise<{ published: number; fetched: number }> {
    const cursorKey = `${this.name}:${group}`;
    const existing = await this.store.load(cursorKey);
    // Cursor + 1ms so we don't re-fetch the cursor event itself; lookback
    // window on the first poll of a fresh group (operator can pre-seed the
    // checkpoint to 0 for from-beginning).
    const startTimeMs =
      existing !== null ? existing + 1 : Date.now() - this.lookbackMsOnFirstPoll;

    const collected = await this.fetchGroup(group, startTimeMs);
    // Sort ascending so the contiguous-success prefix is well-defined.
    collected.sort((a, b) => a.ts - b.ts);

    let watermark = existing ?? 0;
    let firstFailureSeen = false;
    let published = 0;
    for (const c of collected) {
      try {
        await this.baseOpts.publish(c.record);
        published++;
        // Only advance the watermark over the CONTIGUOUS success prefix. Once
        // any publish fails we freeze it; the failing record AND every later
        // record in this batch are re-fetched next tick (ingest dedupes by
        // fingerprint), guaranteeing at-least-once without losing the failure.
        if (!firstFailureSeen && c.ts > watermark) watermark = c.ts;
      } catch (err) {
        firstFailureSeen = true;
        logger.warn(
          { err, group, sourceRecordId: c.sourceRecordId, eventTs: c.ts },
          `${this.provider} source: publish failed; freezing watermark, will retry from this ts on next tick`,
        );
      }
    }

    if (watermark > (existing ?? 0)) {
      await this.store.save(cursorKey, this.baseOpts.tenantId, watermark);
    }
    return { published, fetched: collected.length };
  }

  private async runLoop(): Promise<void> {
    let consecutiveFailures = 0;
    while (!this.stopRequested) {
      const tickStart = Date.now();
      try {
        await this.pollOnce();
        consecutiveFailures = 0;
      } catch (err) {
        consecutiveFailures++;
        const backoff = Math.min(
          this.maxBackoffMs,
          this.initialBackoffMs * 2 ** (consecutiveFailures - 1),
        );
        // Best-effort ledger append: if the ledger itself is down at the same
        // time as the upstream failure, an unhandled rejection here would kill
        // the loop. Log-and-continue keeps polling.
        try {
          await appendLedger({
            tenantId: this.baseOpts.tenantId,
            actor: { kind: "system", id: "ingest" },
            eventType: "ingest.source_error",
            subjectType: "log_source",
            subjectId: this.name,
            payload: {
              provider: this.provider,
              error: err instanceof Error ? err.message : String(err),
              consecutive_failures: consecutiveFailures,
              backoff_ms: backoff,
              groups: this.baseOpts.groups,
            },
          });
        } catch (ledgerErr) {
          logger.error(
            { err, ledgerErr, source: this.name },
            `${this.provider} source: failed to ledger ingest.source_error; continuing poll loop`,
          );
        }
        await this.interruptibleSleep(backoff);
        continue;
      }
      const elapsed = Date.now() - tickStart;
      const sleepMs = Math.max(0, this.pollIntervalMs - elapsed);
      if (sleepMs > 0 && !this.stopRequested) {
        await this.interruptibleSleep(sleepMs);
      }
    }
  }

  /** Sleep for `ms` OR until `stop()` wakes us — whichever is first. */
  private interruptibleSleep(ms: number): Promise<void> {
    return new Promise<void>((resolve) => {
      let done = false;
      const finish = (): void => {
        if (done) return;
        done = true;
        clearTimeout(t);
        this.wakeUp = null;
        resolve();
      };
      const t = setTimeout(finish, ms);
      if (typeof t.unref === "function") t.unref();
      this.wakeUp = finish;
    });
  }
}

/** Shared SDK lazy loader — hides the dynamic import id from the TS static
 *  analyzer so the cloud SDKs stay optional deps (a dev install never pulls
 *  them). Same pattern as cloud-embedders.ts / cloud-log-sources.ts. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function loadOptionalSdk(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

/** Parse a bounded positive int env var, falling back to `fallback`. */
export function parsePositiveIntEnv(
  raw: string | undefined,
  fallback: number,
): number {
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}
