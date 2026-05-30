// M8: Real cloud log source adapters.
//
// Mirrors the lazy-load pattern in cloud-embedders.ts: SDK imports are
// hidden from the TS static analyzer via a variable-aliased dynamic
// import, so the AWS/GCP/Azure SDKs are optional dependencies — a dev
// install never pulls them. Operators install the SDK for the cloud
// they're actually using.
//
// Per ARCHITECTURE.md §17.2 / §3 — the system is interface-first
// (LogSource is the seam), and this is the first real cloud impl behind
// the seam. Per threat_model "System ↔ Log Sources": log content is
// attacker-controlled; nothing in this module touches payload bytes
// except to wrap them in a LogRecord for the ingest pipeline to
// detect+redact. Provenance fields land in the LogRecord verbatim;
// the ingest pipeline applies the trust-boundary validation.

import { and, eq, sql } from "drizzle-orm";
import { db, logSourceCheckpointsTable } from "@workspace/db";
import { appendLedger } from "./ledger";
import { logger } from "./logger";
import type { LogRecord, LogSource } from "./log-source";

// ----- SDK lazy loader -------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ----- Checkpoint store --------------------------------------------------

/** Per-source cursor (last-seen source-side event timestamp in ms epoch).
 *  Backed by `log_source_checkpoints` in production; an in-memory impl
 *  is provided for tests so they don't touch the shared dev DB. */
export interface CheckpointStore {
  load(sourceName: string): Promise<number | null>;
  /** Idempotent — repeat saves with the same ts are no-ops. */
  save(sourceName: string, tenantId: string, ts: number): Promise<void>;
}

export class DbCheckpointStore implements CheckpointStore {
  async load(sourceName: string): Promise<number | null> {
    const rows = await db
      .select({ ts: logSourceCheckpointsTable.lastEventTs })
      .from(logSourceCheckpointsTable)
      .where(eq(logSourceCheckpointsTable.sourceName, sourceName))
      .limit(1);
    return rows[0]?.ts ?? null;
  }

  async save(sourceName: string, tenantId: string, ts: number): Promise<void> {
    // ON CONFLICT … DO UPDATE so the cursor advances monotonically. We
    // also guard against going backwards: a buggy adapter handing us a
    // stale ts would otherwise re-deliver an entire window. The
    // GREATEST() clause keeps the stored value as the max of current
    // and incoming.
    await db
      .insert(logSourceCheckpointsTable)
      .values({ sourceName, tenantId, lastEventTs: ts, updatedAt: new Date() })
      .onConflictDoUpdate({
        target: logSourceCheckpointsTable.sourceName,
        set: {
          lastEventTs: sql`GREATEST(${logSourceCheckpointsTable.lastEventTs}, ${ts})`,
          updatedAt: new Date(),
        },
        where: and(
          eq(logSourceCheckpointsTable.sourceName, sourceName),
          // Defense in depth: refuse the update if a different tenant
          // somehow claims the same source_name (would indicate a
          // misconfiguration; we'd rather error than overwrite).
          eq(logSourceCheckpointsTable.tenantId, tenantId),
        ),
      });
  }
}

export class InMemoryCheckpointStore implements CheckpointStore {
  private readonly cursors = new Map<string, number>();
  async load(name: string): Promise<number | null> {
    return this.cursors.get(name) ?? null;
  }
  async save(name: string, _tenantId: string, ts: number): Promise<void> {
    const cur = this.cursors.get(name) ?? 0;
    if (ts > cur) this.cursors.set(name, ts);
  }
}

// ----- CloudWatch Logs adapter ------------------------------------------

/** Minimal client shape we actually use. The real
 *  `@aws-sdk/client-cloudwatch-logs` exports `CloudWatchLogsClient` +
 *  `FilterLogEventsCommand`; the lazy loader adapts those to this shape
 *  so the rest of the module is SDK-agnostic and trivial to mock. */
export interface CloudwatchClient {
  filterLogEvents(params: {
    logGroupName: string;
    startTime?: number;
    nextToken?: string;
    limit?: number;
  }): Promise<{
    events?: ReadonlyArray<{
      eventId?: string;
      timestamp?: number;
      ingestionTime?: number;
      message?: string;
    }>;
    nextToken?: string;
  }>;
}

export interface CloudwatchLogSourceOpts {
  readonly tenantId: string;
  /** One or more log group names to poll (e.g. "/aws/lambda/billing-svc"). */
  readonly logGroups: ReadonlyArray<string>;
  readonly region: string;
  /** Publish into the bus. Wired to `logBus.publish("raw.logs", r)` at boot. */
  readonly publish: (record: LogRecord) => Promise<unknown>;
  /** Tick interval. Default 5s. */
  readonly pollIntervalMs?: number;
  /** How far back to look on the very first poll for a fresh log group
   *  (no checkpoint stored yet). Defaults to 5min — long enough to catch
   *  the in-flight window across a deploy, short enough to avoid
   *  re-ingesting a day of logs. */
  readonly lookbackMsOnFirstPoll?: number;
  /** Max pages per tick per group — bounds worst-case API spend on a
   *  burst. Default 5 (= 5 × max 1000 events = 5000 events / group / tick). */
  readonly maxPagesPerTick?: number;
  /** Initial backoff after error. Doubles on each consecutive failure,
   *  capped at `maxBackoffMs`. Default 1s. */
  readonly initialBackoffMs?: number;
  /** Backoff cap. Default 60s. */
  readonly maxBackoffMs?: number;
  /** Test injection: bypass the real SDK loader. */
  readonly clientFactory?: () => Promise<CloudwatchClient>;
  /** Test injection: bypass DB-backed checkpoint store. */
  readonly checkpointStore?: CheckpointStore;
}

export class CloudwatchLogSource implements LogSource {
  readonly name: string;
  private running = false;
  private stopRequested = false;
  private loopPromise: Promise<void> | null = null;
  private wakeUp: (() => void) | null = null;
  private clientPromise: Promise<CloudwatchClient> | null = null;
  private readonly store: CheckpointStore;
  private readonly pollIntervalMs: number;
  private readonly lookbackMsOnFirstPoll: number;
  private readonly maxPagesPerTick: number;
  private readonly initialBackoffMs: number;
  private readonly maxBackoffMs: number;

  constructor(private readonly opts: CloudwatchLogSourceOpts) {
    if (opts.logGroups.length === 0) {
      throw new Error("CloudwatchLogSource: at least one logGroup required");
    }
    this.name = `cloudwatch:${opts.tenantId}`;
    this.store = opts.checkpointStore ?? new DbCheckpointStore();
    this.pollIntervalMs = opts.pollIntervalMs ?? 5000;
    this.lookbackMsOnFirstPoll = opts.lookbackMsOnFirstPoll ?? 5 * 60 * 1000;
    this.maxPagesPerTick = opts.maxPagesPerTick ?? 5;
    this.initialBackoffMs = opts.initialBackoffMs ?? 1000;
    this.maxBackoffMs = opts.maxBackoffMs ?? 60_000;
  }

  private async getClient(): Promise<CloudwatchClient> {
    if (this.opts.clientFactory) return this.opts.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          const id = "@aws-sdk/client-cloudwatch-logs";
          mod = await loadOptional(id);
        } catch {
          throw new Error(
            "CloudwatchLogSource selected but @aws-sdk/client-cloudwatch-logs " +
              "is not installed. Run: pnpm --filter @workspace/api-server add " +
              "@aws-sdk/client-cloudwatch-logs",
          );
        }
        const native = new mod.CloudWatchLogsClient({ region: this.opts.region });
        return {
          async filterLogEvents(params) {
            const cmd = new mod.FilterLogEventsCommand(params);
            const resp = (await native.send(cmd)) as {
              events?: ReadonlyArray<{
                eventId?: string;
                timestamp?: number;
                ingestionTime?: number;
                message?: string;
              }>;
              nextToken?: string;
            };
            return {
              ...(resp.events ? { events: resp.events } : {}),
              ...(resp.nextToken ? { nextToken: resp.nextToken } : {}),
            };
          },
        };
      })();
    }
    return this.clientPromise;
  }

  async start(): Promise<void> {
    if (this.running) return;
    // Architect-flagged (M8): emit the lifecycle ledger row BEFORE flipping
    // `running=true`. If the ledger append throws (e.g. DB down at boot),
    // a half-started state would have `running=true` + `loopPromise=null`,
    // making subsequent start() calls silent no-ops while no loop is
    // actually polling. Append-then-flip keeps the state machine clean:
    // either we're fully started (loop running, lifecycle row in ledger)
    // or we're fully not (caller sees the throw and can retry).
    await appendLedger({
      tenantId: this.opts.tenantId,
      actor: { kind: "system", id: "ingest" },
      eventType: "ingest.source_started",
      subjectType: "log_source",
      subjectId: this.name,
      payload: {
        log_groups: this.opts.logGroups,
        region: this.opts.region,
        poll_interval_ms: this.pollIntervalMs,
      },
    });
    this.running = true;
    this.stopRequested = false;
    // Fire and store — caller awaits start() returning, not loop completion.
    this.loopPromise = this.runLoop();
  }

  async stop(): Promise<void> {
    if (!this.running) return;
    this.stopRequested = true;
    // If the loop is currently sleeping between ticks, wake it so stop()
    // doesn't have to wait out the full pollIntervalMs. Without this, a
    // test (or graceful shutdown) configuring a long poll interval would
    // hang here for that interval before observing stopRequested.
    if (this.wakeUp) this.wakeUp();
    try {
      await this.loopPromise;
    } finally {
      this.running = false;
      this.loopPromise = null;
      await appendLedger({
        tenantId: this.opts.tenantId,
        actor: { kind: "system", id: "ingest" },
        eventType: "ingest.source_stopped",
        subjectType: "log_source",
        subjectId: this.name,
        payload: { log_groups: this.opts.logGroups },
      });
    }
  }

  /** Public for tests: drive exactly one poll across all groups and return
   *  totals. In production the scheduler calls this from `runLoop`. */
  async pollOnce(): Promise<{ published: number; pages: number }> {
    const client = await this.getClient();
    let published = 0;
    let pages = 0;
    for (const group of this.opts.logGroups) {
      const r = await this.pollGroup(client, group);
      published += r.published;
      pages += r.pages;
    }
    return { published, pages };
  }

  private async pollGroup(
    client: CloudwatchClient,
    logGroup: string,
  ): Promise<{ published: number; pages: number }> {
    const cursorKey = `${this.name}:${logGroup}`;
    const existing = await this.store.load(cursorKey);
    // CloudWatch FilterLogEvents `startTime` is INCLUSIVE. To avoid
    // re-fetching the cursor event itself, advance by 1ms (CloudWatch
    // timestamps are ms-granular). On the very first poll for a group
    // with no stored cursor, use the lookback window — this is the
    // dev/operator-friendly behavior. A production "from-beginning"
    // operator can pre-seed the checkpoint to 0.
    const startTime =
      existing !== null
        ? existing + 1
        : Date.now() - this.lookbackMsOnFirstPoll;

    let nextToken: string | undefined;
    let published = 0;
    let pages = 0;
    // Architect-flagged (M8): the cursor must be a **contiguous** success
    // watermark, not the max of any successful timestamp. Otherwise a
    // failure at ts=2000 followed by a success at ts=3000 in the same
    // batch would advance the cursor to 3000, and the failed record at
    // 2000 would never be retried (next poll starts at 3001). We collect
    // ALL events first (sorted ascending by ts), then iterate; the cursor
    // tracks only the timestamp of the longest *contiguous* success
    // prefix. As soon as any record fails, we stop advancing the cursor
    // for this batch — the failing record AND every later record in the
    // batch will be re-fetched and re-published on the next tick. The
    // ingest pipeline already dedupes by fingerprint, so re-publishing a
    // successful record is a cheap no-op (occurrence_count bumps).
    type Collected = {
      ts: number;
      record: LogRecord;
      sourceRecordId: string;
    };
    const collected: Collected[] = [];

    do {
      const resp = await client.filterLogEvents({
        logGroupName: logGroup,
        startTime,
        limit: 1000,
        ...(nextToken ? { nextToken } : {}),
      });
      pages++;
      const events = resp.events ?? [];
      for (const e of events) {
        if (!e.timestamp || !e.message) continue;
        // Use eventId if present (globally unique per CloudWatch),
        // otherwise synthesize one from timestamp + a short hash of the
        // message so dedupe in the ingest layer still has something
        // stable to fingerprint on.
        const sourceRecordId = e.eventId ?? `${e.timestamp}:${shortHash(e.message)}`;
        const record: LogRecord = {
          tenantId: this.opts.tenantId,
          sourceType: "cloudwatch",
          sourceName: logGroup,
          sourceRecordId,
          observedAt: new Date(e.timestamp),
          ingestedAt: new Date(),
          payload: e.message,
        };
        collected.push({ ts: e.timestamp, record, sourceRecordId });
      }
      nextToken = resp.nextToken;
      if (pages >= this.maxPagesPerTick) break;
    } while (nextToken);

    // Sort ascending by timestamp so the "contiguous success prefix" is
    // well-defined. FilterLogEvents is documented to return events in
    // event-time order but we belt-and-suspenders sort defensively (cost
    // is O(n log n) on a small page-bounded set).
    collected.sort((a, b) => a.ts - b.ts);

    let watermark = existing ?? 0;
    let firstFailureSeen = false;
    for (const c of collected) {
      try {
        await this.opts.publish(c.record);
        published++;
        if (!firstFailureSeen && c.ts > watermark) watermark = c.ts;
      } catch (err) {
        // Once we hit a failure, freeze the watermark. Every later event
        // in the batch — even if its publish() succeeds — will be
        // re-fetched on the next tick (and the ingest pipeline will
        // dedupe). This is the only way to guarantee at-least-once
        // delivery of the failed record without silently losing it.
        firstFailureSeen = true;
        logger.warn(
          { err, logGroup, sourceRecordId: c.sourceRecordId, eventTs: c.ts },
          "cloudwatch source: publish failed; freezing watermark, will retry from this ts on next tick",
        );
      }
    }

    // Persist the cursor advance. Idempotent + monotonic via GREATEST().
    if (watermark > (existing ?? 0)) {
      await this.store.save(cursorKey, this.opts.tenantId, watermark);
    }
    return { published, pages };
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
        // Architect-flagged (M8): best-effort ledger append in the error
        // path. If the ledger itself is down (e.g. transient DB blip
        // happening at the same time as the upstream CloudWatch failure),
        // an unhandled rejection here would propagate out of runLoop and
        // kill the source entirely — exactly the wrong response to a
        // transient outage. Log-and-continue keeps the poll loop alive;
        // operators see the underlying error in stderr.
        try {
          await appendLedger({
            tenantId: this.opts.tenantId,
            actor: { kind: "system", id: "ingest" },
            eventType: "ingest.source_error",
            subjectType: "log_source",
            subjectId: this.name,
            payload: {
              error: err instanceof Error ? err.message : String(err),
              consecutive_failures: consecutiveFailures,
              backoff_ms: backoff,
              log_groups: this.opts.logGroups,
            },
          });
        } catch (ledgerErr) {
          logger.error(
            { err, ledgerErr, source: this.name },
            "cloudwatch source: failed to ledger ingest.source_error; continuing poll loop",
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

  /** Sleep for `ms` OR until `stop()` resolves the wakeUp — whichever is
   *  first. Without the wakeUp path a long pollIntervalMs would keep
   *  stop() blocked for up to a full interval. */
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

function shortHash(s: string): string {
  // Tiny non-crypto hash — sufficient to disambiguate same-ms events
  // when CloudWatch elides eventId. Not used for any security decision.
  let h = 5381;
  for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16);
}

// ----- Env-driven builder -----------------------------------------------

/** Build a CloudwatchLogSource from env, or return null if not configured.
 *  Mirrors `buildChannelsFromEnv` — inert by default; an operator opts in
 *  by setting `LOG_SOURCE=cloudwatch` plus the required vars. */
export function buildCloudwatchSourceFromEnv(
  publish: (record: LogRecord) => Promise<unknown>,
): CloudwatchLogSource | null {
  if (process.env["LOG_SOURCE"] !== "cloudwatch") return null;
  const tenantId = process.env["CLOUDWATCH_TENANT_ID"];
  const groupsRaw = process.env["CLOUDWATCH_LOG_GROUPS"];
  const region = process.env["AWS_REGION"];
  if (!tenantId) throw new Error("LOG_SOURCE=cloudwatch requires CLOUDWATCH_TENANT_ID");
  if (!groupsRaw) throw new Error("LOG_SOURCE=cloudwatch requires CLOUDWATCH_LOG_GROUPS (CSV)");
  if (!region) throw new Error("LOG_SOURCE=cloudwatch requires AWS_REGION");
  const logGroups = groupsRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (logGroups.length === 0) {
    throw new Error("LOG_SOURCE=cloudwatch: CLOUDWATCH_LOG_GROUPS parsed to empty list");
  }
  const pollIntervalMs = parsePositiveInt(process.env["CLOUDWATCH_POLL_INTERVAL_MS"], 5000);
  const lookbackMsOnFirstPoll = parsePositiveInt(
    process.env["CLOUDWATCH_LOOKBACK_MS"],
    5 * 60 * 1000,
  );
  return new CloudwatchLogSource({
    tenantId,
    logGroups,
    region,
    publish,
    pollIntervalMs,
    lookbackMsOnFirstPoll,
  });
}

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}
