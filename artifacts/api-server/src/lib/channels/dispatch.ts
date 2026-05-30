// Channel dispatch — the post-ledger-commit hook that fans alertable
// ledger entries out to configured channels (Slack / webhook today).
//
// Hard rules enforced here (all from threat_model.md):
//
//   1. OUTBOUND PHI HARD GATE. Every envelope field is rescanned with
//      `scanForPhi` before any adapter is called. A hit aborts ALL
//      adapter sends, ledgers `channel.send_blocked_phi` (critical), and
//      returns. The envelope shape (types.ts) is already an allow-list,
//      so a hit here is a defense-in-depth catch on a future field
//      addition that accidentally lets content through.
//
//   2. SELF-RECURSION GUARD. `channel.*` ledger events are themselves
//      written by THIS module. Re-dispatching them would build an
//      infinite loop. We filter them at the top of the hook.
//
//   3. PER-CHANNEL RATE LIMIT. Sliding-window cap per adapter name to
//      contain a storm (e.g. a chain-invalid-flapping bug). Over-cap
//      sends ledger `channel.send_throttled` (warning) instead.
//
//   4. ADAPTER FAILURES DO NOT THROW OUT. Adapter contract returns
//      `DispatchResult.ok=false` on any failure; we ledger
//      `channel.send_failed` (warning) and continue. The hook is
//      already `void`-wrapped fire-and-forget by the caller, but
//      isolating per-adapter ensures one bad adapter doesn't starve the
//      others.

import { ALERT_RULES, type AlertSeverity } from "../alerts";
import { appendLedger } from "../ledger";
import { logger } from "../logger";
import { scanForPhi } from "../redact";
import { selectChannels, type ChannelConfig } from "./router";
import type { ChannelEnvelope } from "./types";
import type { LedgerEntry } from "@workspace/db";

// ----- Module state (default-off, like supervisor.ts) -------------------

let channels: ReadonlyArray<ChannelConfig> = [];

/** In-memory sliding-window counters per channel name. Capacity is a
 *  process-level cap, not a per-tenant cap — channel storms tend to be
 *  global (chain-invalid, redaction-regression). Per-tenant rate limits
 *  belong in a multi-tenant milestone. */
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_DEFAULT = 30;
const sendTimes = new Map<string, number[]>();

function getRateLimit(): number {
  const raw = process.env["CHANNEL_RATE_LIMIT_PER_MINUTE"];
  if (raw === undefined) return RATE_LIMIT_DEFAULT;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? n : RATE_LIMIT_DEFAULT;
}

function checkAndRecord(channelName: string): boolean {
  const now = Date.now();
  pruneExpiredRateLimitState(now);
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  const arr = (sendTimes.get(channelName) ?? []).filter((t) => t >= cutoff);
  if (arr.length >= getRateLimit()) {
    if (arr.length === 0) sendTimes.delete(channelName);
    else sendTimes.set(channelName, arr);
    return false;
  }
  arr.push(now);
  sendTimes.set(channelName, arr);
  return true;
}

/** Periodically sweep `sendTimes` for channels whose entire window has
 *  expired. Without this, a removed / renamed channel's empty timestamp
 *  array stays in the map forever (small but unbounded leak). Sweep is
 *  amortized: we do at most one full pass per `RATE_LIMIT_WINDOW_MS`
 *  regardless of how often `checkAndRecord` is called. */
let lastSweepAt = 0;
function pruneExpiredRateLimitState(now: number): void {
  if (now - lastSweepAt < RATE_LIMIT_WINDOW_MS) return;
  lastSweepAt = now;
  const cutoff = now - RATE_LIMIT_WINDOW_MS;
  for (const [name, arr] of sendTimes) {
    const live = arr.filter((t) => t >= cutoff);
    if (live.length === 0) sendTimes.delete(name);
    else if (live.length !== arr.length) sendTimes.set(name, live);
  }
}

// ----- Public init / test hooks -----------------------------------------

export function initChannels(configured: ReadonlyArray<ChannelConfig>): void {
  channels = configured;
  logger.info(
    {
      enabled: channels.map((c) => ({ name: c.adapter.name, minSeverity: c.minSeverity })),
      rateLimitPerMinute: getRateLimit(),
    },
    "channel dispatch initialized",
  );
}

export function __setChannelsForTest(c: ReadonlyArray<ChannelConfig>): void {
  channels = c;
  sendTimes.clear();
}

export function __resetChannelsForTest(): void {
  channels = [];
  sendTimes.clear();
}

// ----- Envelope construction --------------------------------------------

function buildEnvelope(entry: LedgerEntry, severity: AlertSeverity): ChannelEnvelope {
  return {
    severity,
    eventType: entry.eventType,
    tenantId: entry.tenantId,
    ledgerSeq: entry.seq,
    ledgerHashShort: entry.hash.slice(0, 16),
    subjectType: entry.subjectType,
    subjectId: entry.subjectId,
    occurredAt: entry.ts.toISOString(),
  };
}

/** Allow-list of envelope fields that are SYSTEM-GENERATED and have a
 *  fixed, attacker-uncontrollable format. Excluded from the rescan
 *  because they would otherwise always false-positive (e.g. UUID
 *  tenantId → credit-card-like detector → all alerts suppressed). Any
 *  future ChannelEnvelope field NOT in this set is automatically scanned
 *  — so a developer adding a content-bearing field cannot accidentally
 *  bypass the gate by forgetting to update the scan list. */
const SCAN_EXEMPT_FIELDS = new Set<keyof ChannelEnvelope>([
  "tenantId", // system-generated UUID
  "ledgerHashShort", // SHA-256 hex slice we computed
  "occurredAt", // ISO timestamp from our own clock
  "severity", // enum literal from ALERT_RULES
  "ledgerSeq", // numeric
]);

function scanEnvelopeForPhi(env: ChannelEnvelope): string[] {
  const hits: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    if (SCAN_EXEMPT_FIELDS.has(key as keyof ChannelEnvelope)) continue;
    if (typeof value !== "string" || value.length === 0) continue;
    for (const h of scanForPhi(value)) hits.push(h.detector);
  }
  return Array.from(new Set(hits));
}

// ----- Dispatch hook ----------------------------------------------------

/** Track in-flight dispatch work for tests so a deterministic barrier
 *  exists. Production callers don't need this — `appendLedger` already
 *  treats dispatch as fire-and-forget. */
const inFlight = new Set<Promise<void>>();

/** Test-only barrier: resolves once all in-flight dispatch promises
 *  triggered before the call have settled. */
export async function __drainChannelsForTest(): Promise<void> {
  while (inFlight.size > 0) {
    await Promise.allSettled([...inFlight]);
  }
}

export function dispatchAlertFromLedger(entry: LedgerEntry): void {
  // (2) Self-recursion guard. Channel.* events are emitted from this
  //     module's own appendLedger calls below; re-dispatching them would
  //     create an infinite loop.
  if (entry.eventType.startsWith("channel.")) return;

  const severity = ALERT_RULES[entry.eventType];
  if (!severity) return;

  if (channels.length === 0) return;

  const selected = selectChannels(channels, severity);
  if (selected.length === 0) return;

  const env = buildEnvelope(entry, severity);

  // (1) Outbound PHI hard gate.
  const phiDetectors = scanEnvelopeForPhi(env);
  if (phiDetectors.length > 0) {
    const p = appendLedger({
      tenantId: entry.tenantId,
      actor: { kind: "system", id: "channels" },
      eventType: "channel.send_blocked_phi",
      ...(entry.subjectType ? { subjectType: entry.subjectType } : {}),
      ...(entry.subjectId ? { subjectId: entry.subjectId } : {}),
      payload: {
        source_ledger_seq: entry.seq,
        source_event_type: entry.eventType,
        detectors: phiDetectors,
        channels_skipped: selected.map((a) => a.name),
      },
    })
      .then(() => {})
      .catch((err) => {
        logger.error({ err }, "failed to ledger channel.send_blocked_phi");
      });
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p));
    return;
  }

  // Fan out per adapter. Each adapter call is independent — a slow one
  // can't block a fast one because they're parallel promises.
  for (const adapter of selected) {
    // (3) Per-channel rate limit.
    if (!checkAndRecord(adapter.name)) {
      const p = appendLedger({
        tenantId: entry.tenantId,
        actor: { kind: "system", id: "channels" },
        eventType: "channel.send_throttled",
        ...(entry.subjectType ? { subjectType: entry.subjectType } : {}),
        ...(entry.subjectId ? { subjectId: entry.subjectId } : {}),
        payload: {
          channel: adapter.name,
          source_ledger_seq: entry.seq,
          source_event_type: entry.eventType,
          window_seconds: RATE_LIMIT_WINDOW_MS / 1000,
          limit: getRateLimit(),
        },
      })
        .then(() => {})
        .catch((err) => {
          logger.error({ err }, "failed to ledger channel.send_throttled");
        });
      inFlight.add(p);
      void p.finally(() => inFlight.delete(p));
      continue;
    }

    const p = (async () => {
      let result;
      try {
        result = await adapter.send(env);
      } catch (err) {
        // (4) Defense in depth: contract says adapters return
        //     DispatchResult, but we tolerate a misbehaving adapter that
        //     throws.
        result = {
          channel: adapter.name,
          ok: false,
          err: err instanceof Error ? err.message : String(err),
          durationMs: 0,
        };
      }
      try {
        await appendLedger({
          tenantId: entry.tenantId,
          actor: { kind: "system", id: "channels" },
          eventType: result.ok ? "channel.send_succeeded" : "channel.send_failed",
          ...(entry.subjectType ? { subjectType: entry.subjectType } : {}),
          ...(entry.subjectId ? { subjectId: entry.subjectId } : {}),
          payload: {
            channel: adapter.name,
            source_ledger_seq: entry.seq,
            source_event_type: entry.eventType,
            status_code: result.statusCode ?? null,
            duration_ms: result.durationMs,
            ...(result.ok ? {} : { err: result.err ?? "unknown" }),
          },
        });
      } catch (err) {
        logger.error({ err, channel: adapter.name }, "failed to ledger channel send result");
      }
    })();
    inFlight.add(p);
    void p.finally(() => inFlight.delete(p));
  }
}
