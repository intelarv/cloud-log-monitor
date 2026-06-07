// M3: In-process pub/sub event bus. Stand-in for Kafka/Redpanda/NATS per
// ARCHITECTURE.md §3 (`topic: raw.logs`). The `LogBus` interface is the
// contract — any cloud-native or self-hosted broker (KafkaJS, NATS client,
// Redpanda) implements it without touching ingest pipeline or source
// adapters.
//
// Dev/test uses `InMemoryLogBus`: handlers run sequentially per publish
// (in-order delivery; backpressure = caller waits). Production swaps to a
// brokered impl with at-least-once delivery + consumer-group scaling — the
// only thing the ingest pipeline knows is the `subscribe()` shape, not who
// the broker is.

import { z } from "zod";
import { logger } from "./logger";
import type { LogRecord, LogSourceType } from "./log-source";

export type LogTopic = "raw.logs";

export type LogHandler = (record: LogRecord) => Promise<void>;

// Runtime mirror of the `LogSourceType` union (log-source.ts is a type-only
// declaration). Used to validate records arriving off a real broker — a
// brokered transport is a trust boundary, so we re-validate the envelope
// shape on the consume side even though our own producers wrote it.
export const LOG_SOURCE_TYPES = [
  "cloudwatch",
  "cloud_logging",
  "azure_monitor",
  "onprem",
  "fixture",
] as const satisfies readonly LogSourceType[];

const LogRecordWireSchema = z.object({
  tenantId: z.string().min(1),
  sourceType: z.enum(LOG_SOURCE_TYPES),
  sourceName: z.string().min(1),
  sourceRecordId: z.string().min(1),
  observedAt: z.string().min(1),
  ingestedAt: z.string().min(1),
  payload: z.string(),
});

/** Serialize a `LogRecord` for transit over a real broker. Dates → ISO-8601
 *  strings; everything else is already JSON-safe. The `payload` is
 *  attacker-controlled but carried verbatim (the detector pipeline, not the
 *  transport, is responsible for it). */
export function encodeLogRecord(record: LogRecord): string {
  return JSON.stringify({
    tenantId: record.tenantId,
    sourceType: record.sourceType,
    sourceName: record.sourceName,
    sourceRecordId: record.sourceRecordId,
    observedAt: record.observedAt.toISOString(),
    ingestedAt: record.ingestedAt.toISOString(),
    payload: record.payload,
  });
}

/** Parse + validate a `LogRecord` arriving off a broker. Throws on malformed
 *  JSON, a bad envelope shape, or unparseable timestamps — the consumer
 *  treats a throw as a poison message (logged + skipped, never crashes the
 *  consume loop). */
export function decodeLogRecord(raw: string): LogRecord {
  const parsed = LogRecordWireSchema.parse(JSON.parse(raw));
  const observedAt = new Date(parsed.observedAt);
  const ingestedAt = new Date(parsed.ingestedAt);
  if (Number.isNaN(observedAt.getTime())) {
    throw new Error(`decodeLogRecord: invalid observedAt "${parsed.observedAt}"`);
  }
  if (Number.isNaN(ingestedAt.getTime())) {
    throw new Error(`decodeLogRecord: invalid ingestedAt "${parsed.ingestedAt}"`);
  }
  return {
    tenantId: parsed.tenantId,
    sourceType: parsed.sourceType,
    sourceName: parsed.sourceName,
    sourceRecordId: parsed.sourceRecordId,
    observedAt,
    ingestedAt,
    payload: parsed.payload,
  };
}

/** Per-publish delivery result. `delivered` counts handlers that completed
 *  without throwing; `errors` carries everything else. Callers that need
 *  at-least-once semantics (the admin replay route, demos) inspect this to
 *  decide what to surface; callers that don't care can ignore it. */
export interface PublishResult {
  delivered: number;
  errors: Array<{ handler: string; err: unknown }>;
}

export interface LogBus {
  publish(topic: LogTopic, record: LogRecord): Promise<PublishResult>;
  subscribe(topic: LogTopic, handler: LogHandler): () => void;
  /** Connect to the underlying broker and begin consuming. No-op for the
   *  in-memory bus (publish dispatches synchronously). Brokered impls open
   *  producer/consumer connections here, AFTER subscribers have registered,
   *  so the consume loop sees the handler set. */
  start?(): Promise<void>;
  /** Disconnect the broker. No-op for the in-memory bus. */
  stop?(): Promise<void>;
}

export class InMemoryLogBus implements LogBus {
  private readonly handlers = new Map<LogTopic, Set<LogHandler>>();

  async publish(topic: LogTopic, record: LogRecord): Promise<PublishResult> {
    const subs = this.handlers.get(topic);
    if (!subs || subs.size === 0) return { delivered: 0, errors: [] };
    // Sequential dispatch — preserves per-record ordering so the dedupe path
    // (SELECT-then-upsert by fingerprint, even with the advisory lock) sees
    // a deterministic order in tests. A handler that throws does NOT abort
    // the other handlers — log + record + continue, matching at-least-once
    // semantics of a real broker where one consumer's failure doesn't block
    // others. The PublishResult lets the caller see what failed.
    const result: PublishResult = { delivered: 0, errors: [] };
    for (const h of subs) {
      try {
        await h(record);
        result.delivered++;
      } catch (err) {
        const handlerName = h.name || "anonymous";
        result.errors.push({ handler: handlerName, err });
        logger.error(
          {
            err,
            topic,
            handler: handlerName,
            source: `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`,
          },
          "log-bus handler threw; continuing dispatch to other handlers",
        );
      }
    }
    return result;
  }

  subscribe(topic: LogTopic, handler: LogHandler): () => void {
    const set = this.handlers.get(topic) ?? new Set();
    set.add(handler);
    this.handlers.set(topic, set);
    return () => {
      const cur = this.handlers.get(topic);
      cur?.delete(handler);
    };
  }
}

/** Process-wide bus instance. Sources publish here; the ingest pipeline
 *  subscribes here at boot. Tests construct fresh `InMemoryLogBus`
 *  instances instead of using this singleton so they don't bleed
 *  handlers across cases. */
export const logBus: LogBus = new InMemoryLogBus();
