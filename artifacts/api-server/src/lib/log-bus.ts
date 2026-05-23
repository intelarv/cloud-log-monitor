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

import { logger } from "./logger";
import type { LogRecord } from "./log-source";

export type LogTopic = "raw.logs";

export type LogHandler = (record: LogRecord) => Promise<void>;

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
