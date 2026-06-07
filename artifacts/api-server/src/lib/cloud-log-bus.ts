// Real broker-backed `LogBus` implementations (Kafka / Redpanda via kafkajs,
// NATS JetStream via nats).
//
// Mirrors the lazy-load pattern in cloud-log-sources.ts / cloud-embedders.ts:
// the broker SDK is imported through a variable-aliased dynamic import inside
// `connect()`, so it is an OPTIONAL dependency — a dev/CI install never pulls
// kafkajs or nats, and constructing a brokered bus is inert (no I/O, no SDK
// load) until `start()` is called. The default `InMemoryLogBus` therefore
// stays byte-identical for the credential-free eval gate.
//
// Per ARCHITECTURE.md §3 the `raw.logs` topic carries raw log lines BEFORE
// the detector pipeline (Log Sources → Kafka/NATS → Detectors → findings), so
// attacker-controlled `payload` bytes legitimately transit the broker. The
// relevant control at this layer is transport security + access control on the
// broker connection (threat_model §"TLS everywhere") — exposed here via the
// SSL/SASL (Kafka) and TLS/auth (NATS) options. Redaction happens downstream
// in ingest; nothing here inspects payload bytes beyond wrapping them.

import { logger } from "./logger";
import {
  decodeLogRecord,
  encodeLogRecord,
  type LogBus,
  type LogHandler,
  type LogTopic,
  type PublishResult,
} from "./log-bus";
import type { LogRecord } from "./log-source";

// ----- SDK lazy loader (variable id hides it from the bundler) ----------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ----- Broker driver seam -----------------------------------------------

/** The minimal broker surface `BrokeredLogBus` actually needs. Both Kafka and
 *  NATS reduce to this; tests inject an in-memory fake so the publish→consume
 *  round-trip (encode/decode, dispatch, at-least-once redelivery) is exercised
 *  without a live broker. `connect()` is where the SDK is lazily loaded. */
export interface BrokerDriver {
  connect(): Promise<void>;
  /** Produce one already-encoded record. `key` is the partition/ordering key
   *  (we use tenantId so a tenant's records stay ordered on one partition). */
  produce(value: string, key: string): Promise<void>;
  /** Begin consuming. `onMessage` MUST be awaited per message; if it throws,
   *  the driver MUST NOT ack/commit (at-least-once → the broker redelivers).
   *  Resolves once the subscription is established. */
  consume(onMessage: (value: string) => Promise<void>): Promise<void>;
  close(): Promise<void>;
}

// ----- Generic brokered bus ---------------------------------------------

/** A `LogBus` over any `BrokerDriver`. `subscribe()` only registers handlers;
 *  the broker connection + consume loop start in `start()` (called at boot
 *  AFTER the ingest pipeline subscribes). `publish()` produces to the broker
 *  and reports a `PublishResult` shaped like the in-memory bus: `delivered: 1`
 *  on a broker ack, or `delivered: 0` + the error captured (never thrown), so
 *  the admin replay route's accounting stays uniform across bus impls. */
export class BrokeredLogBus implements LogBus {
  private readonly handlers = new Set<LogHandler>();
  private started = false;

  constructor(
    private readonly driver: BrokerDriver,
    private readonly label: string,
  ) {}

  subscribe(_topic: LogTopic, handler: LogHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  async start(): Promise<void> {
    if (this.started) return;
    await this.driver.connect();
    try {
      await this.driver.consume(async (value) => {
        await this.onMessage(value);
      });
    } catch (err) {
      // `connect()` already opened producer/consumer (or a NATS connection); if
      // `consume()` then fails (e.g. subscribe rejected) we must release those
      // handles, otherwise a boot-time start failure leaks an open broker
      // connection for the life of the process.
      await this.driver.close().catch(() => {});
      throw err;
    }
    this.started = true;
    logger.info({ bus: this.label }, "log bus connected and consuming");
  }

  /** Decode + dispatch one raw broker message. A decode failure is a poison
   *  message: logged + dropped (returning normally → the driver acks, so it
   *  is not redelivered forever). A handler failure is rethrown so the driver
   *  does NOT ack and the broker redelivers (at-least-once). Re-delivery is
   *  safe because ingest dedupes by fingerprint (idempotent upsert). */
  private async onMessage(value: string): Promise<void> {
    let record;
    try {
      record = decodeLogRecord(value);
    } catch (err) {
      logger.error(
        { err, bus: this.label },
        "log bus dropping undecodable (poison) message",
      );
      return;
    }
    const errors: unknown[] = [];
    for (const h of this.handlers) {
      try {
        await h(record);
      } catch (err) {
        errors.push(err);
        logger.error(
          {
            err,
            bus: this.label,
            handler: h.name || "anonymous",
            source: `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`,
          },
          "log bus handler threw; will not ack (at-least-once redelivery)",
        );
      }
    }
    if (errors.length > 0) {
      // Surface to the driver so it refuses to ack → broker redelivers.
      throw errors[0];
    }
  }

  async publish(_topic: LogTopic, record: LogRecord): Promise<PublishResult> {
    try {
      await this.driver.produce(encodeLogRecord(record), record.tenantId);
      return { delivered: 1, errors: [] };
    } catch (err) {
      logger.error(
        {
          err,
          bus: this.label,
          source: `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`,
        },
        "log bus produce failed",
      );
      return { delivered: 0, errors: [{ handler: "broker-produce", err }] };
    }
  }

  async stop(): Promise<void> {
    if (!this.started) return;
    await this.driver.close();
    this.started = false;
  }
}

// ----- Kafka / Redpanda driver (lazy kafkajs) ---------------------------

export interface KafkaSasl {
  mechanism: "plain" | "scram-sha-256" | "scram-sha-512";
  username: string;
  password: string;
}

export interface KafkaDriverConfig {
  brokers: string[];
  clientId: string;
  groupId: string;
  topic: string;
  ssl: boolean;
  sasl?: KafkaSasl;
}

export function createKafkaDriver(cfg: KafkaDriverConfig): BrokerDriver {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let producer: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let consumer: any;
  return {
    async connect() {
      const mod = await loadOptional("kafkajs");
      const Kafka = mod.Kafka ?? mod.default?.Kafka;
      const logLevel = mod.logLevel ?? mod.default?.logLevel;
      if (!Kafka) {
        throw new Error(
          "LOG_BUS_PROVIDER=kafka requires the 'kafkajs' package. " +
            "Install it: pnpm --filter @workspace/api-server add kafkajs",
        );
      }
      const kafka = new Kafka({
        clientId: cfg.clientId,
        brokers: cfg.brokers,
        ssl: cfg.ssl,
        ...(cfg.sasl ? { sasl: cfg.sasl } : {}),
        ...(logLevel ? { logLevel: logLevel.NOTHING } : {}),
      });
      producer = kafka.producer();
      consumer = kafka.consumer({ groupId: cfg.groupId });
      await producer.connect();
      await consumer.connect();
    },
    async produce(value, key) {
      await producer.send({
        topic: cfg.topic,
        messages: [{ key, value }],
      });
    },
    async consume(onMessage) {
      await consumer.subscribe({ topic: cfg.topic, fromBeginning: false });
      // `consumer.run()` RESOLVES once the background fetch loop has started —
      // it does NOT block for the consumption lifetime (the eachMessage callback
      // is invoked off the background runner). So awaiting it here returns
      // promptly and boot proceeds to listen. (NATS is the opposite: its
      // `for await (m of sub)` loop blocks, which is why the NATS driver drains
      // it in a detached `void (async () => …)()` instead.)
      await consumer.run({
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        eachMessage: async ({ message }: any) => {
          const value: string | undefined = message?.value?.toString("utf8");
          if (value == null) return;
          // A throw here aborts the kafkajs batch → offset is NOT committed →
          // the message is redelivered. That's the at-least-once contract.
          await onMessage(value);
        },
      });
    },
    async close() {
      await consumer?.disconnect();
      await producer?.disconnect();
    },
  };
}

// ----- NATS JetStream driver (lazy nats) --------------------------------

export interface NatsAuth {
  token?: string;
  username?: string;
  password?: string;
  /** Path to a NATS .creds file (operator-managed). */
  credsPath?: string;
}

export interface NatsDriverConfig {
  servers: string[];
  stream: string;
  subject: string;
  durable: string;
  tls: boolean;
  auth?: NatsAuth;
}

export function createNatsDriver(cfg: NatsDriverConfig): BrokerDriver {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let nc: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let js: any;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let mod: any;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  return {
    async connect() {
      mod = await loadOptional("nats");
      const connect = mod.connect ?? mod.default?.connect;
      if (!connect) {
        throw new Error(
          "LOG_BUS_PROVIDER=nats requires the 'nats' package. " +
            "Install it: pnpm --filter @workspace/api-server add nats",
        );
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const connOpts: any = { servers: cfg.servers, tls: cfg.tls ? {} : undefined };
      if (cfg.auth?.token) connOpts.token = cfg.auth.token;
      if (cfg.auth?.username) connOpts.user = cfg.auth.username;
      if (cfg.auth?.password) connOpts.pass = cfg.auth.password;
      if (cfg.auth?.credsPath) {
        const credsAuthenticator =
          mod.credsAuthenticator ?? mod.default?.credsAuthenticator;
        const fs = await loadOptional("node:fs/promises");
        if (credsAuthenticator) {
          const creds = await fs.readFile(cfg.auth.credsPath);
          connOpts.authenticator = credsAuthenticator(new Uint8Array(creds));
        }
      }
      nc = await connect(connOpts);
      const jsm = await nc.jetstreamManager();
      // Ensure the stream exists (idempotent — add only if absent).
      try {
        await jsm.streams.info(cfg.stream);
      } catch {
        await jsm.streams.add({ name: cfg.stream, subjects: [cfg.subject] });
      }
      js = nc.jetstream();
    },
    async produce(value) {
      await js.publish(cfg.subject, enc.encode(value));
    },
    async consume(onMessage) {
      const consumerOpts = mod.consumerOpts ?? mod.default?.consumerOpts;
      const opts = consumerOpts();
      opts.durable(cfg.durable);
      opts.manualAck();
      opts.ackExplicit();
      opts.deliverNew();
      const sub = await js.subscribe(cfg.subject, opts);
      // Drain the async iterator in the background; ack on success, nak on
      // failure so JetStream redelivers (at-least-once).
      void (async () => {
        for await (const m of sub) {
          const value = dec.decode(m.data);
          try {
            await onMessage(value);
            m.ack();
          } catch {
            m.nak();
          }
        }
      })();
    },
    async close() {
      await nc?.drain();
    },
  };
}
