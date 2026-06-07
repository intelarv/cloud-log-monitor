import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  BrokeredLogBus,
  type BrokerDriver,
} from "./cloud-log-bus";
import {
  decodeLogRecord,
  encodeLogRecord,
  InMemoryLogBus,
} from "./log-bus";
import type { LogRecord } from "./log-source";
import {
  createLogBus,
  getLogBus,
  initLogBusFromEnv,
  loadLogBusConfigFromEnv,
  resetLogBusForTests,
  setLogBus,
} from "./log-bus-config";

function makeRecord(over: Partial<LogRecord> = {}): LogRecord {
  return {
    tenantId: "default",
    sourceType: "fixture",
    sourceName: "test",
    sourceRecordId: "r1",
    observedAt: new Date("2026-01-02T03:04:05.000Z"),
    ingestedAt: new Date("2026-01-02T03:04:06.000Z"),
    payload: "hello",
    ...over,
  };
}

/** In-memory fake broker: produce enqueues; consume registers a callback that
 *  is invoked on every produced message (incl. ones already queued), with
 *  at-least-once redelivery — if the callback throws, the message is requeued
 *  once and retried so the test can assert eventual delivery. */
function makeFakeDriver(): BrokerDriver & {
  connected: boolean;
  closed: boolean;
  delivered: string[];
} {
  let onMessage: ((value: string) => Promise<void>) | null = null;
  const queue: string[] = [];
  const state = {
    connected: false,
    closed: false,
    delivered: [] as string[],
    async connect() {
      state.connected = true;
    },
    async produce(value: string) {
      queue.push(value);
      await pump();
    },
    async consume(cb: (value: string) => Promise<void>) {
      onMessage = cb;
      await pump();
    },
    async close() {
      state.closed = true;
    },
  };
  async function pump() {
    if (!onMessage) return;
    while (queue.length > 0) {
      const value = queue.shift()!;
      try {
        await onMessage(value);
        state.delivered.push(value);
      } catch {
        // at-least-once: requeue once for redelivery and stop this pass so the
        // test controls when redelivery happens (next produce/consume pump).
        queue.unshift(value);
        break;
      }
    }
  }
  return state;
}

describe("encode/decode LogRecord wire codec", () => {
  it("round-trips a record, preserving Date fields", () => {
    const rec = makeRecord();
    const decoded = decodeLogRecord(encodeLogRecord(rec));
    expect(decoded).toEqual(rec);
    expect(decoded.observedAt).toBeInstanceOf(Date);
    expect(decoded.observedAt.getTime()).toBe(rec.observedAt.getTime());
  });

  it("rejects malformed JSON", () => {
    expect(() => decodeLogRecord("not json")).toThrow();
  });

  it("rejects a bad envelope shape (missing tenantId)", () => {
    const bad = JSON.stringify({
      sourceType: "fixture",
      sourceName: "x",
      sourceRecordId: "y",
      observedAt: new Date().toISOString(),
      ingestedAt: new Date().toISOString(),
      payload: "p",
    });
    expect(() => decodeLogRecord(bad)).toThrow();
  });

  it("rejects an unknown sourceType", () => {
    const bad = encodeLogRecord(makeRecord()).replace(
      '"fixture"',
      '"martian"',
    );
    expect(() => decodeLogRecord(bad)).toThrow();
  });

  it("rejects an unparseable timestamp", () => {
    const bad = JSON.stringify({
      tenantId: "t",
      sourceType: "fixture",
      sourceName: "x",
      sourceRecordId: "y",
      observedAt: "nonsense",
      ingestedAt: new Date().toISOString(),
      payload: "p",
    });
    expect(() => decodeLogRecord(bad)).toThrow(/observedAt/);
  });
});

describe("BrokeredLogBus", () => {
  it("publish → consume round-trips a record to a subscribed handler", async () => {
    const driver = makeFakeDriver();
    const bus = new BrokeredLogBus(driver, "fake");
    const handler = vi.fn().mockResolvedValue(undefined);
    bus.subscribe("raw.logs", handler);
    await bus.start();
    const rec = makeRecord({ sourceRecordId: "x" });

    const result = await bus.publish("raw.logs", rec);

    expect(result).toEqual({ delivered: 1, errors: [] });
    expect(driver.connected).toBe(true);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(rec);
  });

  it("unsubscribe stops further delivery", async () => {
    const driver = makeFakeDriver();
    const bus = new BrokeredLogBus(driver, "fake");
    const handler = vi.fn().mockResolvedValue(undefined);
    const unsub = bus.subscribe("raw.logs", handler);
    await bus.start();
    unsub();
    await bus.publish("raw.logs", makeRecord());
    expect(handler).not.toHaveBeenCalled();
  });

  it("drops poison (undecodable) messages without throwing, no redelivery", async () => {
    const driver = makeFakeDriver();
    const bus = new BrokeredLogBus(driver, "fake");
    const handler = vi.fn().mockResolvedValue(undefined);
    bus.subscribe("raw.logs", handler);
    await bus.start();

    // Inject a poison message straight onto the driver (bypassing encode).
    await driver.produce("not-decodable", "k");

    expect(handler).not.toHaveBeenCalled();
    // The poison message was consumed (delivered to the bus) and dropped, not
    // requeued — i.e. it did not throw back to the driver.
    expect(driver.delivered).toEqual(["not-decodable"]);
  });

  it("redelivers when a handler throws (at-least-once)", async () => {
    const driver = makeFakeDriver();
    const bus = new BrokeredLogBus(driver, "fake");
    const handler = vi
      .fn()
      .mockRejectedValueOnce(new Error("transient"))
      .mockResolvedValueOnce(undefined);
    bus.subscribe("raw.logs", handler);
    await bus.start();
    const rec = makeRecord({ sourceRecordId: "redeliver" });

    // First produce: handler throws → fake driver requeues, does not mark
    // delivered.
    await bus.publish("raw.logs", rec);
    expect(handler).toHaveBeenCalledTimes(1);

    // Trigger another pump (a fresh produce) → the requeued message is retried
    // and now succeeds.
    await bus.publish("raw.logs", makeRecord({ sourceRecordId: "other" }));
    expect(handler).toHaveBeenCalledTimes(3); // redelivered rec + new record
  });

  it("publish reports delivered:0 + error when the broker produce fails", async () => {
    const driver: BrokerDriver = {
      connect: async () => {},
      produce: async () => {
        throw new Error("broker down");
      },
      consume: async () => {},
      close: async () => {},
    };
    const bus = new BrokeredLogBus(driver, "fake");
    await bus.start();
    const result = await bus.publish("raw.logs", makeRecord());
    expect(result.delivered).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.handler).toBe("broker-produce");
  });

  it("stop closes the driver", async () => {
    const driver = makeFakeDriver();
    const bus = new BrokeredLogBus(driver, "fake");
    await bus.start();
    await bus.stop();
    expect(driver.closed).toBe(true);
  });

  it("closes the driver if consume() fails after connect() (no leaked connection)", async () => {
    let closed = false;
    const driver: BrokerDriver = {
      connect: async () => {},
      produce: async () => {},
      consume: async () => {
        throw new Error("subscribe rejected");
      },
      close: async () => {
        closed = true;
      },
    };
    const bus = new BrokeredLogBus(driver, "fake");
    await expect(bus.start()).rejects.toThrow(/subscribe rejected/);
    expect(closed).toBe(true);
  });
});

describe("loadLogBusConfigFromEnv", () => {
  it("defaults to memory when unset", () => {
    expect(loadLogBusConfigFromEnv({})).toEqual({ provider: "memory" });
  });

  it("treats explicit memory as memory", () => {
    expect(loadLogBusConfigFromEnv({ LOG_BUS_PROVIDER: "memory" })).toEqual({
      provider: "memory",
    });
  });

  it("throws on an unknown provider", () => {
    expect(() => loadLogBusConfigFromEnv({ LOG_BUS_PROVIDER: "rabbit" })).toThrow(
      /Unknown LOG_BUS_PROVIDER/,
    );
  });

  it("parses kafka with defaults", () => {
    const cfg = loadLogBusConfigFromEnv({
      LOG_BUS_PROVIDER: "kafka",
      KAFKA_BROKERS: "a:9092, b:9092",
    });
    expect(cfg).toEqual({
      provider: "kafka",
      brokers: ["a:9092", "b:9092"],
      clientId: "phi-audit",
      groupId: "phi-audit-ingest",
      topic: "raw.logs",
      ssl: false,
    });
  });

  it("kafka requires KAFKA_BROKERS", () => {
    expect(() =>
      loadLogBusConfigFromEnv({ LOG_BUS_PROVIDER: "kafka" }),
    ).toThrow(/KAFKA_BROKERS/);
  });

  it("kafka SASL requires username+password", () => {
    expect(() =>
      loadLogBusConfigFromEnv({
        LOG_BUS_PROVIDER: "kafka",
        KAFKA_BROKERS: "a:9092",
        KAFKA_SASL_MECHANISM: "plain",
      }),
    ).toThrow(/KAFKA_SASL_USERNAME/);
  });

  it("kafka SASL parses with credentials + ssl", () => {
    const cfg = loadLogBusConfigFromEnv({
      LOG_BUS_PROVIDER: "kafka",
      KAFKA_BROKERS: "a:9092",
      KAFKA_SSL: "1",
      KAFKA_SASL_MECHANISM: "scram-sha-512",
      KAFKA_SASL_USERNAME: "u",
      KAFKA_SASL_PASSWORD: "p",
    });
    expect(cfg).toMatchObject({
      provider: "kafka",
      ssl: true,
      sasl: { mechanism: "scram-sha-512", username: "u", password: "p" },
    });
  });

  it("rejects an invalid kafka SASL mechanism", () => {
    expect(() =>
      loadLogBusConfigFromEnv({
        LOG_BUS_PROVIDER: "kafka",
        KAFKA_BROKERS: "a:9092",
        KAFKA_SASL_MECHANISM: "md5",
      }),
    ).toThrow(/KAFKA_SASL_MECHANISM/);
  });

  it("parses nats with defaults", () => {
    const cfg = loadLogBusConfigFromEnv({
      LOG_BUS_PROVIDER: "nats",
      NATS_SERVERS: "nats://x:4222",
    });
    expect(cfg).toEqual({
      provider: "nats",
      servers: ["nats://x:4222"],
      stream: "RAW_LOGS",
      subject: "raw.logs",
      durable: "phi-audit-ingest",
      tls: false,
    });
  });

  it("nats requires NATS_SERVERS", () => {
    expect(() => loadLogBusConfigFromEnv({ LOG_BUS_PROVIDER: "nats" })).toThrow(
      /NATS_SERVERS/,
    );
  });

  it("nats token auth wins; username/password must pair", () => {
    expect(
      loadLogBusConfigFromEnv({
        LOG_BUS_PROVIDER: "nats",
        NATS_SERVERS: "x:4222",
        NATS_TOKEN: "tok",
      }),
    ).toMatchObject({ auth: { token: "tok" } });
    expect(() =>
      loadLogBusConfigFromEnv({
        LOG_BUS_PROVIDER: "nats",
        NATS_SERVERS: "x:4222",
        NATS_USERNAME: "u",
      }),
    ).toThrow(/NATS_USERNAME and NATS_PASSWORD/);
  });
});

describe("createLogBus + registry", () => {
  beforeEach(() => resetLogBusForTests());

  it("memory provider yields an InMemoryLogBus", () => {
    expect(createLogBus({ provider: "memory" })).toBeInstanceOf(InMemoryLogBus);
  });

  it("getLogBus lazily defaults to the in-memory singleton", () => {
    const bus = getLogBus();
    expect(bus).toBeInstanceOf(InMemoryLogBus);
  });

  it("setLogBus/getLogBus round-trip", () => {
    const custom = new InMemoryLogBus();
    setLogBus(custom);
    expect(getLogBus()).toBe(custom);
  });

  it("initLogBusFromEnv registers and returns the bus", () => {
    const bus = initLogBusFromEnv({});
    expect(bus).toBeInstanceOf(InMemoryLogBus);
    expect(getLogBus()).toBe(bus);
  });
});
