import { describe, it, expect, vi } from "vitest";
import { InMemoryLogBus } from "./log-bus";
import type { LogRecord } from "./log-source";

function makeRecord(over: Partial<LogRecord> = {}): LogRecord {
  return {
    tenantId: "default",
    sourceType: "fixture",
    sourceName: "test",
    sourceRecordId: "r1",
    observedAt: new Date(),
    ingestedAt: new Date(),
    payload: "hello",
    ...over,
  };
}

describe("InMemoryLogBus", () => {
  it("publish with no subscribers reports zero delivered, zero errors", async () => {
    const bus = new InMemoryLogBus();
    const out = await bus.publish("raw.logs", makeRecord());
    expect(out).toEqual({ delivered: 0, errors: [] });
  });

  it("subscribe then publish delivers the record to the handler", async () => {
    const bus = new InMemoryLogBus();
    const fn = vi.fn().mockResolvedValue(undefined);
    bus.subscribe("raw.logs", fn);
    const rec = makeRecord({ sourceRecordId: "x" });
    await bus.publish("raw.logs", rec);
    expect(fn).toHaveBeenCalledTimes(1);
    expect(fn).toHaveBeenCalledWith(rec);
  });

  it("dispatches to every subscriber", async () => {
    const bus = new InMemoryLogBus();
    const a = vi.fn().mockResolvedValue(undefined);
    const b = vi.fn().mockResolvedValue(undefined);
    bus.subscribe("raw.logs", a);
    bus.subscribe("raw.logs", b);
    await bus.publish("raw.logs", makeRecord());
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
  });

  it("a throwing handler does not prevent other handlers from running and is reported in errors", async () => {
    const bus = new InMemoryLogBus();
    const a = vi.fn().mockRejectedValue(new Error("boom"));
    const b = vi.fn().mockResolvedValue(undefined);
    bus.subscribe("raw.logs", a);
    bus.subscribe("raw.logs", b);
    const out = await bus.publish("raw.logs", makeRecord());
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);
    expect(out.delivered).toBe(1);
    expect(out.errors).toHaveLength(1);
    expect((out.errors[0]!.err as Error).message).toBe("boom");
  });

  it("unsubscribe stops further delivery to that handler", async () => {
    const bus = new InMemoryLogBus();
    const fn = vi.fn().mockResolvedValue(undefined);
    const unsub = bus.subscribe("raw.logs", fn);
    await bus.publish("raw.logs", makeRecord());
    unsub();
    await bus.publish("raw.logs", makeRecord());
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("delivers in registration order (sequential dispatch)", async () => {
    const bus = new InMemoryLogBus();
    const order: string[] = [];
    bus.subscribe("raw.logs", async () => {
      await new Promise((r) => setTimeout(r, 5));
      order.push("a");
    });
    bus.subscribe("raw.logs", async () => {
      order.push("b");
    });
    await bus.publish("raw.logs", makeRecord());
    expect(order).toEqual(["a", "b"]);
  });
});
