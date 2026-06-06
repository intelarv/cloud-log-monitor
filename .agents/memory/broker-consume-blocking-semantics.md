---
name: Broker consume() blocking semantics (KafkaJS vs NATS)
description: Why the shared BrokerDriver.consume() awaits Kafka's run() directly but background-drains the NATS iterator — a non-obvious SDK difference.
---

When implementing a `consume()` that "starts consuming and resolves once the
subscription is established" over two different broker SDKs, the two SDKs have
OPPOSITE blocking semantics — get this wrong and either boot hangs or messages
are never consumed:

- **KafkaJS `consumer.run({ eachMessage })`** RESOLVES promptly, right after the
  background fetch loop is launched. `eachMessage` fires off that detached
  runner. So you `await consumer.run(...)` directly and `consume()` returns —
  boot proceeds to `app.listen()`.
- **NATS JetStream `for await (const m of sub)`** BLOCKS for the lifetime of the
  subscription. You must drain it in a detached `void (async () => { ... })()`
  IIFE, otherwise `consume()` never resolves and boot deadlocks.

**Why:** A code reviewer (and anyone reasoning from the `consume()` signature
alone) will naturally assume `await driver.consume()` blocks for Kafka the same
way the NATS iterator does, and flag a false "startup deadlock." It is not a
deadlock — it's the documented KafkaJS contract. Don't "fix" the Kafka path by
backgrounding `run()`; that would drop the start-failure error on the floor.

**How to apply:** In any `BrokerDriver.consume()` that must resolve after
subscription setup: await Kafka's `run()`; background-drain the NATS async
iterator. Keep `BrokeredLogBus.start()` wrapping `consume()` in try/catch that
closes the driver on failure so a post-`connect()` failure can't leak the
broker connection.
