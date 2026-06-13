---
name: Async-start orchestration backends — fail-closed + buffer
description: How an opt-in durable backend whose start() does network I/O must behave at boot so it never silently drops work.
---

When you add an opt-in backend behind a default-inert seam (LOG_BUS_PROVIDER /
LLM_PROVIDER / WORKFLOW_ENGINE style) whose `start()` performs real network I/O
(connect a client, spin up a worker), two failure modes silently lose work and
must be designed against:

1. **Boot must fail-closed when the durable backend is the *selected* one.**
   The original boot wiring fired `start()` and only `logger.error`'d on
   rejection, then continued to `app.listen`. For the default in-process engine
   that's fine (its `start()` is synchronous and cannot reject). For a selected
   network backend, a failed start leaves an engine that accepts submits and
   drops them — strictly worse than crashing. Branch on `engine.kind`: crash
   (`process.exit(1)`) when the durable backend fails to start; keep log-only for
   the synchronous default.

2. **Fire-and-forget submit must buffer during the async startup window.**
   `start()` is awaited off the boot path (returns a stop fn synchronously), so
   events can arrive between "selected" and "worker ready" and get dropped. Give
   the engine an explicit phase machine (`idle → starting → running → stopped`):
   buffer submits (bounded, loud on overflow) while idle/starting, flush them in
   order on `start()`, dispatch while running, drop only while stopped. Reset to
   idle if `start()` throws so a retry starts clean.

**Why:** code review caught that a selected-but-unstartable Temporal engine
silently dropped every `finding.created` review — the whole point of choosing a
durable engine is *not* losing work, so degrading instead of crashing defeats it.

**How to apply:** any future `*_PROVIDER` / `*_ENGINE` seam whose opt-in branch
opens a connection or worker at boot. The default in-memory branch stays
byte-identical; the hardening lives entirely in the opt-in adapter + the boot
wiring's `kind`-aware catch.

## Retry policy on non-idempotent activities (Temporal-style durable backends)

A durable orchestrator (Temporal) auto-retries failed activities. If the
activity does non-idempotent side effects (here: per-tenant budget charge +
append-only audit-ledger writes) with NO per-step idempotency key, a retry after
a *partial* side effect duplicates them — for a compliance audit ledger that is
corruption, not just waste. Default the activity retry to `maximumAttempts: 1`
(at-most-once per step) so the durable path matches the no-retry in-process
engine. Exactly-once-per-work-item still comes from the acquire CAS + the
orchestrator's workflow-id idempotency, and worker failover still resumes from
*completed* activities via history replay (replay reuses recorded results — it is
independent of the retry policy). Only raise `maximumAttempts` once each step is
idempotent keyed by `{tenant, item, step}`.

**Why:** code review rejected `maximumAttempts: 3` on the review activities for
exactly this duplicate-ledger/double-charge risk.

**How to apply:** keep the retry-policy object in a pure, SDK-free module so it's
unit-testable without the optional `@temporalio/*` packages installed (assert
`retry.maximumAttempts === 1`); the workflow shim just imports it.
