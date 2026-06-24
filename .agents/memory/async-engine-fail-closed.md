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

## Awaited one-shot jobs CANNOT buffer like fire-and-forget submits — inline-fallback instead

The buffer-during-startup rule above is for **fire-and-forget** work (submitReview
returns void; cron schedules). A one-shot job whose **result is awaited by the
caller** (boot search-index reconcile logs the counts; the replay route returns
`{replayed,delivered,errors}`) cannot be buffered across the async-start window —
there is no caller still waiting by the time the worker comes up. So an
`executeOneShot<T>(job): Promise<T>` seam must, when the durable engine isn't
`running` yet, run `job.run()` **inline** (logged) and return that, NOT enqueue.
This is safe only because the migrated one-shots are idempotent (reconcile is a
no-op for the Postgres provider) or dev-only (fixture replay). The boot reconcile
*always* takes this inline path under `WORKFLOW_ENGINE=temporal` because it runs
before `startAgentSupervisor` selects+starts the engine.

**Why:** the periodic/reaper migration was fire-and-forget so it could buffer;
the one-shot migration looks identical but the awaited return value changes the
correct degraded behavior from "buffer + flush" to "run inline now".

**How to apply:** when deciding buffer-vs-inline for a not-yet-running durable
backend, branch on whether the caller awaits a result. Awaited ⇒ inline fallback
(only if the unit is idempotent/safe to run off the durable path). Fire-and-forget
⇒ buffer + flush. Also: one-shots must use a UNIQUE per-run workflow id (they are
intentionally NOT deduped, unlike the fixed-id cron jobs whose AlreadyStarted is
swallowed for idempotency).
