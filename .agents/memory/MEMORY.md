# Memory Index

- [Raw-evidence tiering vs ingest ref ownership](raw-evidence-tiering.md) — migrating inline raw→ref must MERGE (don't overwrite a newer ingest-seated ref.latest), not just write+null.
- [Detector test fixtures: valid SSNs only](detector-test-fixtures.md) — SSNs with area 666 (and 000/900-999) are never-allocated → detector ignores them → no finding; pick valid SSNs in tests.
- [Derived-cache eviction concurrency guard](derived-cache-eviction-concurrency.md) — eviction/pruning DELETEs must re-check the never-evict predicate against the live source row in the same statement (READ COMMITTED lets state flip between SELECT and DELETE).
- [Generated zod coerce.date() swallows null](generated-zod-coerce-date-null.md) — nullable date-time response fields must skip the generated `.parse()`; `coerce.date()` rewrites `null` → epoch 0 (1970). Return plain object, cover with a route test.
- [Async-start orchestration backends fail-closed + buffer](async-engine-fail-closed.md) — an opt-in durable backend (Temporal-style) whose start() does network I/O must crash boot on start failure, not log+continue, and buffer fire-and-forget submits during the async startup window or it silently drops work.
- [Partition config vs schema drift](partition-config-vs-schema-drift.md) — one-way DDL conversions: derive the runtime code path (e.g. ON CONFLICT arbiter) from the live catalog, not the env flag that requested it.
- [Live Temporal worker not runnable in dev sandbox](temporal-live-test-sandbox.md) — server+native worker OOMs (137) here; killed calls roll back file writes; `find /nix/store` is >30s. Verify via gated test elsewhere.
- [Retryable side-effect step idempotency](retryable-side-effect-idempotency.md) — to auto-retry a step doing ledger+budget side effects: gate on ledger idempotencyKey, recover result from payload, charge AFTER the gate write.
- [Dashboard UI tests are committed vitest component tests](dashboard-ui-tests.md) — "automated UI test" deliverables must land as committed vitest+RTL files; ephemeral Playwright-subagent runs alone get rejected at code review.
