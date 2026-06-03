---
name: Dashboard timestamp render safety
description: Why the dashboard must never feed raw server timestamps to date-fns inline, and how that is enforced.
---

# Dashboard timestamp render safety

**Rule:** In `artifacts/dashboard`, never call `format(new Date(x))` or
`formatDistanceToNow(new Date(x))` directly in render. Always go through the
shared guarded helpers `safeTimestamp(ts, fmt?)` / `safeRelativeTime(ts)` in
`src/lib/format.ts`, which return `"unknown time"` for non-string / unparseable
values.

**Why:** These formatters throw `RangeError: Invalid time value` on a malformed
or missing date. Because they run inline during render, one bad row (corrupt /
partial ledger entry, half-written finding, an unexpected null from a future API
shape) white-screens the *entire* page for a compliance analyst — the same class
of crash that the finding-history work originally hit. The audit dashboard's job
is to stay legible even when the data behind it is broken.

**How to apply:** New pages/panels that show a timestamp import from
`../lib/format`. The `dashboard-typecheck` + `dashboard-test` validation
commands run on every change; keep render-resilience covered so a regression
fails the gate instead of reaching a user. The same defensive posture applies to
other render-time parsing (actor objects, payload fields, enums) — guard with a
fallback rather than assuming shape; see `findings-list-strict-parse.md`.
