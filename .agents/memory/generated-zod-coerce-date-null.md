---
name: generated zod coerce.date() swallows null in nullable-date unions
description: Why server response handlers for endpoints with a nullable date-time field must NOT run the generated Zod response schema's .parse().
---

# `zod.coerce.date()` in a `union([coerce.date(), null])` rewrites genuine `null` → epoch 0

Orval/zod codegen turns an OpenAPI `oneOf: [string date-time, null]` field into
`zod.union([zod.coerce.date(), zod.null()])`. `zod.coerce.date()` greedily
accepts `null` — `new Date(null)` is `1970-01-01T00:00:00.000Z`, a *valid* Date —
so the union's first member matches and a real "never happened" `null` is
silently rewritten to the epoch timestamp. The `null` branch is never reached.

**Why it matters:** an endpoint whose `last_run_at` (or any nullable timestamp)
means "this never ran" will, if it pipes its response through the generated
`SomeResponse.parse(...)`, emit `1970-01-01...` instead of `null` — the UI then
shows "56 years ago" instead of "Never". A route test that asserts the literal
`null` for the empty/zero state catches this; a typecheck does not.

**How to apply:** for read endpoints that return a nullable date-time, return
the plain typed object (`res.json({...})`) and do NOT call the generated
response schema's `.parse()`. Cover the shape with a route test instead. The
notarization-checkpoints and maintenance-metrics handlers in
`artifacts/api-server/src/routes/ledger.ts` both follow this pattern and explain
it inline. (Input/request schemas are unaffected — this is only the
coercion-on-output hazard.)
