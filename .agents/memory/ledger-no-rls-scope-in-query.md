---
name: ledger_entries has no RLS — in-app views must scope by tenant in the query
description: Why per-tenant ledger read endpoints need an explicit tenant_id predicate, unlike findings/chat/grants which rely on RLS.
---

# `ledger_entries` is a single global hash chain with NO RLS policy

Unlike `findings` / `chat_sessions` / `chat_messages` / `break_glass_grants` /
`finding_embeddings` (all FORCE-RLS, tenant-isolated via the `app.tenant_id`
GUC set by `withTenant`), `ledger_entries` deliberately has **no RLS policy**.

**Why:** the global hash chain + the periodic chain verifier + the external
notarizer must walk *every* tenant's entries in `seq` order to prove integrity.
RLS would break that global walk. So the table stays global by design, and the
global integrity endpoints (`/api/admin/ledger/verify`, `.../checkpoints`) must
stay global too.

**How to apply:** any *in-app, per-tenant* read of the ledger (e.g. the
`GET /api/ledger` list view) must add an **explicit** `eq(tenantId, session
tenant)` predicate — there is no RLS backstop. This applies to BOTH the entries
query AND the `head` (most-recent-row) query; a missed `head` predicate leaks
the global cross-tenant event count/hash even when the list is scoped. Entry
payloads carry tenant-private free text (break-glass justification /
approval_note / revoke reason), so an unscoped list is a real cross-tenant
disclosure, not just a count leak. Regression guard lives in
`cross-tenant-isolation.route.test.ts` (asserts list + head + payload text are
all tenant-local).
