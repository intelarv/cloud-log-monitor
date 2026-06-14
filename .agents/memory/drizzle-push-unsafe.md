---
name: drizzle-kit push is unsafe against this schema
description: Why DB reconciliation uses `db setup` (raw SETUP_SQL), never `drizzle-kit push`, and why making push's diff "clean" is dangerous.
---

# `drizzle-kit push` must not run against a populated DB

**Rule:** DB reconciliation (post-merge + app boot) uses the idempotent raw-SQL
bootstrap `pnpm --filter @workspace/db run setup` (SETUP_SQL), never
`drizzle-kit push`. Do not try to make push produce a clean diff, and never run
`push --force` on a populated DB.

**Why:** Much of the security layer is owned by raw DDL in `setup-sql.ts`
(RLS/FORCE RLS, the `findings_redacted` view, CHECK constraints like
`bg_no_self_approval`, pgvector + generated FTS column) that the Drizzle table
defs don't model. push diffs all of it as orphans and wants to DROP/DISABLE it.
push is "safe" today only by accident: the data-loss prompt on the populated
pgvector/FTS objects aborts the whole batch under closed stdin. Remove that
abort (clean diff, `--force`, or an empty DB) and the remaining **non-data-loss**
statements apply SILENTLY — disabling RLS and dropping the redacted view +
self-approval constraint. So making push "cleaner" makes it MORE dangerous.

**How to apply:** When post-merge push noise (data-loss warning / stack trace)
appears, fix it by using `db setup`, NOT by reconciling the Drizzle schema with
the raw objects. Test any drizzle config/schema experiment only on a throwaway
`CREATE DATABASE` scratch copy, never the dev DB (silent drops). Core Drizzle
tables (`findings`, `ledger_entries`, `chat_*`, `agent_identity`) are not in
SETUP_SQL — they come from a one-time fresh-DB `db push`; new core columns are
seated by `ADD COLUMN IF NOT EXISTS` in SETUP_SQL, so dropping push from
post-merge (an already-provisioned path) regresses nothing.
