#!/bin/bash
set -e
pnpm install --frozen-lockfile

# DB reconciliation uses the idempotent raw-SQL bootstrap (`@workspace/db setup`,
# = SETUP_SQL), NOT `drizzle-kit push`.
#
# Why not `drizzle-kit push`: a large part of this schema is owned by raw DDL in
# `lib/db/src/setup-sql.ts` — pgvector `finding_embeddings`, the generated
# `findings.search_tsv` FTS column + its GIN index, ROW LEVEL SECURITY (+ FORCE
# RLS) on every tenant-scoped table, the `findings_redacted` view, and CHECK
# constraints such as break-glass `bg_no_self_approval`. drizzle-kit only knows
# the Drizzle table definitions, so `push` diffs all of those as orphans and
# wants to DROP/DISABLE them. Today that push is only "safe" by accident: the
# data-loss prompt on dropping the populated `finding_embeddings`/`search_tsv`
# aborts the whole batch under a closed stdin, so nothing is applied. Remove or
# bypass that abort (e.g. `--force`, or an empty DB) and push would SILENTLY
# disable RLS and drop the redacted view + self-approval constraint — a security
# teardown. So push must never run against a populated DB here.
#
# `setup` is idempotent (CREATE/ALTER ... IF NOT EXISTS, CREATE OR REPLACE) and
# is the exact bootstrap the API server runs on boot, so running it here is
# safe, quiet, and self-healing. Core Drizzle tables are provisioned out of band
# (a one-time `pnpm --filter @workspace/db run push` on a fresh DB); post-merge
# always runs against an already-provisioned environment.
pnpm --filter @workspace/db run setup
