// Shared test-support harness for the DB-backed integration suites (M1.9).
//
// Background (replit.md "Gotchas" → DB integration tests): these suites run
// against the *shared dev Postgres ledger*. They cannot assume the table is
// clean — other suites (and prior runs) leave `system.integration_test_marker`
// rows, bigserial gaps, and the occasional forged checkpoint row behind. The
// agreed isolation discipline is therefore NOT "clean the table" (the ledger is
// append-only by design and the writer role has no DELETE grant) but:
//
//   1. capture the ledger head sequence BEFORE the code under test runs, then
//      assert only over rows with `seq > sinceSeq` (ignore prior pollution);
//   2. give every test its own unguessable tenant id / source id / fingerprint
//      so concurrent or replayed rows can never collide.
//
// Every DB suite used to re-declare its own `uniq()` + `ledgerHeadSeq()` /
// `currentHeadSeq()` (13 and 12 copies respectively, with subtly different SQL
// and return-coercion). This module is the single source of truth for that
// scoping vocabulary so the discipline is applied identically everywhere.
//
// NOTE on `fileParallelism: false` (vitest.config.ts): this harness reduces
// cross-test COUPLING (shared, consistent scoping) but does NOT by itself make
// it safe to run suites in parallel. `appendLedger` serializes every write
// behind a single Postgres advisory lock and the notarization scheduler asserts
// a head-sequence idempotency invariant; parallel file workers race that
// invariant regardless of per-test tenant scoping. Serialized execution is a
// genuine correctness requirement here, not merely a pollution workaround, so
// it stays — documented rather than silently flipped.

import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";

/** Short random suffix for source ids, fingerprints, user ids, etc. Kept
 *  identical to the value every suite previously inlined so existing id shapes
 *  are unchanged. */
export function uniq(): string {
  return Math.random().toString(36).slice(2, 10);
}

/** A per-test tenant id that cannot collide with the seed tenant (`default`)
 *  or with another test. Use this instead of a hardcoded `"default"` whenever a
 *  test does not specifically rely on seeded `default`-tenant rows. */
export function uniqueTenant(label = "t"): string {
  return `${label}_${randomUUID()}`;
}

/** Current ledger head sequence (0 when empty). Capture before the code under
 *  test, then scope assertions to `seq > sinceSeq` so prior pollution and other
 *  suites' rows are excluded. Canonical replacement for the per-file
 *  `ledgerHeadSeq()` / `currentHeadSeq()` copies. */
export async function ledgerHeadSeq(): Promise<number> {
  const res = await db.execute(
    sql`SELECT COALESCE(MAX(seq), 0)::int AS head FROM ledger_entries`,
  );
  return Number((res.rows[0] as { head?: number }).head ?? 0);
}
