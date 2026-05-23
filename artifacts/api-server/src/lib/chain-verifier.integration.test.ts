// DB-backed integration tests for verifyChainSince + dedupe + leader lock.
// Architect-flagged M1.9 follow-up: the M1.8 unit tests mock appendLedger,
// so the query semantics of verifyChainSince (especially the bigserial-gap
// tolerance fix) weren't directly exercised. These hit the real dev DB.
//
// Side-effects: appends a few ledger rows to the dev DB. The chain stays
// valid throughout (we never UPDATE/DELETE existing rows — the ENABLE
// ALWAYS triggers would refuse anyway), so this is safe to run repeatedly.

import { describe, it, expect, beforeAll } from "vitest";
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import { appendLedger, verifyChainSince, verifyChain } from "./ledger";
import { __test__ } from "./chain-verifier";

describe("verifyChainSince — DB integration", () => {
  beforeAll(async () => {
    // Ensure the boot path's full-chain verify is still green before we add
    // rows; if the dev DB is already corrupt, these tests' assertions
    // would be meaningless.
    const r = await verifyChain();
    expect(r.ok, `pre-existing chain is invalid: ${r.errors.join("; ")}`).toBe(
      true,
    );
  });

  it("empty window returns ok with walked=0 and genesis seed", async () => {
    // Future timestamp → no rows in window.
    const future = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);
    const r = await verifyChainSince(future);
    expect(r.ok).toBe(true);
    expect(r.walked).toBe(0);
  });

  it("validates a contiguous chain inside the window", async () => {
    const before = new Date();
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "verifyChainSince-contiguous" },
    });
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "verifyChainSince-contiguous-2" },
    });
    const r = await verifyChainSince(before);
    expect(r.ok, `errors: ${r.errors.join("; ")}`).toBe(true);
    expect(r.walked).toBeGreaterThanOrEqual(2);
  });

  it("tolerates a bigserial gap at the window BOUNDARY (architect's M1.8 correctness fix)", async () => {
    // The M1.8 bug was specifically in window-boundary seed lookup:
    // `eq(seq, first.seq - 1)` assumed contiguous seqs. We must put the
    // gap immediately BEFORE the first in-window row so the boundary lookup
    // is the thing under test, not an interior gap. The buggy version
    // would look for `first.seq - 1`, find nothing, and emit a false
    // `gap: missing row at seq N` error. The fixed version uses
    // `seq < first.seq ORDER BY seq DESC LIMIT 1` and walks from there.
    //
    // Append `preceding` row, bump the sequence to gap the next insert,
    // *then* mark `before` so `preceding` is OUTSIDE the window and the
    // gapped `in_window` row is the FIRST row inside it.
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "boundary-preceding" },
    });
    await db.execute(
      sql`SELECT setval(
        pg_get_serial_sequence('ledger_entries', 'seq'),
        (SELECT MAX(seq) + 5 FROM ledger_entries)
      )`,
    );
    // Ensure `before` lands strictly after the preceding row's ts.
    await new Promise((r) => setTimeout(r, 10));
    const before = new Date();
    await new Promise((r) => setTimeout(r, 10));
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "boundary-in-window" },
    });

    const r = await verifyChainSince(before);
    expect(r.ok, `errors: ${r.errors.join("; ")}`).toBe(true);
    expect(r.walked).toBeGreaterThanOrEqual(1);

    // Full chain walk shares walkFrom() and must also stay green.
    const full = await verifyChain();
    expect(full.ok, `errors: ${full.errors.join("; ")}`).toBe(true);
  });
});

describe("chain-verifier — leader lock + dedupe (DB integration)", () => {
  it("withLeaderLock: second concurrent caller is skipped", async () => {
    let firstReleased = false;
    const first = __test__.withLeaderLock("rolling_24h", async () => {
      // Hold the lock long enough for the second call to race.
      await new Promise((r) => setTimeout(r, 100));
      firstReleased = true;
      return "ran" as const;
    });
    // Race a second caller while the first is still inside.
    await new Promise((r) => setTimeout(r, 20));
    const second = await __test__.withLeaderLock("rolling_24h", async () => {
      return "ran" as const;
    });
    const firstResult = await first;
    expect(firstReleased).toBe(true);
    expect(firstResult).toBe("ran");
    expect(second).toBe("skipped");

    // After both settle, lock must be released — a third call gets it.
    const third = await __test__.withLeaderLock("rolling_24h", async () => "ran" as const);
    expect(third).toBe("ran");
  });

  it("isDuplicateChainInvalid: false when no prior chain_invalid matches this signature", async () => {
    // We don't actually emit one — we just assert the query returns false
    // for a synthetic signature that no real entry will ever carry.
    const synthetic = `seq 9999999999: synthetic test signature ${Date.now()}`;
    const dup = await __test__.isDuplicateChainInvalid("rolling_24h", synthetic);
    expect(dup).toBe(false);
  });
});
