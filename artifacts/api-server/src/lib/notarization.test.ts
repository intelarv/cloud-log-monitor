// M2: notarization unit + DB-integration tests.
//
// Unit tests cover the signature primitive (deterministic, key-id-domain-
// separated, tampering detected). Integration tests exercise the full
// flow against the real dev DB: createCheckpoint round-trip, verify ok,
// verify catches a head-hash divergence injected by directly tampering the
// checkpoint row (we can't tamper the ledger row — ENABLE ALWAYS refuses —
// which is itself one of the system's tamper-evidence guarantees; the
// "ledger row rewritten" scenario in production is what the checkpoint
// row pinning the *old* hash would catch).

import { describe, it, expect, beforeAll } from "vitest";
import { sql } from "drizzle-orm";
import { db } from "@workspace/db";
import {
  createCheckpoint,
  verifyCheckpoints,
  hasDedicatedNotarizationSecret,
  __test__,
} from "./notarization";
import { appendLedger, verifyChain } from "./ledger";

const {
  computeSignature,
  constantTimeEq,
  resetRetiredKeysCache,
  isUnnotarizedHash,
  ACTIVE_KEY_ID,
  MAX_MISMATCHES_IN_PAYLOAD,
} = __test__;

describe("notarization signature primitive", () => {
  it("is deterministic for the same inputs", () => {
    const args = {
      seq: 42,
      headHash: "a".repeat(64),
      notarizedAtIso: "2026-05-23T12:00:00.000Z",
      signingKeyId: ACTIVE_KEY_ID,
    };
    expect(computeSignature(args)).toBe(computeSignature(args));
  });

  it("changes when any input changes (tamper detection)", () => {
    const base = {
      seq: 42,
      headHash: "a".repeat(64),
      notarizedAtIso: "2026-05-23T12:00:00.000Z",
      signingKeyId: ACTIVE_KEY_ID,
    };
    const sig = computeSignature(base);
    expect(computeSignature({ ...base, seq: 43 })).not.toBe(sig);
    expect(computeSignature({ ...base, headHash: "b".repeat(64) })).not.toBe(sig);
    expect(
      computeSignature({ ...base, notarizedAtIso: "2026-05-23T12:00:00.001Z" }),
    ).not.toBe(sig);
  });

  it("refuses to sign/verify with an unknown key id (rotation safety)", () => {
    expect(() =>
      computeSignature({
        seq: 1,
        headHash: "x".repeat(64),
        notarizedAtIso: "2026-01-01T00:00:00.000Z",
        signingKeyId: "notarization-v999",
      }),
    ).toThrow(/notarization-v999.*unknown/);
  });

  it("constantTimeEq returns false (not throws) on malformed hex — alert-suppression fix", () => {
    // Architect-flagged: if constantTimeEq throws on malformed signature
    // bytes, the upstream catch suppresses ledger.checkpoint_mismatch.
    // Must return false instead, so the mismatch path is taken.
    const valid = "a".repeat(64);
    expect(constantTimeEq(valid, "zz" + "a".repeat(62))).toBe(false);
    expect(constantTimeEq(valid, "not-hex-at-all-not-hex-at-all-not-hex-at-all-not-hex-at-all-xxxx")).toBe(false);
    expect(constantTimeEq(valid, "a".repeat(63))).toBe(false);
    expect(constantTimeEq(valid, "")).toBe(false);
    expect(constantTimeEq(valid, valid)).toBe(true);
  });

  it("isUnnotarizedHash distinguishes the all-zero placeholder from a real head hash", () => {
    // The all-zero (or empty) head hash marks a checkpoint that was never
    // externally notarized — a placeholder/forged row, NOT a tamper. A real
    // SHA-256 head hash (any non-zero hex) must NOT be treated as unnotarized,
    // so genuine live≠notarized tampers still take the critical mismatch path.
    expect(isUnnotarizedHash("0".repeat(64))).toBe(true);
    expect(isUnnotarizedHash("")).toBe(true);
    expect(isUnnotarizedHash("0")).toBe(true);
    expect(isUnnotarizedHash("f".repeat(64))).toBe(false);
    expect(isUnnotarizedHash("a".repeat(64))).toBe(false);
    // A single non-zero nibble anywhere is enough to count as "notarized".
    expect(isUnnotarizedHash("0".repeat(63) + "1")).toBe(false);
  });

  it("retired key id resolves via NOTARIZATION_RETIRED_KEYS — rotation safety", () => {
    const origRetired = process.env.NOTARIZATION_RETIRED_KEYS;
    try {
      const retiredSecret = "x".repeat(32);
      process.env.NOTARIZATION_RETIRED_KEYS = JSON.stringify({
        "notarization-v0": retiredSecret,
      });
      resetRetiredKeysCache();
      // Should sign + verify using the retired key without throwing.
      const sig = computeSignature({
        seq: 1,
        headHash: "a".repeat(64),
        notarizedAtIso: "2026-01-01T00:00:00.000Z",
        signingKeyId: "notarization-v0",
      });
      expect(sig).toMatch(/^[0-9a-f]{64}$/);
      // Same inputs reproduce same signature (deterministic).
      expect(
        computeSignature({
          seq: 1,
          headHash: "a".repeat(64),
          notarizedAtIso: "2026-01-01T00:00:00.000Z",
          signingKeyId: "notarization-v0",
        }),
      ).toBe(sig);
      // Genuinely unknown key still throws.
      expect(() =>
        computeSignature({
          seq: 1,
          headHash: "a".repeat(64),
          notarizedAtIso: "2026-01-01T00:00:00.000Z",
          signingKeyId: "notarization-v999",
        }),
      ).toThrow(/notarization-v999.*unknown/);
    } finally {
      if (origRetired === undefined) delete process.env.NOTARIZATION_RETIRED_KEYS;
      else process.env.NOTARIZATION_RETIRED_KEYS = origRetired;
      resetRetiredKeysCache();
    }
  });

  it("hasDedicatedNotarizationSecret reflects env presence", () => {
    const orig = process.env.NOTARIZATION_SECRET;
    try {
      delete process.env.NOTARIZATION_SECRET;
      expect(hasDedicatedNotarizationSecret()).toBe(false);
      process.env.NOTARIZATION_SECRET = "x".repeat(32);
      expect(hasDedicatedNotarizationSecret()).toBe(true);
      // Sub-minimum length must be treated as unset for safety.
      process.env.NOTARIZATION_SECRET = "short";
      expect(hasDedicatedNotarizationSecret()).toBe(false);
    } finally {
      if (orig === undefined) delete process.env.NOTARIZATION_SECRET;
      else process.env.NOTARIZATION_SECRET = orig;
    }
  });
});

describe("notarization — DB integration", () => {
  beforeAll(async () => {
    const r = await verifyChain();
    expect(r.ok, `pre-existing chain invalid: ${r.errors.join("; ")}`).toBe(true);
  });

  it("createCheckpoint round-trips and verifyCheckpoints reports ok", async () => {
    // Make sure SOMETHING changed since the last checkpoint so the create
    // isn't skipped as "head_unchanged". A test marker ledger row is fine.
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "notarization-roundtrip" },
    });
    const created = await createCheckpoint();
    expect(created.kind).toBe("created");
    if (created.kind !== "created") return;

    // Scope verification to JUST the checkpoint we created. The shared dev
    // DB may already carry forged-checkpoint rows from prior runs of the
    // "detects a tampered checkpoint row" test (see deferred isolation
    // gotcha in replit.md M1.9). Walking the whole table would
    // false-positive on those legitimate mismatches.
    const verify = await verifyCheckpoints(created.checkpoint.seq - 1);
    expect(
      verify.ok,
      `mismatches: ${verify.first_mismatches.join("; ")}`,
    ).toBe(true);
    expect(verify.walked).toBeGreaterThanOrEqual(1);
  });

  it("is idempotent: second call with unchanged head is skipped", async () => {
    // First call (may create or skip depending on prior test state).
    await createCheckpoint();
    // M1.9 gotcha: other test files share this DB and may append ledger
    // rows between our two calls, so the second call may itself "create"
    // a new checkpoint at the advanced head. The invariant we actually
    // need is: a call that observes no head change returns "skipped".
    // So loop up to a few times until we get two back-to-back calls
    // with no intervening write, and assert the second is skipped.
    let lastSkip: Awaited<ReturnType<typeof createCheckpoint>> | null = null;
    for (let i = 0; i < 5 && !lastSkip; i++) {
      await createCheckpoint();
      const r = await createCheckpoint();
      if (r.kind === "skipped") lastSkip = r;
    }
    expect(lastSkip?.kind).toBe("skipped");
    if (lastSkip?.kind === "skipped") {
      expect(lastSkip.reason).toBe("head_unchanged");
    }
  });

  it("ledger_checkpoints refuses direct UPDATE (ENABLE ALWAYS append-only guarantee)", async () => {
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "notarization-update-refusal-target" },
    });
    const created = await createCheckpoint();
    expect(created.kind).toBe("created");
    if (created.kind !== "created") return;
    const id = created.checkpoint.id;

    // Direct UPDATE on ledger_checkpoints would be refused by ENABLE ALWAYS.
    // Confirm that — this is itself a tamper-evidence guarantee we want
    // covered. (drizzle wraps the underlying trigger error in a "Failed
    // query" envelope; we just assert it rejects and that the row didn't
    // actually change.)
    await expect(
      db.execute(
        sql`UPDATE ledger_checkpoints SET head_hash = ${"f".repeat(64)} WHERE id = ${id}`,
      ),
    ).rejects.toThrow();
    const afterRes = await db.execute<{ head_hash: string }>(
      sql`SELECT head_hash FROM ledger_checkpoints WHERE id = ${id}`,
    );
    expect(afterRes.rows[0]!.head_hash).toBe(created.checkpoint.headHash);
  });

  it("classifies an all-zero checkpoint as never-notarized, NOT a tamper mismatch", async () => {
    // Simulate the placeholder/forged-row condition (the historical dev-DB
    // pollution): a checkpoint whose head_hash is the all-zero sentinel and
    // does NOT match the live ledger row at that seq. Pre-fix this surfaced as
    // a critical `checkpoint_mismatch` every verifier cycle; post-fix it must
    // be classified as "not yet notarized" so `ok` stays true and the tamper
    // ERROR is not raised. INSERTs are allowed (append-only blocks UPDATE/DELETE
    // only); the all-zero row persists harmlessly because it is now quiet.
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "advance-head-for-unnotarized-slot" },
    });
    const headRes = await db.execute<{ seq: number }>(
      sql`SELECT seq FROM ledger_entries ORDER BY seq DESC LIMIT 1`,
    );
    const liveHeadSeq = Number(headRes.rows[0]!.seq);
    const zeroHash = "0".repeat(64);
    const notarizedAt = new Date();
    const sigForZero = computeSignature({
      seq: liveHeadSeq,
      headHash: zeroHash,
      notarizedAtIso: notarizedAt.toISOString(),
      signingKeyId: ACTIVE_KEY_ID,
    });
    await db.execute(
      sql`INSERT INTO ledger_checkpoints (seq, head_hash, notarized_at, signature, signing_key_id)
          VALUES (${liveHeadSeq}, ${zeroHash}, ${notarizedAt}, ${sigForZero}, ${ACTIVE_KEY_ID})
          ON CONFLICT (seq) DO NOTHING`,
    );

    // Scope to JUST our inserted seq so the assertion is robust to other rows.
    const verify = await verifyCheckpoints(liveHeadSeq - 1);
    // The all-zero row is "not yet notarized", never a mismatch.
    expect(verify.unnotarized_count).toBeGreaterThanOrEqual(1);
    expect(verify.first_unnotarized[0]).toMatch(/not yet notarized/);
    expect(
      verify.first_mismatches.every((m) => !/notarized 0{64}/.test(m)),
      `all-zero rows must NOT appear as mismatches: ${verify.first_mismatches.join("; ")}`,
    ).toBe(true);
    // No genuine mismatch in this scope ⇒ ok stays true (spam-fix invariant).
    expect(verify.mismatch_count).toBe(0);
    expect(verify.ok).toBe(true);
  });

  it("still flags a genuine (non-zero) head-hash mismatch as a critical tamper (rolled back so dev stays clean)", async () => {
    // Genuine tamper = a checkpoint pinning a REAL (non-zero) head hash that
    // disagrees with the live ledger row. This MUST still be a critical
    // mismatch. We run it inside a transaction and roll back so we don't leave
    // a persistent forged-mismatch row that would re-introduce perpetual
    // checkpoint_mismatch ERRORs in the shared dev DB.
    await appendLedger({
      tenantId: null,
      actor: { kind: "system", id: "integration_test" },
      eventType: "system.integration_test_marker",
      payload: { marker: "advance-head-for-genuine-tamper-slot" },
    });
    const wrongHash = "f".repeat(64);
    const notarizedAt = new Date();
    const ROLLBACK = "rollback-genuine-tamper-sentinel";
    let asserted = false;
    try {
      await db.transaction(async (tx) => {
        const head = await tx.execute<{ seq: number; hash: string }>(
          sql`SELECT seq, hash FROM ledger_entries ORDER BY seq DESC LIMIT 1`,
        );
        const liveSeq = Number(head.rows[0]!.seq);
        // The live row's real hash must differ from our forged non-zero hash.
        expect(head.rows[0]!.hash).not.toBe(wrongHash);
        const sig = computeSignature({
          seq: liveSeq,
          headHash: wrongHash,
          notarizedAtIso: notarizedAt.toISOString(),
          signingKeyId: ACTIVE_KEY_ID,
        });
        await tx.execute(
          sql`INSERT INTO ledger_checkpoints (seq, head_hash, notarized_at, signature, signing_key_id)
              VALUES (${liveSeq}, ${wrongHash}, ${notarizedAt}, ${sig}, ${ACTIVE_KEY_ID})
              ON CONFLICT (seq) DO NOTHING`,
        );
        const verify = await verifyCheckpoints(liveSeq - 1, tx);
        expect(verify.ok).toBe(false);
        expect(verify.mismatch_count).toBeGreaterThanOrEqual(1);
        expect(
          verify.first_mismatches.some((m) => /!= notarized f{64}/.test(m)),
          `expected a non-zero tamper mismatch: ${verify.first_mismatches.join("; ")}`,
        ).toBe(true);
        expect(verify.first_mismatches.length).toBeLessThanOrEqual(
          MAX_MISMATCHES_IN_PAYLOAD,
        );
        // A genuine tamper is NOT counted as unnotarized.
        expect(verify.unnotarized_count).toBe(0);
        asserted = true;
        // Force rollback: the forged row never commits.
        throw new Error(ROLLBACK);
      });
    } catch (err) {
      if ((err as Error).message !== ROLLBACK) throw err;
    }
    expect(asserted).toBe(true);
  });
});
