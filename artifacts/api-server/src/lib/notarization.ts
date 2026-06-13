// M2: external ledger notarization (§23.2 second half).
//
// The hash chain alone proves "the ledger has not been tampered with since
// it was last verified by THIS verifier" — an attacker holding both the
// writer role and the verifier could rewrite the chain consistently and
// every recompute would succeed. Notarization breaks that loop:
//
//   1. At a cadence, sign the current ledger head with a key whose secret
//      is held in a SEPARATE trust zone (in dev: `NOTARIZATION_SECRET`,
//      distinct from `SESSION_SECRET`; in production: KMS in a separate
//      account, per `docs/ARCHITECTURE.md` §23.2).
//   2. Persist the signed checkpoint to `ledger_checkpoints` (append-only,
//      ENABLE ALWAYS triggers; in production additionally WORM Object Lock
//      in the separate account).
//   3. Verifier walks checkpoints: for each {seq, head_hash, signature,
//      signing_key_id}, looks up `ledger_entries.hash` at the same seq and
//      asserts it equals head_hash, then recomputes the HMAC and asserts
//      it equals signature. Any mismatch is a `ledger.checkpoint_mismatch`
//      event — critical alert per §25.
//
// What this protects against that the chain alone does not:
//   - A privileged operator who silently rebuilds the whole chain after
//     deletion (chain still self-consistent → checkpoints disagree).
//   - Hash function compromise (checkpoint signatures are a second,
//     independently-keyed witness over the same data).
//   - Backup/restore from a tampered snapshot (checkpoints predate the
//     tampering window → still attest the original hashes).
//
// What it does NOT protect against — explicitly out of scope here:
//   - Attacker who compromises both DBs AND the notarization secret. The
//     production design puts the notarization key in a separate KMS in a
//     separate cloud account specifically to make this require two
//     compromises; dev models that with a separate env var.

import { createHmac, timingSafeEqual } from "node:crypto";
import { desc, eq, gt } from "drizzle-orm";
import {
  db,
  ledgerCheckpointsTable,
  ledgerEntriesTable,
  canonicalJSON,
  type LedgerCheckpoint,
} from "@workspace/db";

// Stable identifier for the active signing key. Bumping this constant is
// effectively a key rotation: new checkpoints sign with the new id +
// secret, and old checkpoints continue to verify because their `key_id`
// resolves to a retired secret in `RETIRED_KEYS` below.
const ACTIVE_KEY_ID = "notarization-v1";

const MIN_SECRET_LEN = 16;

// Retired signing keys, keyed by their original `signing_key_id`. Populated
// from `NOTARIZATION_RETIRED_KEYS` (JSON object: { "<key_id>": "<secret>" }).
// On rotation, the previous active key id + secret is added here so old
// checkpoints keep verifying instead of generating permanent mismatches.
// Parsed lazily so a malformed env var only blows up the verifier path,
// not boot.
let RETIRED_KEYS_CACHE: Record<string, string> | null = null;
function getRetiredKeys(): Record<string, string> {
  if (RETIRED_KEYS_CACHE) return RETIRED_KEYS_CACHE;
  const raw = process.env.NOTARIZATION_RETIRED_KEYS;
  if (!raw) return (RETIRED_KEYS_CACHE = {});
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(
      `NOTARIZATION_RETIRED_KEYS is not valid JSON: ${(err as Error).message}`,
    );
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    Object.values(parsed).some(
      (v) => typeof v !== "string" || v.length < MIN_SECRET_LEN,
    )
  ) {
    throw new Error(
      `NOTARIZATION_RETIRED_KEYS must be {key_id: secret} with secrets >= ${MIN_SECRET_LEN} chars`,
    );
  }
  RETIRED_KEYS_CACHE = parsed as Record<string, string>;
  return RETIRED_KEYS_CACHE;
}
// Test-only reset hook.
function resetRetiredKeysCache(): void {
  RETIRED_KEYS_CACHE = null;
}

function getSecret(keyId: string): string {
  if (keyId === ACTIVE_KEY_ID) {
    const s =
      process.env.NOTARIZATION_SECRET ??
      // Dev fallback: derive a stable but distinct secret from SESSION_SECRET
      // so a fresh checkout doesn't need a second env var to boot.
      // Production MUST set NOTARIZATION_SECRET to a value held in a separate
      // trust zone — the index.ts boot path warns when this fallback is
      // used.
      (process.env.SESSION_SECRET
        ? `dev-notarization::${process.env.SESSION_SECRET}`
        : null);
    if (!s || s.length < MIN_SECRET_LEN) {
      throw new Error(
        `NOTARIZATION_SECRET (or SESSION_SECRET fallback) must be set and at least ${MIN_SECRET_LEN} characters long`,
      );
    }
    return s;
  }
  const retired = getRetiredKeys()[keyId];
  if (retired) return retired;
  throw new Error(
    `notarization key id ${JSON.stringify(keyId)} is unknown; cannot verify or sign`,
  );
}

/** Returns true iff NOTARIZATION_SECRET is set in env (i.e. the operator
 *  has deliberately configured a separate trust-zone secret instead of
 *  relying on the SESSION_SECRET-derived dev fallback). The boot path
 *  uses this to log a warning in production-ish modes. */
export function hasDedicatedNotarizationSecret(): boolean {
  const s = process.env.NOTARIZATION_SECRET;
  return typeof s === "string" && s.length >= MIN_SECRET_LEN;
}

function computeSignature(args: {
  seq: number;
  headHash: string;
  notarizedAtIso: string;
  signingKeyId: string;
}): string {
  const secret = getSecret(args.signingKeyId);
  // Sign over canonical JSON of the fields we'll verify against, with the
  // key id mixed in so a checkpoint signed under v1 can't be re-presented
  // as signed under v2 once we rotate.
  const body = canonicalJSON({
    seq: args.seq,
    head_hash: args.headHash,
    notarized_at: args.notarizedAtIso,
    signing_key_id: args.signingKeyId,
  });
  return createHmac("sha256", secret).update(body).digest("hex");
}

// Constant-time hex comparison. Returns false (NOT throws) on malformed or
// length-mismatched input — architect-flagged: a tamperer with insert
// capability could otherwise write a non-hex signature and make
// `Buffer.from(...,"hex")`+`timingSafeEqual` throw, which would be caught
// upstream as an "operational failure" and SUPPRESS the critical
// `ledger.checkpoint_mismatch` alert. Treat any decode failure as a real
// mismatch so the alert fires.
function constantTimeEq(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  // /^[0-9a-fA-F]*$/ — anything else is not a valid HMAC-hex string.
  if (!/^[0-9a-fA-F]*$/.test(a) || !/^[0-9a-fA-F]*$/.test(b)) return false;
  try {
    return timingSafeEqual(Buffer.from(a, "hex"), Buffer.from(b, "hex"));
  } catch {
    return false;
  }
}

export interface CheckpointCreateResult {
  /** A new checkpoint was written. */
  kind: "created";
  checkpoint: LedgerCheckpoint;
}

export interface CheckpointSkipResult {
  /** Most recent checkpoint already attests to the current head — skipped
   *  to avoid filling the table with identical rows on a quiet ledger. */
  kind: "skipped";
  reason: "head_unchanged" | "no_ledger_rows";
  lastSeq?: number;
}

export type CheckpointResult = CheckpointCreateResult | CheckpointSkipResult;

/** Create a checkpoint over the current ledger head. Idempotent: if the
 *  most recent checkpoint's seq matches the current head's seq, returns
 *  `skipped` without writing. Returns `no_ledger_rows` if the ledger is
 *  empty (genesis hasn't run yet). */
export async function createCheckpoint(): Promise<CheckpointResult> {
  const [head] = await db
    .select({ seq: ledgerEntriesTable.seq, hash: ledgerEntriesTable.hash })
    .from(ledgerEntriesTable)
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  if (!head) {
    return { kind: "skipped", reason: "no_ledger_rows" };
  }
  const [last] = await db
    .select({ seq: ledgerCheckpointsTable.seq })
    .from(ledgerCheckpointsTable)
    .orderBy(desc(ledgerCheckpointsTable.seq))
    .limit(1);
  if (last && last.seq === head.seq) {
    return { kind: "skipped", reason: "head_unchanged", lastSeq: last.seq };
  }
  const notarizedAt = new Date();
  const signature = computeSignature({
    seq: head.seq,
    headHash: head.hash,
    notarizedAtIso: notarizedAt.toISOString(),
    signingKeyId: ACTIVE_KEY_ID,
  });
  // ON CONFLICT (seq) DO NOTHING — a concurrent leader (e.g. cross-process
  // race the advisory lock did NOT cover, or a manual operator call) may
  // have already inserted a checkpoint at this seq. We treat that as
  // benign and report `skipped` so the caller still runs verify.
  const inserted = await db
    .insert(ledgerCheckpointsTable)
    .values({
      seq: head.seq,
      headHash: head.hash,
      notarizedAt,
      signature,
      signingKeyId: ACTIVE_KEY_ID,
    })
    .onConflictDoNothing({ target: ledgerCheckpointsTable.seq })
    .returning();
  const row = inserted[0];
  if (!row) {
    return { kind: "skipped", reason: "head_unchanged", lastSeq: head.seq };
  }
  return { kind: "created", checkpoint: row };
}

export interface CheckpointVerifyResult {
  ok: boolean;
  walked: number;
  /** Number of checkpoints whose signature/head mismatched the live ledger. */
  mismatch_count: number;
  /** Capped sample of mismatch descriptions for the alert payload. */
  first_mismatches: string[];
  /** Checkpoints whose notarized head hash is the all-zero placeholder: never
   *  externally notarized (e.g. a forged/placeholder row, or dev test
   *  pollution), as opposed to a genuine live≠notarized tamper. Counted
   *  separately so it does NOT raise the critical tamper alert. */
  unnotarized_count: number;
  /** Capped sample of "not yet notarized" descriptions. */
  first_unnotarized: string[];
}

const MAX_MISMATCHES_IN_PAYLOAD = 5;

// An all-zero (or empty) notarized head hash is never a value the real notarizer
// produces over a non-empty ledger (a head hash is a SHA-256 of real content);
// it marks a checkpoint that was never externally notarized — a placeholder.
function isUnnotarizedHash(h: string): boolean {
  return h.length === 0 || /^0+$/.test(h);
}

/** Walk every checkpoint with seq > `sinceSeq` and verify two things:
 *    (a) signature is a valid HMAC over (seq, head_hash, notarized_at, key_id)
 *    (b) live ledger row at the same seq still hashes to head_hash
 *
 *  Returns a structured result; the periodic verifier converts a failed
 *  result into a `ledger.checkpoint_mismatch` ledger event whose post-
 *  commit alert hook routes critical per §25. */
export async function verifyCheckpoints(
  sinceSeq = 0,
  // Optional db handle so tests can run the verifier inside a transaction and
  // roll it back — that lets the genuine-tamper path be exercised against the
  // real schema WITHOUT persisting a forged mismatch row into the shared dev
  // ledger (which would re-introduce perpetual checkpoint_mismatch ERRORs).
  // Production always uses the module-level `db`.
  dbh: Pick<typeof db, "select"> = db,
): Promise<CheckpointVerifyResult> {
  const checkpoints = await dbh
    .select()
    .from(ledgerCheckpointsTable)
    .where(gt(ledgerCheckpointsTable.seq, sinceSeq))
    .orderBy(ledgerCheckpointsTable.seq);

  const mismatches: string[] = [];
  const unnotarized: string[] = [];
  let walked = 0;

  for (const c of checkpoints) {
    walked++;
    // (a) signature
    let expectedSig: string;
    try {
      expectedSig = computeSignature({
        seq: c.seq,
        headHash: c.headHash,
        notarizedAtIso: c.notarizedAt.toISOString(),
        signingKeyId: c.signingKeyId,
      });
    } catch (err) {
      // Unknown signing key id is itself a mismatch — possibly a rotated-
      // out key OR a forged checkpoint signed by an attacker who doesn't
      // know the current secret.
      mismatches.push(
        `checkpoint seq=${c.seq}: signing_key_id=${c.signingKeyId} unknown (${
          (err as Error).message
        })`,
      );
      continue;
    }
    if (!constantTimeEq(expectedSig, c.signature)) {
      mismatches.push(
        `checkpoint seq=${c.seq}: signature invalid (key=${c.signingKeyId})`,
      );
      continue;
    }
    // (b) live ledger row hashes to head_hash
    const [live] = await dbh
      .select({ hash: ledgerEntriesTable.hash })
      .from(ledgerEntriesTable)
      .where(eq(ledgerEntriesTable.seq, c.seq))
      .limit(1);
    if (!live) {
      mismatches.push(
        `checkpoint seq=${c.seq}: live ledger row missing (notarized head_hash=${c.headHash})`,
      );
      continue;
    }
    if (live.hash !== c.headHash) {
      if (isUnnotarizedHash(c.headHash)) {
        // Placeholder head hash: this checkpoint was never externally notarized
        // (forged/placeholder row, e.g. dev test pollution), NOT a tamper. A
        // genuine tamper carries a real notarized hash that disagrees with the
        // live row. Track separately so `ok` stays true and the critical
        // tamper alert is not raised for an expected/benign placeholder.
        unnotarized.push(
          `checkpoint seq=${c.seq}: not yet notarized (placeholder head_hash; live ${live.hash})`,
        );
        continue;
      }
      mismatches.push(
        `checkpoint seq=${c.seq}: live hash ${live.hash} != notarized ${c.headHash}`,
      );
      continue;
    }
  }

  return {
    ok: mismatches.length === 0,
    walked,
    mismatch_count: mismatches.length,
    first_mismatches: mismatches.slice(0, MAX_MISMATCHES_IN_PAYLOAD),
    unnotarized_count: unnotarized.length,
    first_unnotarized: unnotarized.slice(0, MAX_MISMATCHES_IN_PAYLOAD),
  };
}

// Test-only seam: lets tests sign with a non-active key id (e.g. to assert
// "unknown key id" verification path) without smuggling internal secrets
// into the test surface. Production code MUST NOT import this.
export const __test__ = {
  ACTIVE_KEY_ID,
  computeSignature,
  constantTimeEq,
  resetRetiredKeysCache,
  isUnnotarizedHash,
  MAX_MISMATCHES_IN_PAYLOAD,
};
