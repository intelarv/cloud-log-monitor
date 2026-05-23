import {
  pgTable,
  text,
  bigint,
  timestamp,
  bigserial,
  uniqueIndex,
} from "drizzle-orm/pg-core";

// M2: external ledger notarization checkpoints.
//
// The hash chain on `ledger_entries` proves "no tampering since the last
// write" — but an attacker with both the writer role and the ability to
// re-run the verifier could rewrite the whole chain consistently and the
// verifier would say "ok". §23.2 specifies external notarization: at a
// cadence, sign the current head with a key in a SEPARATE trust zone and
// persist the signed checkpoint somewhere the production app cannot
// rewrite. Verifier then cross-checks each checkpoint against the live
// ledger row at the same seq.
//
// Replit-dev scaling: separate trust zone is modelled by a distinct env
// secret (`NOTARIZATION_SECRET`, NOT `SESSION_SECRET`) and an append-only
// table with the same ENABLE ALWAYS UPDATE/DELETE/TRUNCATE refusal as the
// ledger. In production this table would live in a separate account /
// project with WORM Object Lock, per §23.2.
export const ledgerCheckpointsTable = pgTable(
  "ledger_checkpoints",
  {
    id: bigserial("id", { mode: "number" }).primaryKey(),
    // The ledger seq this checkpoint attests to. Unique so we don't
    // double-notarize the same head — verifier dedupe relies on this.
    seq: bigint("seq", { mode: "number" }).notNull(),
    // Snapshot of `ledger_entries.hash` at the moment of notarization.
    headHash: text("head_hash").notNull(),
    notarizedAt: timestamp("notarized_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    // HMAC-SHA256(NOTARIZATION_SECRET, canonical(seq, head_hash, notarized_at)).
    signature: text("signature").notNull(),
    // Identifier of the signing key (e.g. "notarization-v1"). Carried so a
    // key rotation can be validated end-to-end and so a checkpoint signed
    // with a retired/unknown key surfaces as a verification failure.
    signingKeyId: text("signing_key_id").notNull(),
  },
  (t) => [uniqueIndex("ledger_checkpoints_seq_uniq").on(t.seq)],
);

export type LedgerCheckpoint = typeof ledgerCheckpointsTable.$inferSelect;
