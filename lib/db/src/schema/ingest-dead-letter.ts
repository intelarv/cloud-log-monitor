import { pgTable, text, integer, timestamp } from "drizzle-orm/pg-core";

// M8 (DLQ): terminal-failure dead-letter store for the ingest pipeline.
//
// When a `raw.logs` record fails to process after the bounded per-record
// retry (DB blip, transient downstream error, genuine poison record), the
// pipeline records a metadata-only marker here and ACKs the record so a real
// broker stops redelivering the poison message forever. The marker is enough
// for an operator to (a) know a specific source record was dropped, (b)
// correlate it back to the authoritative log source by `source_record_id`,
// and (c) decide whether to re-pull it — WITHOUT duplicating the raw payload
// into a queryable hot table.
//
// PHI posture (threat_model §InformationDisclosure): the raw log payload is
// attacker-controlled and may contain PHI, so it is NEVER stored here. We
// keep only the source-provenance pointer + a `payload_sha256` for
// correlation + the error name + attempt count. This mirrors the existing
// `ingest.malformed_record` precedent (lengths/hash only, never the raw
// value). The authoritative raw payload stays in the upstream log source.
//
// Like `log_source_checkpoints`, this table is operator/system-scoped and
// carries no audit-evidence weight (the tamper-evident anchor is the
// `ingest.dead_lettered` ledger event). It is NOT under ENABLE ALWAYS
// triggers and NOT RLS-scoped. Default-inert: only written when the operator
// opts the DLQ in (`INGEST_DEAD_LETTER_ENABLED`).
export const ingestDeadLetterTable = pgTable("ingest_dead_letter", {
  id: text("id").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  sourceType: text("source_type").notNull(),
  sourceName: text("source_name").notNull(),
  sourceRecordId: text("source_record_id").notNull(),
  // Correlation hash only — never the raw (possibly-PHI) payload.
  payloadSha256: text("payload_sha256").notNull(),
  payloadBytes: integer("payload_bytes").notNull(),
  // Error NAME only (e.g. "Error", "DatabaseError") — never the raw message,
  // which could embed payload-derived values.
  error: text("error").notNull(),
  // Total attempts made before giving up (includes the first try).
  attempts: integer("attempts").notNull(),
  deadLetteredAt: timestamp("dead_lettered_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type IngestDeadLetter = typeof ingestDeadLetterTable.$inferSelect;
