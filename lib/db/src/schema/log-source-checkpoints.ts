import { pgTable, text, bigint, timestamp } from "drizzle-orm/pg-core";

// M8: per-source ingest checkpoint store.
//
// A real cloud log source (CloudWatch, Cloud Logging, Azure Monitor) is a
// pull-based stream. The consumer commits its position so a restart resumes
// where it left off — without this we'd either re-ingest the whole window
// on every boot (dedupe absorbs the dup but burns API quota + reprocess
// cost) or miss the window between stop and start.
//
// Unlike `ledger_entries` / `ledger_checkpoints`, this table is MUTABLE by
// design — the checkpoint advances on every successful poll batch. It is
// NOT under ENABLE ALWAYS triggers; it carries no audit-evidence weight.
// The audit anchor for ingested findings is `finding.created` in the
// ledger, which is itself locked down.
//
// `source_name` is the application-level source identifier
// (`cloudwatch:<tenant>:<logGroup>`) and is the primary key — there is
// exactly one cursor per source. `tenant_id` is duplicated for RLS
// readability and so an operator dashboard can group by tenant without
// parsing the source_name.
export const logSourceCheckpointsTable = pgTable("log_source_checkpoints", {
  sourceName: text("source_name").primaryKey(),
  tenantId: text("tenant_id").notNull(),
  // Source-side event timestamp in milliseconds since epoch. CloudWatch
  // returns ms-precision timestamps; we store as bigint to avoid Date
  // round-tripping issues at API boundaries.
  lastEventTs: bigint("last_event_ts", { mode: "number" }).notNull(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export type LogSourceCheckpoint = typeof logSourceCheckpointsTable.$inferSelect;
