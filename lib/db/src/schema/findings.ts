import {
  pgTable,
  text,
  jsonb,
  timestamp,
  integer,
  index,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const FINDING_CLASSIFICATIONS = [
  "phi",
  "secrets",
  "pii",
  "pii_s",
  "internal",
  "config",
  "phi_in_output",
] as const;

export const FINDING_SEVERITIES = ["low", "medium", "high", "critical"] as const;
export const FINDING_STATUSES = ["open", "resolved", "false_positive"] as const;

export const findingsTable = pgTable(
  "findings",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull().default("default"),
    classification: text("classification").notNull(),
    subclass: text("subclass"),
    severity: text("severity").notNull(),
    status: text("status").notNull().default("open"),
    source: text("source").notNull(),
    fingerprint: text("fingerprint").notNull(),
    redactedEvidence: jsonb("redacted_evidence").notNull(),
    detectorVersion: text("detector_version").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    occurrenceCount: integer("occurrence_count").notNull().default(1),
  },
  (t) => [
    index("findings_tenant_idx").on(t.tenantId),
    index("findings_tenant_status_idx").on(t.tenantId, t.status),
    index("findings_fingerprint_idx").on(t.tenantId, t.fingerprint),
  ],
);

export const insertFindingSchema = createInsertSchema(findingsTable);
export type InsertFinding = z.infer<typeof insertFindingSchema>;
export type Finding = typeof findingsTable.$inferSelect;
