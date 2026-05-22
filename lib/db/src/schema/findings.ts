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
    // M1.6: raw evidence is the unredacted source. Nullable because most
    // findings in dev have no raw payload — only the canary does, for the
    // break-glass-flow demo. In production this column is populated by the
    // detector pipeline writing into a separately-encrypted column / WORM
    // tier, and the dashboard's normal queries MUST NOT select it (only the
    // step-up-gated /admin/findings/:id/raw endpoint reads it).
    rawEvidence: jsonb("raw_evidence"),
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

// M1.6: explicit safe column projection for findings. Use this with
// `tx.select(findingSafeColumns).from(findingsTable)` everywhere EXCEPT the
// step-up-gated /admin/findings/:id/raw endpoint. The only column omitted is
// `rawEvidence`; this is the database-layer enforcement of the threat-model
// invariant "raw PHI only reachable via the break-glass code path". Using
// `tx.select()` with no projection picks up `rawEvidence` and is a bug.
export const findingSafeColumns = {
  id: findingsTable.id,
  tenantId: findingsTable.tenantId,
  classification: findingsTable.classification,
  subclass: findingsTable.subclass,
  severity: findingsTable.severity,
  status: findingsTable.status,
  source: findingsTable.source,
  fingerprint: findingsTable.fingerprint,
  redactedEvidence: findingsTable.redactedEvidence,
  detectorVersion: findingsTable.detectorVersion,
  firstSeenAt: findingsTable.firstSeenAt,
  lastSeenAt: findingsTable.lastSeenAt,
  occurrenceCount: findingsTable.occurrenceCount,
} as const;

// Matches `Finding` minus `rawEvidence`. Drizzle infers this from the
// projection at query sites, but we name the type for explicit annotations.
export type FindingSafe = Omit<Finding, "rawEvidence">;
