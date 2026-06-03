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
    // M10.2/M10.3: pointer to raw evidence held in an EXTERNAL WORM object
    // store (S3 Object Lock / GCS retention / Azure Blob immutability) instead
    // of the `raw_evidence` column. Holds `{first, latest}` object URIs (see
    // RawEvidenceRef in api-server's raw-evidence-store.ts). NULL when the
    // database store is active (raw stays inline in `raw_evidence`) — exactly
    // one of the two columns carries raw for a given finding. Like
    // `raw_evidence`, this is deliberately EXCLUDED from `findingSafeColumns`:
    // it is only ever read on the step-up-gated /admin/findings/:id/raw path,
    // which resolves it back to the payload through the configured store.
    rawEvidenceRef: jsonb("raw_evidence_ref"),
    detectorVersion: text("detector_version").notNull(),
    firstSeenAt: timestamp("first_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    lastSeenAt: timestamp("last_seen_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    occurrenceCount: integer("occurrence_count").notNull().default(1),
    // M5: multi-agent supervisor review state. The Supervisor enqueues a
    // Triage → Verifier pass on every newly-created finding. CAS on
    // `agentReviewStatus` is the idempotency gate so a finding is never
    // double-reviewed even if `finding.created` fires twice.
    //   pending      → not yet picked up
    //   in_progress  → a supervisor worker is currently running it
    //   completed    → both triage + verifier succeeded; verdicts populated
    //   failed       → at least one specialist errored; verdicts may be partial
    //   skipped      → cost-budget or operator opt-out; no LLM call made
    agentReviewStatus: text("agent_review_status").notNull().default("pending"),
    // Verdict shapes are documented in lib/agents/{triage,verifier}.ts.
    // Both are nullable until the corresponding agent has run.
    triageVerdict: jsonb("triage_verdict"),
    verifierVerdict: jsonb("verifier_verdict"),
    lastAgentReviewAt: timestamp("last_agent_review_at", { withTimezone: true }),
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
  // M5: agent-review verdicts are safe to expose — agents only ever
  // see redacted evidence, so verdict text/rationale cannot contain raw
  // PHI by construction. Verifier output is additionally re-scanned
  // before persist (see lib/agents/supervisor.ts) as defense-in-depth.
  agentReviewStatus: findingsTable.agentReviewStatus,
  triageVerdict: findingsTable.triageVerdict,
  verifierVerdict: findingsTable.verifierVerdict,
  lastAgentReviewAt: findingsTable.lastAgentReviewAt,
} as const;

// Matches `Finding` minus the raw-evidence columns. Drizzle infers this from
// the projection at query sites, but we name the type for explicit
// annotations. BOTH `rawEvidence` (inline DB store) and `rawEvidenceRef`
// (external WORM store pointer) are omitted — neither may enter a safe
// projection, an LLM prompt, or an SSE frame; both are reachable only via the
// step-up-gated /admin/findings/:id/raw endpoint.
export type FindingSafe = Omit<Finding, "rawEvidence" | "rawEvidenceRef">;
