import { pgTable, text, timestamp, uniqueIndex, index } from "drizzle-orm/pg-core";

// Redaction request queue (out-of-band operator action sink).
//
// The `RedactionQueueExecutor` backend (artifacts/api-server/src/lib/
// remediation-executor.ts, gated on `REMEDIATION_EXECUTOR=redaction-queue` or
// the `routed` map) is the safe realization of the `redact_at_source`
// remediation action. The agent plane MUST NOT directly mutate or delete data
// at the cloud source (a confused-deputy with delete authority is the highest-
// blast-radius surface in the threat model). Instead, executing a CONFIRMED
// redact-at-source proposal enqueues a row here; a separate, out-of-band
// operator process (with its own scoped credentials and review) drains the
// queue and performs the actual source redaction, flipping `status`
// queued → in_progress → done | failed itself.
//
// Idempotency: one row per proposal (unique tenant_id + proposal_id). The
// executing worker already CAS-guards confirmed→executing so the executor is
// called at most once, but the unique index + ON CONFLICT DO NOTHING make the
// enqueue itself internally idempotent (a retried tick re-resolves the same id).
//
// PHI posture: `summary`/`rationale` are the agent-authored, already-PHI-scanned
// action description copied from the confirmed proposal (agents only ever see
// redacted evidence). This is an INTERNAL, RLS-isolated table at the same trust
// level as `remediation_proposals` — it never crosses a non-BAA boundary — so it
// carries the same data the proposal already holds at rest. No raw evidence.
//
// RLS-protected on tenant_id like every other tenant-scoped table; see
// setup-sql.ts.
export const redactionRequestsTable = pgTable(
  "redaction_requests",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull(),
    findingId: text("finding_id").notNull(),
    proposalId: text("proposal_id").notNull(),
    actionType: text("action_type").notNull(),
    summary: text("summary").notNull(),
    rationale: text("rationale").notNull(),
    // queued | in_progress | done | failed — driven by the out-of-band operator
    // drainer, not by the agent plane.
    status: text("status").notNull().default("queued"),
    requestedAt: timestamp("requested_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    uniqueIndex("redaction_requests_tenant_proposal_idx").on(
      t.tenantId,
      t.proposalId,
    ),
    index("redaction_requests_tenant_status_idx").on(t.tenantId, t.status),
  ],
);

export const REDACTION_REQUEST_STATUSES = [
  "queued",
  "in_progress",
  "done",
  "failed",
] as const;

export type RedactionRequest = typeof redactionRequestsTable.$inferSelect;
