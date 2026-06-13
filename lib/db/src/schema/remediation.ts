import { pgTable, text, timestamp, index } from "drizzle-orm/pg-core";

// Remediation proposals (HITL gate).
//
// Threat model §EoP "HITL gates on write actions":
//   Remediation tools (open PR, redact-at-source, channel send) MUST return
//   *proposals*, not executions. Human confirmation MUST be required and
//   ledgered. Confirmation MUST require the same auth scope as the proposed
//   action.
//
// An agent (today the chat agent, via the `propose_remediation` tool) writes a
// row here in the PENDING state. The proposal does nothing on its own — it is
// inert until a human reviews it. A human then either:
//   - confirms it (step-up gated, ledgered `remediation.confirmed`), which
//     records the authorization to act; the actual execution of the action is
//     an operator/out-of-band step by design (no tool in this system executes
//     code-touching remediations), or
//   - rejects it (session only, ledgered `remediation.rejected`).
//
// Both transitions are compare-and-swap on `status = 'pending'` so two
// concurrent decisions cannot double-ledger. The proposal's *creation* is
// already in the immutable ledger (`remediation.proposed`), so — like
// break-glass grants — losing/mutating the row cannot hide it from auditors;
// no append-only trigger is needed here (the decision transition needs UPDATE).
//
// `actionType` is a free-form (Zod-enum-constrained at the tool boundary)
// label describing what the agent proposes; `summary`/`rationale` are
// human-readable text that is scanned for PHI/secrets/canary by the tool-arg
// policy pass before it is ever written (agents only see redacted evidence, so
// by construction these carry no raw PHI).
//
// RLS-protected on tenant_id like every other tenant-scoped table; see
// setup-sql.ts.
export const remediationProposalsTable = pgTable(
  "remediation_proposals",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull(),
    findingId: text("finding_id").notNull(),
    actionType: text("action_type").notNull(),
    summary: text("summary").notNull(),
    rationale: text("rationale").notNull(),
    // Who proposed it: the agent that called the tool + the human session
    // user_id under which the agent was running (the analyst who drove the
    // chat). Both are recorded for attribution per threat model §Repudiation.
    proposedByAgent: text("proposed_by_agent").notNull(),
    proposedByUserId: text("proposed_by_user_id").notNull(),
    // pending | confirmed | rejected
    status: text("status").notNull().default("pending"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    decidedByUserId: text("decided_by_user_id"),
    decidedAt: timestamp("decided_at", { withTimezone: true }),
    decisionNote: text("decision_note"),
    deciderStepUpReason: text("decider_step_up_reason"),
  },
  (t) => [
    index("remediation_tenant_status_idx").on(t.tenantId, t.status),
    index("remediation_tenant_finding_idx").on(t.tenantId, t.findingId),
  ],
);

export const REMEDIATION_STATUSES = [
  "pending",
  "confirmed",
  "rejected",
] as const;

export type RemediationProposal =
  typeof remediationProposalsTable.$inferSelect;
