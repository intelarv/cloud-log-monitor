import {
  pgTable,
  text,
  timestamp,
  index,
  boolean,
} from "drizzle-orm/pg-core";

// M1.6: break-glass grants for raw-PHI access.
//
// The dashboard's default view is always the redacted projection. When an
// analyst needs to see the underlying raw evidence for an incident, they must
// (a) complete step-up auth (proving recent possession of a second factor),
// (b) submit a written justification, and (c) be issued a *time-boxed*,
// *per-finding* grant.
//
// Threat model §EoP "Break-glass scope minimization":
//   - A break-glass grant MUST scope to a specific finding ID and time window;
//     MUST NOT grant blanket raw-PHI access.
//
// Every grant is ledgered on creation (`break_glass.granted`) and every
// subsequent raw-PHI read against the grant is ledgered separately
// (`break_glass.raw_phi_accessed`) per threat model §Repudiation
// "Every break-glass access MUST require a justification field, MUST be
// time-boxed, MUST auto-revoke, and MUST emit a ledger entry on grant and on
// each subsequent raw-PHI read during the window."
//
// Notes:
//   - `revokedAt` is application-level (no DB enforcement). The
//     application-side `findActiveGrant` query filters on
//     `expiresAt > now() AND revokedAt IS NULL`.
//   - This table is RLS-protected on tenant_id like every other tenant-scoped
//     table; see setup-sql.ts.
//   - No append-only trigger here. Revocation needs UPDATE. The fact that a
//     grant was issued AT ALL is captured in the ledger, so deletion/UPDATE
//     of grant rows cannot hide the original grant from auditors.
// M1.7: two-person rule.
//
// Grants on findings whose severity is `critical` require a second analyst to
// approve before raw access is permitted. The grant row is created in a
// PENDING state (`approverUserId IS NULL`) by the requester, and the approve
// endpoint flips `approverUserId` + `approvedAt` only if a *different* user
// in the same tenant completes step-up and approves.
//
// `requiresSecondApproval` is captured at grant-creation time (from the
// finding's then-current severity) so a later severity change cannot
// retroactively bypass the rule.
export const breakGlassGrantsTable = pgTable(
  "break_glass_grants",
  {
    id: text("id").primaryKey(),
    tenantId: text("tenant_id").notNull(),
    userId: text("user_id").notNull(),
    findingId: text("finding_id").notNull(),
    justification: text("justification").notNull(),
    grantedAt: timestamp("granted_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    requiresSecondApproval: boolean("requires_second_approval")
      .notNull()
      .default(false),
    approverUserId: text("approver_user_id"),
    approvedAt: timestamp("approved_at", { withTimezone: true }),
    approverStepUpReason: text("approver_step_up_reason"),
  },
  (t) => [
    index("bg_grants_tenant_user_idx").on(t.tenantId, t.userId),
    index("bg_grants_lookup_idx").on(
      t.tenantId,
      t.userId,
      t.findingId,
      t.expiresAt,
    ),
  ],
);

export type BreakGlassGrant = typeof breakGlassGrantsTable.$inferSelect;
