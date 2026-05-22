import {
  pgTable,
  text,
  timestamp,
  index,
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
