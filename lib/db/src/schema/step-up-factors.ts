import {
  pgTable,
  text,
  timestamp,
  bigint,
  primaryKey,
  index,
} from "drizzle-orm/pg-core";

// Production step-up second factor (TOTP) enrollment store.
//
// Replaces the dev shared-token (`STEP_UP_DEV_TOKEN`) when
// `STEP_UP_PROVIDER=totp`. One factor per (tenant, user): the analyst enrolls
// an authenticator app once, then proves possession of a fresh 6-digit code on
// every step-up (raw-PHI break-glass, remediation confirm, …).
//
// Security posture:
//   - `secretEnc` holds the TOTP shared secret ENCRYPTED at rest (AES-256-GCM
//     under the per-tenant key from resolveTenantSecret, falling back to
//     SESSION_SECRET). The plaintext base32 secret is NEVER stored, satisfying
//     threat_model §Information Disclosure ("secrets at rest").
//   - `verifiedAt` is NULL until the user confirms enrollment with a live code,
//     so a provisioned-but-unconfirmed secret can never satisfy a step-up.
//   - `lastUsedStep` is the replay guard: each accepted code's RFC 6238 step
//     counter is recorded, and a code from that step or earlier is refused, so
//     a captured 6-digit code cannot be reused within its skew window.
//   - Tenant-scoped + RLS-isolated exactly like every other tenant table; see
//     setup-sql.ts. Provisioned via the idempotent `db setup` path, never push.
export const stepUpFactorsTable = pgTable(
  "step_up_factors",
  {
    tenantId: text("tenant_id").notNull(),
    userId: text("user_id").notNull(),
    // Reserved for future factor types (e.g. "webauthn"); only "totp" today.
    type: text("type").notNull().default("totp"),
    secretEnc: text("secret_enc").notNull(),
    verifiedAt: timestamp("verified_at", { withTimezone: true }),
    lastUsedStep: bigint("last_used_step", { mode: "number" }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [
    primaryKey({ columns: [t.tenantId, t.userId] }),
    index("step_up_factors_tenant_user_idx").on(t.tenantId, t.userId),
  ],
);

export type StepUpFactor = typeof stepUpFactorsTable.$inferSelect;
