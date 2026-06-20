import { pgTable, text, bigint, timestamp, primaryKey } from "drizzle-orm/pg-core";

// Cluster-wide per-tenant daily LLM cost-budget counter (opt-in
// AGENT_BUDGET_STORE=postgres).
//
// The default budget store (agent-budget.ts) is the original per-PROCESS
// in-memory Map: byte-identical to the pre-seam breaker, and the only thing the
// credential-free eval gate ever exercises. Its limitation is documented in
// agent-budget.ts: a multi-process Temporal deployment with N workers gets N
// independent budget maps, each enforcing the cap on its own — so the effective
// fleet-wide cap is up to N× the configured per-tenant budget.
//
// This table is the shared backing store that closes that gap: every worker
// charges the SAME (tenant_id, day_key) row via an atomic upsert-increment, so
// the per-tenant daily token cap is enforced once across the whole fleet
// (threat_model §DoS "per-tenant daily budgets MUST be enforced").
//
// `day_key` is the UTC calendar day (YYYY-MM-DD) the tokens were charged on, so
// the budget rolls over at UTC midnight exactly like the in-memory store; old
// days simply stop being read (and can be reaped out-of-band). Composite PK
// (tenant_id, day_key) is the ON CONFLICT arbiter for the atomic increment.
//
// PHI posture: counters only — tenant id, calendar day, an integer token total.
// No finding content, no PHI. RLS-isolated on tenant_id like every other
// tenant-scoped table (see setup-sql.ts).
export const tenantBudgetsTable = pgTable(
  "tenant_budgets",
  {
    tenantId: text("tenant_id").notNull(),
    dayKey: text("day_key").notNull(),
    tokensUsed: bigint("tokens_used", { mode: "number" }).notNull().default(0),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (t) => [primaryKey({ columns: [t.tenantId, t.dayKey] })],
);

export type TenantBudgetRow = typeof tenantBudgetsTable.$inferSelect;
