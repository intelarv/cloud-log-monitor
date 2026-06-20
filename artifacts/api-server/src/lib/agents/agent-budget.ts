// Per-tenant LLM cost-budget circuit breaker (extracted from supervisor.ts in
// the WorkflowEngine refactor so both the in-process engine AND the Temporal
// activities share ONE budget source without a circular import).
//
// M12.3: the breaker is keyed by tenant so a runaway loop or malicious ingest
// burst in tenant A cannot drain the shared budget and starve tenant B's
// reviews (threat_model §DoS "per-tenant daily budgets" + §EoP "per-tenant LLM
// context isolation"). DAILY_TOKEN_BUDGET is the per-tenant cap. Single-tenant
// deployments (incl. the credential-free eval gate, which only exercises the
// seed `default` tenant) behave identically to the pre-M12.3 global singleton —
// the only observable difference appears when two tenants run concurrently.
//
// STORE SEAM (AGENT_BUDGET_STORE): the counter lives behind an `AgentBudgetStore`
// interface, selected exactly like every other provider seam in this repo:
//   - unset | "memory"  -> MemoryBudgetStore (DEFAULT): the original per-PROCESS
//     in-memory Map. Byte-identical to the pre-seam breaker; the only store the
//     offline eval gate ever exercises. Per-process limitation: a Temporal
//     deployment with N worker processes gets N independent budget maps (each
//     enforces its own cap), so the effective fleet-wide cap is up to N× the
//     configured per-tenant budget — same per-process limitation the queue
//     always had.
//   - "postgres"          -> PostgresBudgetStore (opt-in): a shared
//     `tenant_budgets` row per (tenant_id, UTC day) charged via an atomic
//     upsert-increment, so the per-tenant daily cap is enforced ONCE across the
//     whole fleet. Closes the multi-process gap above.
//
// The store methods are async (a DB-backed store does I/O); the default memory
// store resolves synchronously-in-spirit (the Promise wraps a Map read), so the
// default path keeps the same semantics and the eval gate stays byte-identical.

import { sql } from "drizzle-orm";
import { logger } from "../logger";

// Daily cost budget per process/tenant. Approximate; real billing comes from
// the provider. The point is a hard process-level kill-switch so a runaway loop
// or a malicious ingest burst cannot drain the LLM budget. Per ARCH §23.15.
// Architect-flagged M5 fix: validate the env. `Number(undefined)` is `NaN`, and
// `tokensUsed >= NaN` is always `false` — i.e. an invalid env value would
// silently DISABLE the breaker. Fall back to the default on any non-finite or
// non-positive value and log a boot warning at first read.
export const DAILY_TOKEN_BUDGET = (() => {
  const raw = process.env["AGENT_DAILY_TOKEN_BUDGET"];
  if (raw === undefined) return 1_000_000;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[supervisor] AGENT_DAILY_TOKEN_BUDGET=${raw} is not a positive finite number; falling back to 1,000,000`,
    );
    return 1_000_000;
  }
  return n;
})();

export interface BudgetState {
  dayKey: string;
  tokensUsed: number;
}

function utcDayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

// ---------------------------------------------------------------------------
// Store seam
// ---------------------------------------------------------------------------

/** Pluggable budget counter. All methods are async because a DB-backed store
 *  does I/O; the memory store resolves immediately. */
export interface AgentBudgetStore {
  readonly kind: "memory" | "postgres";
  charge(tenantId: string, tokens: number): Promise<void>;
  exceeded(tenantId: string): Promise<boolean>;
  tokensUsedToday(tenantId: string): Promise<number>;
}

// ---------------------------------------------------------------------------
// Memory store (DEFAULT): the original per-process Map, behavior-preserved.
// ---------------------------------------------------------------------------

export class MemoryBudgetStore implements AgentBudgetStore {
  readonly kind = "memory" as const;
  private readonly budgets = new Map<string, BudgetState>();

  /** Get the tenant's budget state, creating it and rolling it over to today on
   *  the first touch of a new UTC day. */
  private tenantBudget(tenantId: string): BudgetState {
    const today = utcDayKey(new Date());
    let b = this.budgets.get(tenantId);
    if (!b) {
      b = { dayKey: today, tokensUsed: 0 };
      this.budgets.set(tenantId, b);
    } else if (b.dayKey !== today) {
      b.dayKey = today;
      b.tokensUsed = 0;
    }
    return b;
  }

  charge(tenantId: string, tokens: number): Promise<void> {
    this.tenantBudget(tenantId).tokensUsed += tokens;
    return Promise.resolve();
  }

  exceeded(tenantId: string): Promise<boolean> {
    return Promise.resolve(
      this.tenantBudget(tenantId).tokensUsed >= DAILY_TOKEN_BUDGET,
    );
  }

  tokensUsedToday(tenantId: string): Promise<number> {
    return Promise.resolve(this.tenantBudget(tenantId).tokensUsed);
  }

  // --- sync test knobs (memory-only) -------------------------------------
  reset(tenantId?: string): void {
    if (tenantId === undefined) {
      this.budgets.clear();
      return;
    }
    this.budgets.set(tenantId, {
      dayKey: utcDayKey(new Date()),
      tokensUsed: 0,
    });
  }

  snapshot(tenantId = "default"): Readonly<BudgetState> {
    return { ...this.tenantBudget(tenantId) };
  }

  forceExhaust(tenantId = "default"): void {
    this.budgets.set(tenantId, {
      dayKey: utcDayKey(new Date()),
      tokensUsed: DAILY_TOKEN_BUDGET + 1,
    });
  }
}

// ---------------------------------------------------------------------------
// Postgres store (opt-in): one shared row per (tenant_id, UTC day).
// ---------------------------------------------------------------------------

export class PostgresBudgetStore implements AgentBudgetStore {
  readonly kind = "postgres" as const;

  /** Atomic upsert-increment of the (tenant_id, today) counter. The single
   *  ON CONFLICT (tenant_id, day_key) DO UPDATE statement is the cross-process
   *  serialization point — N workers charging concurrently each add their
   *  delta to the same row with no read-modify-write race. Runs under the
   *  tenant GUC so RLS scopes the write. Old days are simply never read again. */
  async charge(tenantId: string, tokens: number): Promise<void> {
    if (tokens === 0) return;
    const { withTenant } = await import("../db-context");
    const day = utcDayKey(new Date());
    await withTenant(tenantId, async (tx) => {
      await tx.execute(sql`
        INSERT INTO tenant_budgets (tenant_id, day_key, tokens_used, updated_at)
        VALUES (${tenantId}, ${day}, ${tokens}, now())
        ON CONFLICT (tenant_id, day_key) DO UPDATE
          SET tokens_used = tenant_budgets.tokens_used + EXCLUDED.tokens_used,
              updated_at = now()
      `);
    });
  }

  async exceeded(tenantId: string): Promise<boolean> {
    return (await this.tokensUsedToday(tenantId)) >= DAILY_TOKEN_BUDGET;
  }

  async tokensUsedToday(tenantId: string): Promise<number> {
    const { withTenant } = await import("../db-context");
    const day = utcDayKey(new Date());
    return withTenant(tenantId, async (tx) => {
      const res = await tx.execute<{ tokens_used: number | string }>(sql`
        SELECT tokens_used FROM tenant_budgets
        WHERE tenant_id = ${tenantId} AND day_key = ${day}
      `);
      const row = res.rows[0];
      return row ? Number(row.tokens_used) : 0;
    });
  }
}

// ---------------------------------------------------------------------------
// Selection + active-store registry (singleton).
// ---------------------------------------------------------------------------

/** The memory store is kept as a concrete reference so the sync test knobs can
 *  reach its Map even when (in tests) it is also the active store. */
const memoryStore = new MemoryBudgetStore();

let activeStore: AgentBudgetStore | null = null;

function selectStoreFromEnv(env: NodeJS.ProcessEnv): AgentBudgetStore {
  const raw = env["AGENT_BUDGET_STORE"]?.trim().toLowerCase();
  if (!raw || raw === "memory") return memoryStore;
  if (raw === "postgres") {
    logger.info("agent budget store: postgres (cluster-wide)");
    return new PostgresBudgetStore();
  }
  throw new Error(
    `Unknown AGENT_BUDGET_STORE "${raw}" (expected "memory" or "postgres")`,
  );
}

export function getBudgetStore(): AgentBudgetStore {
  return activeStore ?? (activeStore = selectStoreFromEnv(process.env));
}

export function setBudgetStore(store: AgentBudgetStore): void {
  activeStore = store;
}

// ---------------------------------------------------------------------------
// Public async API (delegates to the active store).
// ---------------------------------------------------------------------------

export async function chargeBudget(
  tenantId: string,
  tokens: number,
): Promise<void> {
  await getBudgetStore().charge(tenantId, tokens);
}

export async function budgetExceeded(tenantId: string): Promise<boolean> {
  return getBudgetStore().exceeded(tenantId);
}

export async function tokensUsedToday(tenantId: string): Promise<number> {
  return getBudgetStore().tokensUsedToday(tenantId);
}

// ---------------------------------------------------------------------------
// Test-only knobs. These operate on the MEMORY store (the only store tests and
// the eval gate exercise). tenantId defaults to "default" (the seed tenant most
// tests use); reset with no argument clears EVERY tenant's budget.
// ---------------------------------------------------------------------------

export function __resetSupervisorBudgetForTest(tenantId?: string): void {
  memoryStore.reset(tenantId);
}
export function __getSupervisorBudgetForTest(
  tenantId = "default",
): Readonly<BudgetState> {
  return memoryStore.snapshot(tenantId);
}
/** Test-only: jam a tenant's budget so its next review takes the skip path. */
export function __forceBudgetExhaustForTest(tenantId = "default"): void {
  memoryStore.forceExhaust(tenantId);
}
