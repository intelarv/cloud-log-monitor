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
// NOTE on multi-process: this is per-process in-memory state, exactly as before.
// The in-process engine has a single process; a Temporal deployment with N
// worker processes would have N independent budget maps (each worker enforces
// its own cap). That is the same per-process limitation the queue always had;
// a cluster-wide budget would need a shared store and is operator-deferred.

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

const budgets = new Map<string, BudgetState>();

function utcDayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Get the tenant's budget state, creating it and rolling it over to today on
 *  the first touch of a new UTC day. */
export function tenantBudget(tenantId: string): BudgetState {
  const today = utcDayKey(new Date());
  let b = budgets.get(tenantId);
  if (!b) {
    b = { dayKey: today, tokensUsed: 0 };
    budgets.set(tenantId, b);
  } else if (b.dayKey !== today) {
    b.dayKey = today;
    b.tokensUsed = 0;
  }
  return b;
}

export function chargeBudget(tenantId: string, tokens: number): void {
  tenantBudget(tenantId).tokensUsed += tokens;
}

export function budgetExceeded(tenantId: string): boolean {
  return tenantBudget(tenantId).tokensUsed >= DAILY_TOKEN_BUDGET;
}

export function tokensUsedToday(tenantId: string): number {
  return tenantBudget(tenantId).tokensUsed;
}

// Test-only knobs. tenantId defaults to "default" (the seed tenant most tests
// use); reset with no argument clears EVERY tenant's budget.
export function __resetSupervisorBudgetForTest(tenantId?: string): void {
  if (tenantId === undefined) {
    budgets.clear();
    return;
  }
  budgets.set(tenantId, { dayKey: utcDayKey(new Date()), tokensUsed: 0 });
}
export function __getSupervisorBudgetForTest(
  tenantId = "default",
): Readonly<BudgetState> {
  return { ...tenantBudget(tenantId) };
}
/** Test-only: jam a tenant's budget so its next review takes the skip path. */
export function __forceBudgetExhaustForTest(tenantId = "default"): void {
  budgets.set(tenantId, {
    dayKey: utcDayKey(new Date()),
    tokensUsed: DAILY_TOKEN_BUDGET + 1,
  });
}
