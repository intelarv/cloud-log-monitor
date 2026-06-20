import { describe, it, expect, beforeAll, afterEach } from "vitest";
import { bootstrap } from "@workspace/db";
import {
  MemoryBudgetStore,
  PostgresBudgetStore,
  getBudgetStore,
  setBudgetStore,
  DAILY_TOKEN_BUDGET,
} from "./agent-budget";
import { uniqueTenant } from "../../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

// getBudgetStore caches a module-global singleton; restore it after the tests
// that override AGENT_BUDGET_STORE so the rest of the suite keeps the default.
afterEach(() => {
  setBudgetStore(new MemoryBudgetStore());
});

describe("MemoryBudgetStore (default, byte-identical to pre-seam breaker)", () => {
  it("charges, reports usage, and trips at the daily cap per tenant", async () => {
    const store = new MemoryBudgetStore();
    const a = "tenant-a";
    const b = "tenant-b";

    expect(await store.tokensUsedToday(a)).toBe(0);
    expect(await store.exceeded(a)).toBe(false);

    await store.charge(a, 100);
    await store.charge(a, 50);
    expect(await store.tokensUsedToday(a)).toBe(150);

    // Per-tenant isolation: charging A does not move B.
    expect(await store.tokensUsedToday(b)).toBe(0);

    await store.charge(a, DAILY_TOKEN_BUDGET);
    expect(await store.exceeded(a)).toBe(true);
    expect(await store.exceeded(b)).toBe(false);
  });
});

describe("getBudgetStore (selection via AGENT_BUDGET_STORE)", () => {
  const saved = process.env["AGENT_BUDGET_STORE"];
  afterEach(() => {
    if (saved === undefined) delete process.env["AGENT_BUDGET_STORE"];
    else process.env["AGENT_BUDGET_STORE"] = saved;
  });

  it("defaults to the memory store when unset", () => {
    delete process.env["AGENT_BUDGET_STORE"];
    setBudgetStore(null as never); // force re-selection
    expect(getBudgetStore().kind).toBe("memory");
  });

  it("selects the postgres store when set to postgres", () => {
    process.env["AGENT_BUDGET_STORE"] = "postgres";
    setBudgetStore(null as never);
    expect(getBudgetStore().kind).toBe("postgres");
  });

  it("throws on an unknown value", () => {
    process.env["AGENT_BUDGET_STORE"] = "redis";
    setBudgetStore(null as never);
    expect(() => getBudgetStore()).toThrow(/Unknown AGENT_BUDGET_STORE/);
  });
});

describe("PostgresBudgetStore (cluster-wide, atomic upsert-increment)", () => {
  it("accumulates concurrent charges into one shared (tenant, day) row", async () => {
    const store = new PostgresBudgetStore();
    const tenant = uniqueTenant("budget");

    expect(await store.tokensUsedToday(tenant)).toBe(0);
    expect(await store.exceeded(tenant)).toBe(false);

    // Concurrent charges must all land (the ON CONFLICT DO UPDATE increment is
    // the cross-process serialization point — no read-modify-write race).
    await Promise.all(
      Array.from({ length: 10 }, () => store.charge(tenant, 25)),
    );
    expect(await store.tokensUsedToday(tenant)).toBe(250);

    await store.charge(tenant, DAILY_TOKEN_BUDGET);
    expect(await store.exceeded(tenant)).toBe(true);
  });

  it("isolates tenants (no cross-tenant budget bleed)", async () => {
    const store = new PostgresBudgetStore();
    const a = uniqueTenant("budget");
    const b = uniqueTenant("budget");
    await store.charge(a, 500);
    expect(await store.tokensUsedToday(a)).toBe(500);
    expect(await store.tokensUsedToday(b)).toBe(0);
  });
});
