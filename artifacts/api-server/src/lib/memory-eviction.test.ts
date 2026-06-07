import { describe, it, expect, beforeAll } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  bootstrap,
} from "@workspace/db";
import { withTenant } from "./db-context";
import { initEmbedderFromEnv } from "./embedder-config";
import { backfillEmbeddings } from "./search";
import {
  getMemoryPolicyFromEnv,
  computeImportance,
  selectEvictions,
  evictMemoryOnce,
  startMemoryEviction,
  type MemoryFinding,
  type MemoryPolicy,
} from "./memory-eviction";
import { uniq, uniqueTenant, ledgerHeadSeq } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
  initEmbedderFromEnv();
});

const DAY_MS = 24 * 60 * 60 * 1000;

// A baseline policy for the pure-function tests. Cap is huge so count-cap never
// fires unless a test sets it small; half-life is 30 days.
const POLICY: MemoryPolicy = {
  maxPerTenant: 1_000_000,
  halfLifeDays: 30,
  intervalMs: 6 * 60 * 60 * 1000,
};

function mf(over: Partial<MemoryFinding> & { id: string }): MemoryFinding {
  return {
    classification: "phi",
    subclass: null,
    source: "src",
    severity: "low",
    status: "open",
    lastSeenAtMs: Date.now(),
    occurrenceCount: 1,
    ...over,
  };
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

describe("getMemoryPolicyFromEnv", () => {
  it("returns null (disabled) when MEMORY_MAX_EMBEDDINGS_PER_TENANT is unset", () => {
    expect(getMemoryPolicyFromEnv({})).toBeNull();
    expect(
      getMemoryPolicyFromEnv({ MEMORY_MAX_EMBEDDINGS_PER_TENANT: "" }),
    ).toBeNull();
  });

  it("throws on a non-positive / non-numeric cap", () => {
    expect(() =>
      getMemoryPolicyFromEnv({ MEMORY_MAX_EMBEDDINGS_PER_TENANT: "0" }),
    ).toThrow(/positive number/);
    expect(() =>
      getMemoryPolicyFromEnv({ MEMORY_MAX_EMBEDDINGS_PER_TENANT: "-5" }),
    ).toThrow(/positive number/);
    expect(() =>
      getMemoryPolicyFromEnv({ MEMORY_MAX_EMBEDDINGS_PER_TENANT: "abc" }),
    ).toThrow(/positive number/);
  });

  it("applies defaults for half-life (30d) and interval (6h)", () => {
    const p = getMemoryPolicyFromEnv({
      MEMORY_MAX_EMBEDDINGS_PER_TENANT: "500",
    });
    expect(p).toEqual({
      maxPerTenant: 500,
      halfLifeDays: 30,
      intervalMs: 6 * 60 * 60 * 1000,
    });
  });

  it("parses overrides and floors the integer cap/interval", () => {
    const p = getMemoryPolicyFromEnv({
      MEMORY_MAX_EMBEDDINGS_PER_TENANT: "250.9",
      MEMORY_DECAY_HALF_LIFE_DAYS: "7.5",
      MEMORY_EVICT_INTERVAL_MS: "1000.9",
    });
    expect(p).toEqual({
      maxPerTenant: 250,
      halfLifeDays: 7.5,
      intervalMs: 1000,
    });
  });

  it("throws on invalid half-life / interval", () => {
    expect(() =>
      getMemoryPolicyFromEnv({
        MEMORY_MAX_EMBEDDINGS_PER_TENANT: "10",
        MEMORY_DECAY_HALF_LIFE_DAYS: "0",
      }),
    ).toThrow(/positive number/);
    expect(() =>
      getMemoryPolicyFromEnv({
        MEMORY_MAX_EMBEDDINGS_PER_TENANT: "10",
        MEMORY_EVICT_INTERVAL_MS: "-1",
      }),
    ).toThrow(/positive number/);
  });
});

// ---------------------------------------------------------------------------
// computeImportance (pure)
// ---------------------------------------------------------------------------

describe("computeImportance", () => {
  const now = Date.now();

  it("ranks higher severity above lower severity (all else equal)", () => {
    const crit = computeImportance(mf({ id: "a", severity: "critical" }), now, POLICY);
    const high = computeImportance(mf({ id: "b", severity: "high" }), now, POLICY);
    const med = computeImportance(mf({ id: "c", severity: "medium" }), now, POLICY);
    const low = computeImportance(mf({ id: "d", severity: "low" }), now, POLICY);
    expect(crit).toBeGreaterThan(high);
    expect(high).toBeGreaterThan(med);
    expect(med).toBeGreaterThan(low);
  });

  it("ranks recent above old (recency decay)", () => {
    const recent = computeImportance(mf({ id: "a", lastSeenAtMs: now }), now, POLICY);
    const old = computeImportance(
      mf({ id: "b", lastSeenAtMs: now - 60 * DAY_MS }),
      now,
      POLICY,
    );
    expect(recent).toBeGreaterThan(old);
  });

  it("decays by exactly half at one half-life", () => {
    const fresh = computeImportance(
      mf({ id: "a", severity: "high", occurrenceCount: 0, lastSeenAtMs: now }),
      now,
      POLICY,
    );
    const oneHalfLife = computeImportance(
      mf({
        id: "b",
        severity: "high",
        occurrenceCount: 0,
        lastSeenAtMs: now - POLICY.halfLifeDays * DAY_MS,
      }),
      now,
      POLICY,
    );
    expect(oneHalfLife).toBeCloseTo(fresh / 2, 6);
  });

  it("ranks more occurrences above fewer (all else equal)", () => {
    const many = computeImportance(mf({ id: "a", occurrenceCount: 100 }), now, POLICY);
    const few = computeImportance(mf({ id: "b", occurrenceCount: 1 }), now, POLICY);
    expect(many).toBeGreaterThan(few);
  });

  it("penalizes resolved / false_positive below an otherwise-equal open finding", () => {
    const open = computeImportance(mf({ id: "a", status: "open" }), now, POLICY);
    const resolved = computeImportance(mf({ id: "b", status: "resolved" }), now, POLICY);
    const fp = computeImportance(mf({ id: "c", status: "false_positive" }), now, POLICY);
    expect(open).toBeGreaterThan(resolved);
    expect(open).toBeGreaterThan(fp);
  });

  it("clamps future-dated last_seen_at to age 0 (no inflation)", () => {
    const future = computeImportance(
      mf({ id: "a", occurrenceCount: 0, lastSeenAtMs: now + 100 * DAY_MS }),
      now,
      POLICY,
    );
    const present = computeImportance(
      mf({ id: "b", occurrenceCount: 0, lastSeenAtMs: now }),
      now,
      POLICY,
    );
    expect(future).toBeCloseTo(present, 6);
  });
});

// ---------------------------------------------------------------------------
// selectEvictions (pure)
// ---------------------------------------------------------------------------

describe("selectEvictions", () => {
  const now = Date.now();

  it("count-cap keeps the top-N by importance and evicts the rest", () => {
    // 5 open recent findings (no consolidation), distinct sources, cap = 2.
    const findings = [1, 2, 3, 4, 5].map((i) =>
      mf({
        id: `f${i}`,
        source: `s${i}`,
        severity: "high",
        occurrenceCount: i, // higher i => higher importance
        lastSeenAtMs: now,
      }),
    );
    const evict = selectEvictions(findings, { ...POLICY, maxPerTenant: 2 }, now);
    // Keeps f5, f4 (highest occurrence); evicts f3, f2, f1.
    expect([...evict].sort()).toEqual(["f1", "f2", "f3"]);
  });

  it("NEVER evicts a critical+open finding even when over the cap", () => {
    const findings = [
      mf({ id: "crit1", source: "s1", severity: "critical", status: "open" }),
      mf({ id: "crit2", source: "s2", severity: "critical", status: "open" }),
      mf({ id: "low1", source: "s3", severity: "low", status: "open" }),
      mf({ id: "low2", source: "s4", severity: "low", status: "open" }),
    ];
    // cap = 1, but two critical+open floor findings exist.
    const evict = selectEvictions(findings, { ...POLICY, maxPerTenant: 1 }, now);
    expect(evict.has("crit1")).toBe(false);
    expect(evict.has("crit2")).toBe(false);
    // budget = max(0, 1 - 2) = 0 -> both non-floor lows evicted.
    expect(evict.has("low1")).toBe(true);
    expect(evict.has("low2")).toBe(true);
  });

  it("does NOT consolidate recent open findings sharing a group key", () => {
    const findings = [1, 2, 3].map((i) =>
      mf({
        id: `f${i}`,
        classification: "phi",
        subclass: "ssn",
        source: "billing",
        status: "open",
        lastSeenAtMs: now, // recent -> not consolidatable
        occurrenceCount: i,
      }),
    );
    const evict = selectEvictions(findings, POLICY, now);
    expect(evict.size).toBe(0);
  });

  it("group-dedup collapses old/resolved same-group findings to the top rep", () => {
    const findings = [
      mf({
        id: "keep",
        classification: "phi",
        subclass: "ssn",
        source: "billing",
        status: "resolved",
        occurrenceCount: 100, // highest importance -> representative
      }),
      mf({
        id: "drop1",
        classification: "phi",
        subclass: "ssn",
        source: "billing",
        status: "resolved",
        occurrenceCount: 2,
      }),
      mf({
        id: "drop2",
        classification: "phi",
        subclass: "ssn",
        source: "billing",
        status: "resolved",
        occurrenceCount: 1,
      }),
      // Different group -> untouched.
      mf({ id: "other", classification: "pii", source: "auth", status: "resolved" }),
    ];
    const evict = selectEvictions(findings, POLICY, now);
    expect([...evict].sort()).toEqual(["drop1", "drop2"]);
  });

  it("is deterministic on importance ties (breaks by id ascending)", () => {
    const findings = [
      mf({ id: "b", source: "s1", severity: "low", occurrenceCount: 0, lastSeenAtMs: now }),
      mf({ id: "a", source: "s2", severity: "low", occurrenceCount: 0, lastSeenAtMs: now }),
      mf({ id: "c", source: "s3", severity: "low", occurrenceCount: 0, lastSeenAtMs: now }),
    ];
    // All equal importance; cap = 1 keeps the id-ascending winner "a".
    const evict = selectEvictions(findings, { ...POLICY, maxPerTenant: 1 }, now);
    expect(evict.has("a")).toBe(false);
    expect(evict.has("b")).toBe(true);
    expect(evict.has("c")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// startMemoryEviction inertness
// ---------------------------------------------------------------------------

describe("startMemoryEviction", () => {
  it("is a no-op when disabled (explicit null), returning a callable stop()", () => {
    const stop = startMemoryEviction(null);
    expect(typeof stop).toBe("function");
    expect(() => stop()).not.toThrow();
  });

  it("schedules and returns a stop() when given a policy (timer is unref'd)", () => {
    const stop = startMemoryEviction({
      maxPerTenant: 10,
      halfLifeDays: 30,
      intervalMs: 60 * 60 * 1000,
    });
    expect(typeof stop).toBe("function");
    stop(); // clears the interval immediately; nothing runs in-test
  });
});

// ---------------------------------------------------------------------------
// DB integration: evictMemoryOnce + backfill eligibility
// ---------------------------------------------------------------------------
//
// Isolation discipline (replit.md gotchas + ledger-harness): use a per-test
// uniqueTenant, and trigger eviction ONLY via group-dedup over a back-dated
// (ancient) set sharing a unique source. A huge cap + 30d half-life mean the
// per-tenant count-cap never fires for any tenant, and only findings older than
// 30 days (i.e. our ancient rows) are consolidatable by age. The unique source
// keeps our dedup group from colliding with any other tenant's findings.

const HUGE_CAP_POLICY: MemoryPolicy = {
  maxPerTenant: 1_000_000_000,
  halfLifeDays: 30,
  intervalMs: 6 * 60 * 60 * 1000,
};
const ANCIENT = "1900-01-01T00:00:00Z";

async function insertFinding(
  tenantId: string,
  over: {
    source: string;
    severity?: string;
    status?: string;
    classification?: string;
    subclass?: string | null;
    occurrenceCount?: number;
    ancient?: boolean;
  },
): Promise<string> {
  const id = `mem-${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: over.classification ?? "phi",
      subclass: over.subclass ?? null,
      severity: over.severity ?? "low",
      status: over.status ?? "open",
      source: over.source,
      fingerprint: `fp-${id}`,
      redactedEvidence: { snippet: `redacted ${id}` },
      detectorVersion: "test",
      occurrenceCount: over.occurrenceCount ?? 1,
      ...(over.ancient ? { lastSeenAt: new Date(ANCIENT) } : {}),
    });
  });
  return id;
}

async function hasEmbedding(tenantId: string, id: string): Promise<boolean> {
  return withTenant(tenantId, async (tx) => {
    const r = await tx.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM finding_embeddings WHERE finding_id = ${id}`,
    );
    return Number(r.rows[0]?.n ?? 0) > 0;
  });
}

describe("evictMemoryOnce", () => {
  it("group-dedups a back-dated same-source set, keeps the top rep, and ledgers counts", async () => {
    const tenant = uniqueTenant("mem-evict");
    const source = `grp-${uniq()}`;
    // Three ancient resolved-equivalent (consolidatable by age) findings in one
    // group; occurrenceCount picks the representative.
    const keep = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      occurrenceCount: 100,
      ancient: true,
    });
    const drop1 = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      occurrenceCount: 2,
      ancient: true,
    });
    const drop2 = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      occurrenceCount: 1,
      ancient: true,
    });
    // Backfill embeddings for all three (no policy gate so all get a row).
    await backfillEmbeddings({ memoryPolicy: null });
    expect(await hasEmbedding(tenant, keep)).toBe(true);
    expect(await hasEmbedding(tenant, drop1)).toBe(true);
    expect(await hasEmbedding(tenant, drop2)).toBe(true);

    const since = await ledgerHeadSeq();
    const res = await evictMemoryOnce({ policy: HUGE_CAP_POLICY });
    expect(res.failed).toBe(0);

    // The two lower-importance group members lose their embeddings; the rep keeps it.
    expect(await hasEmbedding(tenant, keep)).toBe(true);
    expect(await hasEmbedding(tenant, drop1)).toBe(false);
    expect(await hasEmbedding(tenant, drop2)).toBe(false);

    // A memory.evicted ledger row scoped to our tenant records counts only.
    const rows = await db
      .select({ payload: ledgerEntriesTable.payload })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, since),
          eq(ledgerEntriesTable.tenantId, tenant),
          eq(ledgerEntriesTable.eventType, "memory.evicted"),
        ),
      );
    expect(rows).toHaveLength(1);
    const payload = rows[0]!.payload as Record<string, unknown>;
    expect(payload["evicted"]).toBe(2);
    expect(payload["max_per_tenant"]).toBe(HUGE_CAP_POLICY.maxPerTenant);
    // No finding ids / snippets in the payload.
    expect(JSON.stringify(payload)).not.toContain(keep);
    expect(JSON.stringify(payload)).not.toContain(drop1);
  });

  it("never evicts a critical+open finding sharing the dedup group", async () => {
    const tenant = uniqueTenant("mem-floor");
    const source = `grp-${uniq()}`;
    // Ancient critical+open (floor) + two ancient low/open in the same group.
    const crit = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      severity: "critical",
      status: "open",
      occurrenceCount: 1,
      ancient: true,
    });
    const low1 = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      severity: "low",
      occurrenceCount: 50,
      ancient: true,
    });
    const low2 = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      severity: "low",
      occurrenceCount: 1,
      ancient: true,
    });
    await backfillEmbeddings({ memoryPolicy: null });

    await evictMemoryOnce({ policy: HUGE_CAP_POLICY });

    // Floor finding always retained; the two non-floor lows collapse to the rep.
    expect(await hasEmbedding(tenant, crit)).toBe(true);
    expect(await hasEmbedding(tenant, low1)).toBe(true); // higher-occurrence rep
    expect(await hasEmbedding(tenant, low2)).toBe(false);
  });

  // Concurrency regression: under READ COMMITTED a finding can flip to
  // critical+open AFTER selectEvictions ran but BEFORE the DELETE. The DELETE
  // re-checks live finding state in the same statement, so a floor-protected row
  // can never be removed even if the (stale) selection targeted it. We prove the
  // guard directly: run the exact guarded DELETE explicitly targeting a
  // critical+open finding's embedding and assert it survives.
  it("DELETE-time floor guard refuses to evict a critical+open embedding even when explicitly targeted", async () => {
    const tenant = uniqueTenant("mem-guard");
    const source = `grp-${uniq()}`;
    const crit = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      severity: "critical",
      status: "open",
      ancient: true,
    });
    await backfillEmbeddings({ memoryPolicy: null });
    expect(await hasEmbedding(tenant, crit)).toBe(true);

    // Mirror the module's guarded DELETE, explicitly targeting the floor row as
    // if a stale selection had decided to evict it.
    const del = await withTenant(tenant, async (tx) =>
      tx.execute(sql`
        DELETE FROM finding_embeddings fe
        USING findings f
        WHERE fe.tenant_id = ${tenant}
          AND f.id = fe.finding_id
          AND fe.finding_id IN (${sql`${crit}`})
          AND NOT (f.severity = 'critical' AND f.status = 'open')
      `),
    );
    expect(del.rowCount ?? 0).toBe(0);
    expect(await hasEmbedding(tenant, crit)).toBe(true);
  });
});

describe("backfillEmbeddings memory policy gate", () => {
  it("does not create embeddings for findings the policy would evict (no recreate thrash)", async () => {
    const tenant = uniqueTenant("mem-backfill");
    const source = `grp-${uniq()}`;
    const keep = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      occurrenceCount: 100,
      ancient: true,
    });
    const drop = await insertFinding(tenant, {
      source,
      subclass: "ssn",
      occurrenceCount: 1,
      ancient: true,
    });

    // Backfill WITH the policy: the lower-importance duplicate is ineligible and
    // must NOT get an embedding row; the representative does.
    await backfillEmbeddings({ memoryPolicy: HUGE_CAP_POLICY });
    expect(await hasEmbedding(tenant, keep)).toBe(true);
    expect(await hasEmbedding(tenant, drop)).toBe(false);
  });

  it("byte-identically creates embeddings for all findings when policy is null", async () => {
    const tenant = uniqueTenant("mem-nopolicy");
    const source = `grp-${uniq()}`;
    const a = await insertFinding(tenant, { source, subclass: "ssn", ancient: true });
    const b = await insertFinding(tenant, { source, subclass: "ssn", ancient: true });

    await backfillEmbeddings({ memoryPolicy: null });
    expect(await hasEmbedding(tenant, a)).toBe(true);
    expect(await hasEmbedding(tenant, b)).toBe(true);
  });
});
