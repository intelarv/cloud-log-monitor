import { describe, it, expect, beforeAll } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import {
  db,
  findingsTable,
  ledgerEntriesTable,
  memoryConsolidationSummariesTable,
  bootstrap,
} from "@workspace/db";
import { withTenant } from "./db-context";
import {
  consolidationGroups,
  type MemoryFinding,
  type MemoryPolicy,
} from "./memory-eviction";
import {
  getSummaryPolicyFromEnv,
  memberSignature,
  buildSummaryPrompt,
  summarizeConsolidationsOnce,
  type SummaryPolicy,
} from "./memory-summarizer";
import type {
  LlmAgentRuntime,
  LlmGenerateOpts,
  LlmGenerateResult,
} from "./llm-runtime";
import { uniq, uniqueTenant, ledgerHeadSeq } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const DAY_MS = 24 * 60 * 60 * 1000;

const MEMORY_POLICY: MemoryPolicy = {
  maxPerTenant: 1_000_000_000,
  halfLifeDays: 30,
  intervalMs: 6 * 60 * 60 * 1000,
};

const SUMMARY_POLICY: SummaryPolicy = {
  maxGroupsPerRun: 20,
  maxMembersSampled: 8,
  modelId: "test-model",
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

// A fake runtime whose output is keyed off a per-test marker present in the
// prompt, so a single sweep over the SHARED dev DB only affects this test's
// tenant in a test-specific way (other tenants' groups get a benign summary).
function fakeRuntime(
  marker: string,
  responder: (opts: LlmGenerateOpts) => string,
): LlmAgentRuntime & { calls: number } {
  const rt = {
    calls: 0,
    async generate(opts: LlmGenerateOpts): Promise<LlmGenerateResult> {
      const mine = opts.userPrompt.includes(marker);
      if (mine) rt.calls++;
      const text = mine ? responder(opts) : "benign cluster summary";
      return { text, approxOutputTokens: text.length, modelId: opts.modelId };
    },
  };
  return rt;
}

// ---------------------------------------------------------------------------
// getSummaryPolicyFromEnv (pure)
// ---------------------------------------------------------------------------

describe("getSummaryPolicyFromEnv", () => {
  it("returns null (disabled) when MEMORY_CONSOLIDATION_SUMMARY is unset/false", () => {
    expect(getSummaryPolicyFromEnv({})).toBeNull();
    expect(
      getSummaryPolicyFromEnv({ MEMORY_CONSOLIDATION_SUMMARY: "" }),
    ).toBeNull();
    expect(
      getSummaryPolicyFromEnv({ MEMORY_CONSOLIDATION_SUMMARY: "false" }),
    ).toBeNull();
    expect(
      getSummaryPolicyFromEnv({ MEMORY_CONSOLIDATION_SUMMARY: "0" }),
    ).toBeNull();
  });

  it("enables with defaults when the flag is truthy", () => {
    const p = getSummaryPolicyFromEnv({ MEMORY_CONSOLIDATION_SUMMARY: "1" });
    expect(p).not.toBeNull();
    expect(p!.maxGroupsPerRun).toBe(20);
    expect(p!.maxMembersSampled).toBe(8);
    expect(p!.modelId).toBeTruthy();
  });

  it("parses and floors overrides", () => {
    const p = getSummaryPolicyFromEnv({
      MEMORY_CONSOLIDATION_SUMMARY: "true",
      MEMORY_SUMMARY_MAX_GROUPS_PER_RUN: "5.9",
      MEMORY_SUMMARY_MAX_MEMBERS_SAMPLED: "3",
      MEMORY_SUMMARY_MODEL: "custom-model",
    });
    expect(p!.maxGroupsPerRun).toBe(5);
    expect(p!.maxMembersSampled).toBe(3);
    expect(p!.modelId).toBe("custom-model");
  });

  it("throws on non-positive / non-numeric overrides", () => {
    expect(() =>
      getSummaryPolicyFromEnv({
        MEMORY_CONSOLIDATION_SUMMARY: "1",
        MEMORY_SUMMARY_MAX_GROUPS_PER_RUN: "0",
      }),
    ).toThrow(/positive number/);
    expect(() =>
      getSummaryPolicyFromEnv({
        MEMORY_CONSOLIDATION_SUMMARY: "1",
        MEMORY_SUMMARY_MAX_MEMBERS_SAMPLED: "-2",
      }),
    ).toThrow(/positive number/);
  });
});

// ---------------------------------------------------------------------------
// memberSignature (pure)
// ---------------------------------------------------------------------------

describe("memberSignature", () => {
  it("is order-independent and changes when membership changes", () => {
    const a = memberSignature(["f1", "f2", "f3"]);
    const b = memberSignature(["f3", "f1", "f2"]);
    expect(a).toBe(b);
    expect(memberSignature(["f1", "f2"])).not.toBe(a);
  });
});

// ---------------------------------------------------------------------------
// consolidationGroups (pure) — single source of the Pass-1 grouping rule
// ---------------------------------------------------------------------------

describe("consolidationGroups", () => {
  it("returns only groups with >=2 consolidatable members, ranked rep-first", () => {
    const now = Date.now();
    const old = now - 90 * DAY_MS; // aged well past one half-life
    const findings = [
      mf({ id: "a1", source: "s", subclass: "ssn", lastSeenAtMs: old, occurrenceCount: 5 }),
      mf({ id: "a2", source: "s", subclass: "ssn", lastSeenAtMs: old, occurrenceCount: 50 }),
      mf({ id: "a3", source: "s", subclass: "ssn", lastSeenAtMs: old, occurrenceCount: 1 }),
      // singleton group — excluded
      mf({ id: "b1", source: "other", subclass: "email", lastSeenAtMs: old }),
    ];
    const groups = consolidationGroups(findings, MEMORY_POLICY, now);
    expect(groups).toHaveLength(1);
    const g = groups[0]!;
    expect(g.members.map((m) => m.id)).toEqual(["a2", "a1", "a3"]);
    expect(g.classification).toBe("phi");
    expect(g.subclass).toBe("ssn");
    expect(g.source).toBe("s");
  });

  it("excludes critical+open floor findings and recent (non-consolidatable) findings", () => {
    const now = Date.now();
    const old = now - 90 * DAY_MS;
    const findings = [
      mf({ id: "c1", source: "s", lastSeenAtMs: old, severity: "critical", status: "open" }),
      mf({ id: "c2", source: "s", lastSeenAtMs: old, severity: "critical", status: "open" }),
      // recent + open => not consolidatable
      mf({ id: "r1", source: "t", lastSeenAtMs: now }),
      mf({ id: "r2", source: "t", lastSeenAtMs: now }),
    ];
    expect(consolidationGroups(findings, MEMORY_POLICY, now)).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// buildSummaryPrompt (pure)
// ---------------------------------------------------------------------------

describe("buildSummaryPrompt", () => {
  it("includes structural metadata and bounded redacted snippets only", () => {
    const now = Date.now();
    const members = [
      mf({ id: "m1", source: "billing", subclass: "ssn", lastSeenAtMs: now, occurrenceCount: 3 }),
      mf({ id: "m2", source: "billing", subclass: "ssn", lastSeenAtMs: now, occurrenceCount: 1 }),
    ];
    const group = {
      key: "k",
      classification: "phi",
      subclass: "ssn",
      source: "billing",
      members,
    };
    const redacted = new Map<string, unknown>([
      ["m1", { snippet: "redacted A" }],
      ["m2", { snippet: "redacted B" }],
    ]);
    const { systemPrompt, userPrompt } = buildSummaryPrompt(
      group,
      redacted,
      SUMMARY_POLICY,
    );
    expect(systemPrompt).toMatch(/never include any/i);
    expect(userPrompt).toContain("classification: phi");
    expect(userPrompt).toContain("source: billing");
    expect(userPrompt).toContain("total_occurrences: 4");
    expect(userPrompt).toContain("redacted A");
  });
});

// ---------------------------------------------------------------------------
// summarizeConsolidationsOnce (integration, injected fake LLM)
// ---------------------------------------------------------------------------

const ANCIENT = "1900-01-01T00:00:00Z";

async function insertConsolidatable(
  tenantId: string,
  source: string,
  occurrenceCount: number,
): Promise<string> {
  const id = `sum-${uniq()}`;
  await withTenant(tenantId, async (tx) => {
    await tx.insert(findingsTable).values({
      id,
      tenantId,
      classification: "phi",
      subclass: "ssn",
      severity: "low",
      status: "resolved",
      source,
      fingerprint: `fp-${id}`,
      redactedEvidence: { snippet: `redacted ${id}` },
      detectorVersion: "test",
      occurrenceCount,
      lastSeenAt: new Date(ANCIENT),
    });
  });
  return id;
}

async function summaryRow(tenantId: string, source: string) {
  return withTenant(tenantId, async (tx) => {
    const rows = await tx
      .select()
      .from(memoryConsolidationSummariesTable)
      .where(eq(memoryConsolidationSummariesTable.source, source));
    return rows[0];
  });
}

describe("summarizeConsolidationsOnce", () => {
  it("writes a summary per group, ledgers counts + model_id only, and is idempotent", async () => {
    const tenant = uniqueTenant("mem-sum");
    const source = `grp-${uniq()}`;
    const keep = await insertConsolidatable(tenant, source, 100);
    await insertConsolidatable(tenant, source, 5);
    await insertConsolidatable(tenant, source, 1);

    const rt = fakeRuntime(source, () => `Cluster summary for ${source}`);
    const since = await ledgerHeadSeq();

    const res = await summarizeConsolidationsOnce({
      memoryPolicy: MEMORY_POLICY,
      summaryPolicy: SUMMARY_POLICY,
      runtime: rt,
    });
    expect(res.summarized).toBeGreaterThanOrEqual(1);
    expect(rt.calls).toBe(1);

    const row = await summaryRow(tenant, source);
    expect(row).toBeTruthy();
    expect(row!.consolidatedCount).toBe(3);
    expect(row!.representativeFindingId).toBe(keep);
    expect(row!.summary).toBe(`Cluster summary for ${source}`);
    expect(row!.modelId).toBe("test-model");

    // Ledger row scoped to our tenant carries counts + model_id only.
    const led = await db
      .select({ payload: ledgerEntriesTable.payload })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, since),
          eq(ledgerEntriesTable.tenantId, tenant),
          eq(ledgerEntriesTable.eventType, "memory.summarized"),
        ),
      );
    expect(led).toHaveLength(1);
    const payload = led[0]!.payload as Record<string, unknown>;
    expect(payload["model_id"]).toBe("test-model");
    expect(JSON.stringify(payload)).not.toContain(keep);
    expect(JSON.stringify(payload)).not.toContain(source);

    // Idempotency: unchanged membership signature => skipped, no new LLM call,
    // and the stored summary is NOT overwritten even though the fake now returns
    // different text.
    const rt2 = fakeRuntime(source, () => `DIFFERENT text for ${source}`);
    const res2 = await summarizeConsolidationsOnce({
      memoryPolicy: MEMORY_POLICY,
      summaryPolicy: SUMMARY_POLICY,
      runtime: rt2,
    });
    expect(rt2.calls).toBe(0);
    expect(res2.skipped).toBeGreaterThanOrEqual(1);
    const row2 = await summaryRow(tenant, source);
    expect(row2!.summary).toBe(`Cluster summary for ${source}`);
  });

  it("hard-fails (no row, ledgers memory.summary_failed) when LLM output trips the PHI scan", async () => {
    const tenant = uniqueTenant("mem-sum-phi");
    const source = `grp-${uniq()}`;
    await insertConsolidatable(tenant, source, 9);
    await insertConsolidatable(tenant, source, 2);

    // Output contains a valid-looking SSN => scanForPhi flags it.
    const rt = fakeRuntime(source, () => `Patient SSN is 123-45-6789 in cluster`);
    const since = await ledgerHeadSeq();

    await summarizeConsolidationsOnce({
      memoryPolicy: MEMORY_POLICY,
      summaryPolicy: SUMMARY_POLICY,
      runtime: rt,
    });

    // No summary row was persisted for this group.
    expect(await summaryRow(tenant, source)).toBeUndefined();

    // A memory.summary_failed ledger row scoped to our tenant records the
    // reason only (never the offending text).
    const led = await db
      .select({ payload: ledgerEntriesTable.payload })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, since),
          eq(ledgerEntriesTable.tenantId, tenant),
          eq(ledgerEntriesTable.eventType, "memory.summary_failed"),
        ),
      );
    expect(led.length).toBeGreaterThanOrEqual(1);
    const payload = led[0]!.payload as Record<string, unknown>;
    expect(payload["error"]).toBe("phi_in_output");
    expect(JSON.stringify(payload)).not.toContain("123-45-6789");
  });
});
