import { describe, it, expect, beforeAll } from "vitest";
import { and, eq, gt, isNull, isNotNull, sql } from "drizzle-orm";
import { db, findingsTable, ledgerEntriesTable, bootstrap } from "@workspace/db";
import { ingestRecord } from "./ingest";
import type { LogRecord } from "./log-source";
import type { RawEvidenceStore } from "./raw-evidence-store";
import {
  loadRawEvidenceTieringConfigFromEnv,
  tierRawEvidenceOnce,
  __test__,
} from "./raw-evidence-tiering";
import { uniq, uniqueTenant, ledgerHeadSeq } from "../test-support/ledger-harness";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

// Determinism on the shared dev DB (see replit.md gotchas): rather than rely on
// a real cutoff against `now`, every eligible test finding has its last_seen_at
// stamped to the distant past (1900) and the job runs with a very large age
// window. The cutoff therefore lands in the ~1960s, so ONLY findings this suite
// deliberately back-dates can ever qualify — the seed canary, prior-run rows,
// and every other suite's findings (all far newer) are never touched. Each test
// also uses its own `uniqueTenant`, and assertions read back per-tenant DB +
// ledger state scoped to the rows the test created.
const HUGE_AGE_MS = 60 * 365 * 24 * 60 * 60 * 1000; // ~60 years
const ANCIENT = "1900-01-01T00:00:00Z";

function makeRecord(
  tenantId: string,
  over: Partial<LogRecord> & { payload: string },
): LogRecord {
  return {
    tenantId,
    sourceType: "fixture",
    sourceName: `tier-${uniq()}`,
    sourceRecordId: `rec-${uniq()}`,
    observedAt: new Date(),
    ingestedAt: new Date(),
    ...over,
  };
}

/** Ingest a PHI record (dev has no external store → inline raw_evidence is
 *  written) and back-date its last_seen_at so the tiering cutoff includes it. */
async function seedAgedInlineFinding(
  tenantId: string,
  payload: string,
  aged = true,
): Promise<string> {
  const rec = makeRecord(tenantId, { payload });
  const r = await ingestRecord(rec);
  expect(r.findingsCreated).toBe(1);
  const source = `${rec.sourceType}:${rec.sourceName}:${rec.sourceRecordId}`;
  const rows = await db
    .select({ id: findingsTable.id, raw: findingsTable.rawEvidence })
    .from(findingsTable)
    .where(
      and(eq(findingsTable.tenantId, tenantId), eq(findingsTable.source, source)),
    );
  expect(rows).toHaveLength(1);
  expect(rows[0]!.raw).not.toBeNull(); // inline raw present (no external store in dev)
  const id = rows[0]!.id;
  if (aged) {
    await db.execute(sql`
      UPDATE findings SET last_seen_at = ${ANCIENT}
      WHERE id = ${id} AND tenant_id = ${tenantId}
    `);
  }
  return id;
}

/** Fake external WORM store: each put returns a distinct deterministic URI and
 *  remembers the stored bytes so get-after-put round-trips. */
function makeFakeStore(opts: { failGet?: boolean } = {}): {
  store: RawEvidenceStore;
  puts: Array<{ findingId: string; tenantId: string; evidence: unknown }>;
} {
  const puts: Array<{ findingId: string; tenantId: string; evidence: unknown }> =
    [];
  const objects = new Map<string, unknown>();
  let n = 0;
  const store: RawEvidenceStore = {
    name: "fake-worm",
    external: true,
    async put(args) {
      puts.push(args);
      const uri = `s3://fake/raw/${args.tenantId}/${args.findingId}/obj-${n++}.json`;
      objects.set(uri, args.evidence);
      return uri;
    },
    async get({ uri }) {
      if (opts.failGet) throw new Error("simulated WORM read outage");
      if (!objects.has(uri)) throw new Error(`missing object ${uri}`);
      return objects.get(uri);
    },
  };
  return { store, puts };
}

describe("loadRawEvidenceTieringConfigFromEnv", () => {
  it("returns null (disabled) when RAW_EVIDENCE_TIER_AGE_DAYS is unset", () => {
    expect(loadRawEvidenceTieringConfigFromEnv({})).toBeNull();
    expect(loadRawEvidenceTieringConfigFromEnv({ RAW_EVIDENCE_TIER_AGE_DAYS: "" })).toBeNull();
  });

  it("throws on a non-positive / non-numeric age", () => {
    expect(() =>
      loadRawEvidenceTieringConfigFromEnv({ RAW_EVIDENCE_TIER_AGE_DAYS: "0" }),
    ).toThrow(/positive number of days/);
    expect(() =>
      loadRawEvidenceTieringConfigFromEnv({ RAW_EVIDENCE_TIER_AGE_DAYS: "-3" }),
    ).toThrow(/positive number of days/);
    expect(() =>
      loadRawEvidenceTieringConfigFromEnv({ RAW_EVIDENCE_TIER_AGE_DAYS: "abc" }),
    ).toThrow(/positive number of days/);
  });

  it("applies defaults for interval (1h) and batch size (100)", () => {
    const cfg = loadRawEvidenceTieringConfigFromEnv({
      RAW_EVIDENCE_TIER_AGE_DAYS: "30",
    });
    expect(cfg).toEqual({
      ageMs: 30 * 24 * 60 * 60 * 1000,
      intervalMs: 60 * 60 * 1000,
      batchSize: 100,
    });
  });

  it("honors explicit interval and batch overrides", () => {
    const cfg = loadRawEvidenceTieringConfigFromEnv({
      RAW_EVIDENCE_TIER_AGE_DAYS: "7",
      RAW_EVIDENCE_TIER_INTERVAL_MS: "300000",
      RAW_EVIDENCE_TIER_BATCH_SIZE: "25",
    });
    expect(cfg).toEqual({
      ageMs: 7 * 24 * 60 * 60 * 1000,
      intervalMs: 300000,
      batchSize: 25,
    });
  });

  it("throws on invalid interval / batch overrides", () => {
    expect(() =>
      loadRawEvidenceTieringConfigFromEnv({
        RAW_EVIDENCE_TIER_AGE_DAYS: "7",
        RAW_EVIDENCE_TIER_BATCH_SIZE: "0",
      }),
    ).toThrow(/RAW_EVIDENCE_TIER_BATCH_SIZE/);
    expect(() =>
      loadRawEvidenceTieringConfigFromEnv({
        RAW_EVIDENCE_TIER_AGE_DAYS: "7",
        RAW_EVIDENCE_TIER_INTERVAL_MS: "-1",
      }),
    ).toThrow(/RAW_EVIDENCE_TIER_INTERVAL_MS/);
  });
});

describe("tierRawEvidenceOnce — inert paths", () => {
  it("is a no-op when no store is configured", async () => {
    const r = await tierRawEvidenceOnce({
      ageMs: HUGE_AGE_MS,
      batchSize: 100,
      store: null,
    });
    expect(r).toEqual({ scanned: 0, tiered: 0, failed: 0, skippedNoStore: true });
  });

  it("is a no-op when the configured store is the inline DB store (external=false)", async () => {
    const dbStore: RawEvidenceStore = {
      name: "database",
      external: false,
      async put() {
        throw new Error("inline store does not put");
      },
      async get() {
        throw new Error("inline store does not get");
      },
    };
    // Seed an aged inline finding; the inline-store run must NOT touch it.
    const tenant = uniqueTenant("tier-inert");
    const id = await seedAgedInlineFinding(tenant, "applicant_ssn=111-22-3333");
    const r = await tierRawEvidenceOnce({
      ageMs: HUGE_AGE_MS,
      batchSize: 100,
      store: dbStore,
    });
    expect(r.skippedNoStore).toBe(true);
    const after = await db
      .select({ raw: findingsTable.rawEvidence })
      .from(findingsTable)
      .where(eq(findingsTable.id, id));
    expect(after[0]!.raw).not.toBeNull(); // inline preserved, untouched
  });
});

describe("tierRawEvidenceOnce — migration", () => {
  it("moves inline raw to the external store, seats {first,latest} ref, nulls inline, and ledgers raw_evidence.tiered", async () => {
    const tenant = uniqueTenant("tier-move");
    const id = await seedAgedInlineFinding(tenant, "applicant_ssn=321-54-9876");
    const { store, puts } = makeFakeStore();

    const before = await ledgerHeadSeq();
    // NOTE: the job scans ALL tenants by design, so global counts/puts can
    // include other suites' deliberately back-dated rows from the same run.
    // Assert tolerantly on aggregates and strictly on this tenant's rows.
    const r = await tierRawEvidenceOnce({ ageMs: HUGE_AGE_MS, batchSize: 100, store });
    expect(r.tiered).toBeGreaterThanOrEqual(1);
    expect(r.failed).toBe(0);

    // first === latest for a single-occurrence finding → one put, reused uri.
    const myPuts = puts.filter((p) => p.tenantId === tenant);
    expect(myPuts).toHaveLength(1);
    expect(myPuts[0]!.findingId).toBe(id);

    const after = await db
      .select({ raw: findingsTable.rawEvidence, ref: findingsTable.rawEvidenceRef })
      .from(findingsTable)
      .where(eq(findingsTable.id, id));
    expect(after[0]!.raw).toBeNull(); // hot tier cleared
    const ref = after[0]!.ref as { first: string; latest: string };
    expect(ref.first).toMatch(/^s3:\/\/fake\/raw\//);
    expect(ref.first).toBe(ref.latest);

    // Ledger entry: scoped, no PHI / no URIs in payload.
    const led = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.subjectId, id),
          eq(ledgerEntriesTable.eventType, "raw_evidence.tiered"),
        ),
      );
    expect(led).toHaveLength(1);
    const payload = led[0]!.payload as Record<string, unknown>;
    expect(payload).toEqual({ finding_id: id, provider: "fake-worm" });
    expect(JSON.stringify(payload)).not.toContain("s3://");
  });

  it("respects the age threshold — a recent finding is left inline", async () => {
    const tenant = uniqueTenant("tier-age");
    const oldId = await seedAgedInlineFinding(tenant, "applicant_ssn=111-11-1111");
    const freshId = await seedAgedInlineFinding(
      tenant,
      "applicant_ssn=222-22-2222",
      /* aged */ false,
    );
    const { store } = makeFakeStore();

    await tierRawEvidenceOnce({ ageMs: HUGE_AGE_MS, batchSize: 100, store });

    const oldRow = await db
      .select({ raw: findingsTable.rawEvidence })
      .from(findingsTable)
      .where(eq(findingsTable.id, oldId));
    const freshRow = await db
      .select({ raw: findingsTable.rawEvidence })
      .from(findingsTable)
      .where(eq(findingsTable.id, freshId));
    expect(oldRow[0]!.raw).toBeNull(); // aged → tiered
    expect(freshRow[0]!.raw).not.toBeNull(); // recent → untouched
  });

  it("respects the per-tenant batch size", async () => {
    const tenant = uniqueTenant("tier-batch");
    await seedAgedInlineFinding(tenant, "applicant_ssn=333-33-3331");
    await seedAgedInlineFinding(tenant, "applicant_ssn=333-33-3332");
    await seedAgedInlineFinding(tenant, "applicant_ssn=333-33-3333");
    const { store } = makeFakeStore();

    await tierRawEvidenceOnce({ ageMs: HUGE_AGE_MS, batchSize: 2, store });

    const remainingInline = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, tenant),
          isNotNull(findingsTable.rawEvidence),
        ),
      );
    const tieredRows = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(eq(findingsTable.tenantId, tenant), isNull(findingsTable.rawEvidence)),
      );
    expect(tieredRows).toHaveLength(2); // batch limit honored
    expect(remainingInline).toHaveLength(1); // remainder waits for next cadence
  });
});

describe("tierRawEvidenceOnce — failure handling", () => {
  it("keeps the inline copy and ledgers raw_evidence.tier_failed when get-after-put fails", async () => {
    const tenant = uniqueTenant("tier-fail");
    const id = await seedAgedInlineFinding(tenant, "applicant_ssn=444-44-4444");
    const { store, puts } = makeFakeStore({ failGet: true });

    const before = await ledgerHeadSeq();
    // failGet store fails verify for every candidate → tiers nothing; failed
    // count may include other suites' aged-inline leftovers from the same run.
    const r = await tierRawEvidenceOnce({ ageMs: HUGE_AGE_MS, batchSize: 100, store });
    expect(r.failed).toBeGreaterThanOrEqual(1);
    expect(r.tiered).toBe(0);
    expect(puts.some((p) => p.tenantId === tenant)).toBe(true); // put happened, verify failed

    const after = await db
      .select({ raw: findingsTable.rawEvidence, ref: findingsTable.rawEvidenceRef })
      .from(findingsTable)
      .where(eq(findingsTable.id, id));
    expect(after[0]!.raw).not.toBeNull(); // inline preserved — never destroy sole copy
    expect(after[0]!.ref).toBeNull(); // ref not seated

    const led = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.subjectId, id),
          eq(ledgerEntriesTable.eventType, "raw_evidence.tier_failed"),
        ),
      );
    expect(led).toHaveLength(1);
    const payload = led[0]!.payload as Record<string, unknown>;
    expect(payload.finding_id).toBe(id);
    expect(payload.provider).toBe("fake-worm");
  });
});

describe("tierOneFinding — concurrent-change guard", () => {
  it("returns false (no row nulled) when the inline column was already cleared", async () => {
    const tenant = uniqueTenant("tier-race");
    const id = await seedAgedInlineFinding(tenant, "applicant_ssn=555-55-5555");
    // Simulate a concurrent change clearing the inline column out from under us.
    await db.execute(sql`
      UPDATE findings SET raw_evidence = NULL
      WHERE id = ${id} AND tenant_id = ${tenant}
    `);
    const { store } = makeFakeStore();
    const migrated = await __test__.tierOneFinding({
      store,
      tenantId: tenant,
      findingId: id,
      inline: { first: { payload: "x" }, latest: { payload: "x" } },
    });
    expect(migrated).toBe(false);
  });
});

describe("tierOneFinding — merge with an ingest-seated ref", () => {
  it("preserves a newer ingest ref.latest and migrates inline.first into ref.first", async () => {
    // Models the post-switch steady state: an operator moved this deployment
    // from the inline DB store to an external store, ingest left the legacy
    // row's inline raw untouched but advanced raw_evidence_ref.latest to a NEW
    // (more recent) WORM object on re-hits. Tiering must NOT clobber that newer
    // latest with the stale inline latest; it must only migrate the inline
    // first (the true earliest) into the first slot.
    const tenant = uniqueTenant("tier-merge");
    const id = await seedAgedInlineFinding(tenant, "applicant_ssn=601-23-4567");
    const { store, puts } = makeFakeStore();

    // Simulate ingest's post-switch object + ref.latest pointer.
    const ingestLatestUri = await store.put({
      findingId: id,
      tenantId: tenant,
      evidence: { payload: "post-switch-occurrence" },
    });
    await db.execute(sql`
      UPDATE findings
      SET raw_evidence_ref = ${JSON.stringify({
        first: "s3://fake/raw/ingest-first.json",
        latest: ingestLatestUri,
      })}::jsonb
      WHERE id = ${id} AND tenant_id = ${tenant}
    `);

    const migrated = await __test__.tierOneFinding({
      store,
      tenantId: tenant,
      findingId: id,
      inline: {
        first: { payload: "pre-switch-first" },
        latest: { payload: "pre-switch-latest" },
      },
    });
    expect(migrated).toBe(true);

    const after = await db
      .select({
        raw: findingsTable.rawEvidence,
        ref: findingsTable.rawEvidenceRef,
      })
      .from(findingsTable)
      .where(eq(findingsTable.id, id));
    expect(after[0]!.raw).toBeNull(); // hot tier cleared
    const ref = after[0]!.ref as { first: string; latest: string };
    // ingest's newer latest is preserved (not clobbered by the stale inline).
    expect(ref.latest).toBe(ingestLatestUri);
    // the inline first (true earliest) was migrated into the first slot.
    expect(ref.first).not.toBe(ingestLatestUri);
    expect(ref.first).toMatch(/^s3:\/\/fake\/raw\//);
    // tiering wrote exactly ONE new object — the inline first; it did not
    // re-put the inline latest (the newer ingest latest already supersedes it).
    const tieringPuts = puts.filter(
      (p) =>
        p.findingId === id &&
        JSON.stringify(p.evidence) ===
          JSON.stringify({ payload: "pre-switch-first" }),
    );
    expect(tieringPuts).toHaveLength(1);
    const latestPuts = puts.filter(
      (p) =>
        p.findingId === id &&
        JSON.stringify(p.evidence) ===
          JSON.stringify({ payload: "pre-switch-latest" }),
    );
    expect(latestPuts).toHaveLength(0);
  });
});

describe("normalizeInline", () => {
  it("passes through {first,latest}", () => {
    expect(__test__.normalizeInline({ first: 1, latest: 2 })).toEqual({
      first: 1,
      latest: 2,
    });
  });
  it("treats a legacy flat payload as both first and latest", () => {
    const flat = { payload: "p" };
    expect(__test__.normalizeInline(flat)).toEqual({ first: flat, latest: flat });
  });
});
