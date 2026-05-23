import { describe, it, expect, beforeAll } from "vitest";
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { db, findingsTable, ledgerEntriesTable, bootstrap } from "@workspace/db";
import { ingestRecord, startIngestPipeline } from "./ingest";
import { redactInline, scanForPhi } from "./redact";
import { InMemoryLogBus } from "./log-bus";
import type { LogRecord } from "./log-source";

// Tests in this file hit the real dev DB. They scope every read to rows
// they themselves create (unique source ids / fingerprints) so the
// shared dev ledger pollution flagged in replit.md gotchas doesn't bleed
// in. Bootstrap is idempotent — safe to call from a test setup hook.
beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";
const uniq = () => Math.random().toString(36).slice(2, 10);

function makeRecord(over: Partial<LogRecord> & { payload: string }): LogRecord {
  return {
    tenantId: TENANT,
    sourceType: "fixture",
    sourceName: `test-${uniq()}`,
    sourceRecordId: `rec-${uniq()}`,
    observedAt: new Date(),
    ingestedAt: new Date(),
    ...over,
  };
}

describe("redactInline", () => {
  it("returns text unchanged when no hits", () => {
    const out = redactInline("hello world", []);
    expect(out.snippet).toBe("hello world");
    expect(out.redactions).toEqual([]);
  });

  it("replaces a single hit at its offsets", () => {
    const text = "applicant_ssn=123-45-6789 ok";
    const hits = scanForPhi(text);
    const out = redactInline(text, hits);
    expect(out.snippet).toBe("applicant_ssn=[REDACTED:ssn] ok");
    expect(out.redactions).toEqual(["ssn"]);
    expect(scanForPhi(out.snippet)).toEqual([]);
  });

  it("redacts multiple disjoint hits in order", () => {
    const text = "to=a@b.co key=AKIAIOSFODNN7EXAMPLE end";
    const hits = scanForPhi(text);
    const out = redactInline(text, hits);
    expect(out.snippet).toBe("to=[REDACTED:email] key=[REDACTED:aws_akid] end");
    expect(out.redactions).toEqual(["email", "aws_akid"]);
    expect(scanForPhi(out.snippet)).toEqual([]);
  });

  it("on overlap, longer match wins and shorter is skipped", () => {
    // Construct synthetic overlapping hits — the redactor must not double-write.
    const text = "AAAAAAAA";
    const out = redactInline(text, [
      { classification: "phi", detector: "long", start: 0, end: 8, match: "AAAAAAAA" },
      { classification: "phi", detector: "short", start: 2, end: 4, match: "AA" },
    ]);
    expect(out.snippet).toBe("[REDACTED:long]");
    expect(out.redactions).toEqual(["long"]);
  });
});

describe("ingestRecord", () => {
  it("clean record produces no finding and no ledger entry", async () => {
    const rec = makeRecord({ payload: "ts=2026 level=info msg=ok order_id=99" });
    const before = await ledgerHeadSeq();
    const r = await ingestRecord(rec);
    expect(r).toEqual({
      hits: 0,
      findingsCreated: 0,
      findingsUpdated: 0,
      redactionRegressions: 0,
    });
    const after = await ledgerHeadSeq();
    expect(after).toBe(before);
  });

  it("PHI record creates a finding with raw evidence and clean redacted snippet", async () => {
    const rec = makeRecord({
      payload: "applicant_ssn=111-22-3333 status=retry",
    });
    const before = await ledgerHeadSeq();
    const r = await ingestRecord(rec);
    expect(r.hits).toBe(1);
    expect(r.findingsCreated).toBe(1);
    expect(r.findingsUpdated).toBe(0);
    expect(r.redactionRegressions).toBe(0);

    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(
            findingsTable.source,
            `${rec.sourceType}:${rec.sourceName}:${rec.sourceRecordId}`,
          ),
        ),
      );
    expect(rows).toHaveLength(1);
    const f = rows[0]!;
    expect(f.classification).toBe("phi");
    expect(f.severity).toBe("high");
    expect(f.subclass).toBe("ssn");
    expect(f.detectorVersion).toBe("stage1@m3");
    expect(f.occurrenceCount).toBe(1);

    const re = f.redactedEvidence as { snippet: string; redactions: string[] };
    expect(re.snippet).toContain("[REDACTED:ssn]");
    expect(re.snippet).not.toMatch(/111-22-3333/);
    expect(scanForPhi(re.snippet)).toEqual([]);

    const raw = f.rawEvidence as {
      first: { payload: string };
      latest: { payload: string };
    };
    expect(raw.first.payload).toBe(rec.payload);
    expect(raw.latest.payload).toBe(rec.payload);

    // One `finding.created` ledger entry referencing this finding.
    const ledgered = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.subjectId, f.id),
          eq(ledgerEntriesTable.eventType, "finding.created"),
        ),
      );
    expect(ledgered).toHaveLength(1);
  });

  it("duplicate fingerprint increments occurrence_count instead of inserting", async () => {
    const name = `bill-${uniq()}`;
    const rec1 = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-a",
      payload: "applicant_ssn=555-66-7777 status=retry",
    });
    const rec2 = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-b",
      payload: "applicant_ssn=888-99-1234 status=retry",
    });

    const r1 = await ingestRecord(rec1);
    expect(r1.findingsCreated).toBe(1);

    const seqAfterCreate = await ledgerHeadSeq();
    const r2 = await ingestRecord(rec2);
    expect(r2.findingsCreated).toBe(0);
    expect(r2.findingsUpdated).toBe(1);

    // Exactly one finding row for this (tenant, fingerprint), occurrence=2.
    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(
            findingsTable.fingerprint,
            `phi:ssn:fixture:${name}:v1`,
          ),
        ),
      );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.occurrenceCount).toBe(2);

    // raw_evidence preserves FIRST occurrence AND tracks LATEST — analyst
    // looking at a spiking finding can see both the original leak that
    // anchored the finding and what's arriving now.
    const raw = rows[0]!.rawEvidence as {
      first: { source_record_id: string };
      latest: { source_record_id: string };
    };
    expect(raw.first.source_record_id).toBe("evt-a");
    expect(raw.latest.source_record_id).toBe("evt-b");

    // No new `finding.created` ledger entry on the dedupe path — only
    // first observation gets one.
    const newLedger = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, seqAfterCreate),
          eq(ledgerEntriesTable.subjectId, rows[0]!.id),
          eq(ledgerEntriesTable.eventType, "finding.created"),
        ),
      );
    expect(newLedger).toHaveLength(0);
  });

  it("multi-class record produces one finding per classification", async () => {
    const rec = makeRecord({
      sourceName: `mixed-${uniq()}`,
      payload:
        "user=carol@example.com key=AKIAIOSFODNN7EXAMPLE id=000-00-0000",
    });
    const r = await ingestRecord(rec);
    // SSN regex excludes 000 area; only email (pii) + AWS key (secrets) hit.
    expect(r.hits).toBe(2);
    expect(r.findingsCreated).toBe(2);

    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(
            findingsTable.source,
            `${rec.sourceType}:${rec.sourceName}:${rec.sourceRecordId}`,
          ),
        ),
      );
    const classes = rows.map((f) => f.classification).sort();
    expect(classes).toEqual(["pii", "secrets"]);

    const secret = rows.find((f) => f.classification === "secrets")!;
    expect(secret.severity).toBe("critical");
    expect(secret.subclass).toBe("aws_akid");

    const pii = rows.find((f) => f.classification === "pii")!;
    expect(pii.severity).toBe("medium");
    expect(pii.subclass).toBe("email");

    // Every redacted snippet must re-scan clean (defense-in-depth).
    for (const f of rows) {
      const re = f.redactedEvidence as { snippet: string };
      expect(scanForPhi(re.snippet)).toEqual([]);
    }
  });

  it("emits ingest.redaction_regression (critical) when the redactor misses a hit", async () => {
    const rec = makeRecord({
      sourceName: `regress-${uniq()}`,
      payload: "applicant_ssn=222-33-4444 ok",
    });
    const before = await ledgerHeadSeq();

    // Inject a faulty redactor that returns the original text unchanged.
    // The rescan will still find the SSN, which is exactly the regression
    // path under test.
    const r = await ingestRecord(rec, {
      redact: (text) => ({ snippet: text, redactions: [] }),
    });
    expect(r.redactionRegressions).toBe(1);
    expect(r.findingsCreated).toBe(1);

    // The finding still gets created — but with the SAFE fallback snippet,
    // not the leaky one. No PHI reaches the searchable tier.
    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(
            findingsTable.source,
            `${rec.sourceType}:${rec.sourceName}:${rec.sourceRecordId}`,
          ),
        ),
      );
    expect(rows).toHaveLength(1);
    const re = rows[0]!.redactedEvidence as { snippet: string };
    expect(re.snippet).toContain("full opacity applied");
    expect(scanForPhi(re.snippet)).toEqual([]);

    // Ledger received an `ingest.redaction_regression` AND the
    // `finding.created` for the leak itself — two events.
    const ledgered = await db
      .select()
      .from(ledgerEntriesTable)
      .where(gt(ledgerEntriesTable.seq, before));
    const types = ledgered.map((e) => e.eventType).sort();
    expect(types).toContain("ingest.redaction_regression");
    expect(types).toContain("finding.created");
  });

  it("rejects oversized/malformed provenance and ledgers ingest.malformed_record", async () => {
    const before = await ledgerHeadSeq();
    // Oversized sourceRecordId (>256 chars).
    const rec = makeRecord({
      sourceRecordId: "a".repeat(300),
      payload: "applicant_ssn=111-22-3333",
    });
    const r = await ingestRecord(rec);
    expect(r).toEqual({
      hits: 0,
      findingsCreated: 0,
      findingsUpdated: 0,
      redactionRegressions: 0,
    });
    // No finding for this source — the record was dropped before scan.
    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(
            findingsTable.source,
            `${rec.sourceType}:${rec.sourceName}:${rec.sourceRecordId}`,
          ),
        ),
      );
    expect(rows).toHaveLength(0);
    // But the rejection IS in the ledger so a misbehaving source is auditable.
    const ledgered = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.eventType, "ingest.malformed_record"),
        ),
      );
    expect(ledgered.length).toBeGreaterThanOrEqual(1);
    // Payload carries length-only, never the raw oversized value.
    const last = ledgered[ledgered.length - 1]!.payload as {
      reason: string;
      source_record_id_len: number;
    };
    expect(last.reason).toBe("sourceRecordId_invalid");
    expect(last.source_record_id_len).toBe(300);
  });
});

describe("InMemoryLogBus integration with ingest", () => {
  it("concurrent publishes of the same fingerprint coalesce to a single finding (advisory-lock-serialized)", async () => {
    // Race the dedupe path: fire N concurrent ingestRecord calls with the
    // same (sourceName, payload) → same fingerprint. Without the advisory
    // lock these would produce N findings + N `finding.created` ledger
    // entries. With it: 1 finding, occurrenceCount=N, 1 `finding.created`.
    const name = `race-${uniq()}`;
    const before = await ledgerHeadSeq();
    const mk = (rid: string): LogRecord =>
      makeRecord({
        sourceName: name,
        sourceRecordId: rid,
        payload: "applicant_ssn=444-55-6677",
      });
    const N = 5;
    await Promise.all(
      Array.from({ length: N }, (_, i) => ingestRecord(mk(`evt-${i}`))),
    );
    const rows = await db
      .select()
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(rows).toHaveLength(1);
    expect(rows[0]!.occurrenceCount).toBe(N);
    const created = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.subjectId, rows[0]!.id),
          eq(ledgerEntriesTable.eventType, "finding.created"),
        ),
      );
    expect(created).toHaveLength(1);
  });

  it("startIngestPipeline rethrows on ingest failure so PublishResult.errors[] captures it", async () => {
    // Regression for the architect-flagged gap: previously the pipeline
    // handler swallowed errors, so `/api/admin/ingest/replay` could report
    // `errors: 0` even when ingest actually failed. Forcing function: a
    // record with `observedAt` cast to a non-Date passes validateProvenance
    // (which doesn't check Date type) but throws inside the upsert block
    // when `.toISOString()` is called — exercising the real rethrow path.
    const bus = new InMemoryLogBus();
    const unsub = startIngestPipeline(bus);
    try {
      const bad: LogRecord = {
        tenantId: TENANT,
        sourceType: "fixture",
        sourceName: `fail-${uniq()}`,
        sourceRecordId: `rec-${uniq()}`,
        observedAt: "not-a-date" as unknown as Date,
        ingestedAt: new Date(),
        payload: "applicant_ssn=222-33-4444",
      };
      const out = await bus.publish("raw.logs", bad);
      // A throwing handler counts as 0 delivered + 1 errors per
      // log-bus.ts (delivered only increments on success).
      expect(out.delivered).toBe(0);
      expect(out.errors).toHaveLength(1);
      expect(out.errors[0]!.err).toBeInstanceOf(TypeError);
    } finally {
      unsub();
    }
  });

  it("malformed record with overlong-but-regex-valid tenantId ledgers tenantId=null (no scope poisoning)", async () => {
    // Regression for architect follow-up: the malformed-ledger tenant
    // fallback must require *full* validity (incl. length cap), else an
    // attacker-controlled overlong tenant id would land in
    // ledger_entries.tenant_id and pollute scoping/observability.
    const before = await ledgerHeadSeq();
    // 100 chars of [A-Za-z0-9_-]: regex-valid but > MAX_TENANT_ID_LEN (64).
    const overlong = "a".repeat(100);
    const bad = makeRecord({
      tenantId: overlong,
      sourceName: `bad-${uniq()}`,
      payload: "applicant_ssn=111-22-3333",
    });
    await ingestRecord(bad);
    const rows = await db
      .select({
        eventType: ledgerEntriesTable.eventType,
        tenantId: ledgerEntriesTable.tenantId,
      })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, before),
          eq(ledgerEntriesTable.eventType, "ingest.malformed_record"),
          isNull(ledgerEntriesTable.tenantId),
        ),
      );
    expect(rows.length).toBeGreaterThanOrEqual(1);
  });
});

async function ledgerHeadSeq(): Promise<number> {
  const res = await db.execute(
    sql`SELECT COALESCE(MAX(seq), 0)::int AS head FROM ledger_entries`,
  );
  return Number((res.rows[0] as { head?: number }).head ?? 0);
}
