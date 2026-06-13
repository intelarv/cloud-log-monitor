import { describe, it, expect, beforeAll } from "vitest";
import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { db, findingsTable, ledgerEntriesTable, bootstrap } from "@workspace/db";
import {
  ingestRecord,
  startIngestPipeline,
  rawEvidenceStoreDegraded,
  getDeadLetterConfigFromEnv,
} from "./ingest";
import { ingestDeadLetterTable } from "@workspace/db";
import { redactInline, scanForPhi } from "./redact";
import { InMemoryLogBus } from "./log-bus";
import type { LogRecord } from "./log-source";
import type { RawEvidenceStore } from "./raw-evidence-store";

// Tests in this file hit the real dev DB. They scope every read to rows
// they themselves create (unique source ids / fingerprints) so the
// shared dev ledger pollution flagged in replit.md gotchas doesn't bleed
// in. Bootstrap is idempotent — safe to call from a test setup hook.
beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";
import { uniq, ledgerHeadSeq } from "../test-support/ledger-harness";

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

describe("external raw-evidence store (two-phase write)", () => {
  it("routes raw evidence to the external store and records a {first,latest} ref, leaving raw_evidence NULL", async () => {
    // A fake external store captures the put and hands back a deterministic
    // URI so we can assert the ingest two-phase write: tx-A persists the
    // finding with raw_evidence NULL, tx-B seats raw_evidence_ref.
    const puts: Array<{ findingId: string; tenantId: string; evidence: unknown }> =
      [];
    let n = 0;
    const fakeStore: RawEvidenceStore = {
      name: "fake-worm",
      external: true,
      async put(args) {
        puts.push(args);
        return `s3://fake/raw-evidence/${args.tenantId}/${args.findingId}/obj-${n++}.json`;
      },
      async get() {
        throw new Error("not used in this test");
      },
    };

    const name = `worm-${uniq()}`;
    const rec1 = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-a",
      payload: "applicant_ssn=321-54-9876 status=new",
    });
    const r1 = await ingestRecord(rec1, { rawEvidenceStore: fakeStore });
    expect(r1.findingsCreated).toBe(1);
    expect(puts).toHaveLength(1);

    const fp = `phi:ssn:fixture:${name}:v1`;
    const afterFirst = await db
      .select()
      .from(findingsTable)
      .where(
        and(eq(findingsTable.tenantId, TENANT), eq(findingsTable.fingerprint, fp)),
      );
    expect(afterFirst).toHaveLength(1);
    const f1 = afterFirst[0]!;
    // External store active → inline column stays NULL.
    expect(f1.rawEvidence).toBeNull();
    const ref1 = f1.rawEvidenceRef as { first: string; latest: string };
    expect(ref1.first).toMatch(/^s3:\/\/fake\/raw-evidence\/default\//);
    expect(ref1.first).toBe(ref1.latest);

    // Second occurrence: a NEW immutable object; `first` is pinned, `latest` advances.
    const rec2 = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-b",
      payload: "applicant_ssn=321-54-9876 status=retry",
    });
    const r2 = await ingestRecord(rec2, { rawEvidenceStore: fakeStore });
    expect(r2.findingsUpdated).toBe(1);
    expect(puts).toHaveLength(2);

    const afterSecond = await db
      .select()
      .from(findingsTable)
      .where(
        and(eq(findingsTable.tenantId, TENANT), eq(findingsTable.fingerprint, fp)),
      );
    const f2 = afterSecond[0]!;
    expect(f2.rawEvidence).toBeNull();
    const ref2 = f2.rawEvidenceRef as { first: string; latest: string };
    expect(ref2.first).toBe(ref1.first); // first-writer-wins (COALESCE)
    expect(ref2.latest).not.toBe(ref1.latest); // latest advanced
    expect(puts[1]!.tenantId).toBe(TENANT);
    expect(puts[1]!.findingId).toBe(f2.id);
  });

  it("does not block ingest when the external store put fails (finding persists, ref left NULL)", async () => {
    const failingStore: RawEvidenceStore = {
      name: "fake-worm-broken",
      external: true,
      async put() {
        throw new Error("simulated WORM outage");
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormfail-${uniq()}`;
    const rec = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-a",
      payload: "applicant_ssn=765-43-2109 status=new",
    });
    const r = await ingestRecord(rec, { rawEvidenceStore: failingStore });
    // The finding is still committed (raw write is best-effort, post-commit).
    expect(r.findingsCreated).toBe(1);
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
    expect(rows[0]!.rawEvidence).toBeNull();
    expect(rows[0]!.rawEvidenceRef).toBeNull();
  });

  it("emits an operator alert event (no PHI) when the external store put fails", async () => {
    const failingStore: RawEvidenceStore = {
      name: "fake-worm-alerting",
      external: true,
      async put() {
        throw new Error("simulated WORM outage");
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormalert-${uniq()}`;
    const ssn = "765-43-2110";
    const rec = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-a",
      payload: `applicant_ssn=${ssn} status=new`,
    });
    const r = await ingestRecord(rec, {
      rawEvidenceStore: failingStore,
      rawEvidenceWriteRetry: { maxAttempts: 1 },
    });
    expect(r.findingsCreated).toBe(1);

    const findings = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);
    const findingId = findings[0]!.id;

    const events = await db
      .select({
        eventType: ledgerEntriesTable.eventType,
        subjectId: ledgerEntriesTable.subjectId,
        payload: ledgerEntriesTable.payload,
      })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.eventType, "ingest.raw_evidence_store_failed"),
          eq(ledgerEntriesTable.subjectId, findingId),
        ),
      );
    expect(events).toHaveLength(1);
    const ev = events[0]!;
    const payload = ev.payload as Record<string, unknown>;
    expect(payload.provider).toBe("fake-worm-alerting");
    expect(payload.finding_id).toBe(findingId);
    // No PHI / raw payload anywhere in the ledger payload.
    const payloadStr = JSON.stringify(payload);
    expect(payloadStr).not.toContain(ssn);
  });

  it("does NOT emit the store-failure alert when the inline DB store is used", async () => {
    // The inline DB store can't fail this way, so a successful inline ingest
    // must never produce the operator alert event.
    const name = `worminline-${uniq()}`;
    const rec = makeRecord({
      sourceName: name,
      sourceRecordId: "evt-a",
      payload: "applicant_ssn=765-43-2111 status=new",
    });
    const r = await ingestRecord(rec, { rawEvidenceStore: null });
    expect(r.findingsCreated).toBe(1);

    const findings = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);

    const events = await db
      .select({ seq: ledgerEntriesTable.seq })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.eventType, "ingest.raw_evidence_store_failed"),
          eq(ledgerEntriesTable.subjectId, findings[0]!.id),
        ),
      );
    expect(events).toHaveLength(0);
  });

  it("emits a recovery event (no PHI) when the external store put succeeds after a prior failure", async () => {
    // Flaky store: the first put throws (latches degraded), the second
    // succeeds (the recovery edge).
    let calls = 0;
    const provider = `worm-recover-${uniq()}`;
    const flakyStore: RawEvidenceStore = {
      name: provider,
      external: true,
      async put() {
        calls++;
        if (calls === 1) throw new Error("simulated WORM outage");
        return `mem://${provider}/obj-${calls}`;
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormrecover-${uniq()}`;
    const ssn = "765-43-2112";
    const mk = (rid: string): LogRecord =>
      makeRecord({
        sourceName: name,
        sourceRecordId: rid,
        payload: `applicant_ssn=${ssn} status=new`,
      });

    // Disable retry so the single put failure on occurrence 1 latches degraded
    // (with retry the flaky store would recover within the first ingest).
    const noRetry = { rawEvidenceWriteRetry: { maxAttempts: 1 } };
    // Occurrence 1: put throws → degraded latched + failure alert.
    await ingestRecord(mk("evt-a"), { rawEvidenceStore: flakyStore, ...noRetry });
    // Occurrence 2 (same fingerprint): put succeeds → recovery alert + latch cleared.
    await ingestRecord(mk("evt-b"), { rawEvidenceStore: flakyStore, ...noRetry });

    const findings = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);
    const findingId = findings[0]!.id;

    const events = await db
      .select({
        eventType: ledgerEntriesTable.eventType,
        subjectId: ledgerEntriesTable.subjectId,
        payload: ledgerEntriesTable.payload,
      })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(
            ledgerEntriesTable.eventType,
            "ingest.raw_evidence_store_recovered",
          ),
          eq(ledgerEntriesTable.subjectId, findingId),
        ),
      );
    expect(events).toHaveLength(1);
    const payload = events[0]!.payload as Record<string, unknown>;
    expect(payload.provider).toBe(provider);
    expect(payload.finding_id).toBe(findingId);
    // No PHI / raw payload anywhere in the ledger payload.
    expect(JSON.stringify(payload)).not.toContain(ssn);

    // The latch is cleared once recovery is emitted.
    expect(rawEvidenceStoreDegraded.has(`${provider}::${TENANT}`)).toBe(false);
  });

  it("does NOT emit a recovery event on steady-state success (no preceding failure)", async () => {
    const provider = `worm-steady-${uniq()}`;
    const okStore: RawEvidenceStore = {
      name: provider,
      external: true,
      async put() {
        return `mem://${provider}/obj`;
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormsteady-${uniq()}`;
    const r = await ingestRecord(
      makeRecord({
        sourceName: name,
        sourceRecordId: "evt-a",
        payload: "applicant_ssn=765-43-2113 status=new",
      }),
      { rawEvidenceStore: okStore },
    );
    expect(r.findingsCreated).toBe(1);

    const findings = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);

    const events = await db
      .select({ seq: ledgerEntriesTable.seq })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(
            ledgerEntriesTable.eventType,
            "ingest.raw_evidence_store_recovered",
          ),
          eq(ledgerEntriesTable.subjectId, findings[0]!.id),
        ),
      );
    expect(events).toHaveLength(0);
  });

  it("retries a transient store failure and succeeds without alerting", async () => {
    // Store fails the first two puts (transient blip), succeeds on the third.
    // With maxAttempts: 3 the write recovers within one ingest, so NO failure
    // alert and NO degraded latch.
    let calls = 0;
    const provider = `worm-retry-ok-${uniq()}`;
    const flakyStore: RawEvidenceStore = {
      name: provider,
      external: true,
      async put() {
        calls++;
        if (calls < 3) throw new Error("transient 503");
        return `mem://${provider}/obj-${calls}`;
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormretryok-${uniq()}`;
    const r = await ingestRecord(
      makeRecord({
        sourceName: name,
        sourceRecordId: "evt-a",
        payload: "applicant_ssn=765-43-2114 status=new",
      }),
      {
        rawEvidenceStore: flakyStore,
        rawEvidenceWriteRetry: { maxAttempts: 3, backoffMs: 0 },
      },
    );
    expect(r.findingsCreated).toBe(1);
    expect(calls).toBe(3);

    const findings = await db
      .select({ id: findingsTable.id, rawEvidenceRef: findingsTable.rawEvidenceRef })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);
    // The retried write landed: the ref was seated.
    expect(findings[0]!.rawEvidenceRef).not.toBeNull();

    // No failure alert, since the retry succeeded.
    const failed = await db
      .select({ seq: ledgerEntriesTable.seq })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.eventType, "ingest.raw_evidence_store_failed"),
          eq(ledgerEntriesTable.subjectId, findings[0]!.id),
        ),
      );
    expect(failed).toHaveLength(0);
    // And the provider/tenant is not latched degraded.
    expect(rawEvidenceStoreDegraded.has(`${provider}::${TENANT}`)).toBe(false);
  });

  it("exhausts bounded retries then emits the failure alert", async () => {
    // Store always fails. With maxAttempts: 2 the write is tried exactly twice,
    // then declares durable capture degraded (latch + failure alert).
    let calls = 0;
    const provider = `worm-retry-exhaust-${uniq()}`;
    const failingStore: RawEvidenceStore = {
      name: provider,
      external: true,
      async put() {
        calls++;
        throw new Error("persistent outage");
      },
      async get() {
        throw new Error("not used");
      },
    };
    const name = `wormretryexhaust-${uniq()}`;
    const ssn = "765-43-2115";
    const r = await ingestRecord(
      makeRecord({
        sourceName: name,
        sourceRecordId: "evt-a",
        payload: `applicant_ssn=${ssn} status=new`,
      }),
      {
        rawEvidenceStore: failingStore,
        rawEvidenceWriteRetry: { maxAttempts: 2, backoffMs: 0 },
      },
    );
    expect(r.findingsCreated).toBe(1);
    expect(calls).toBe(2);

    const findings = await db
      .select({ id: findingsTable.id })
      .from(findingsTable)
      .where(
        and(
          eq(findingsTable.tenantId, TENANT),
          eq(findingsTable.fingerprint, `phi:ssn:fixture:${name}:v1`),
        ),
      );
    expect(findings).toHaveLength(1);

    const events = await db
      .select({ payload: ledgerEntriesTable.payload })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.eventType, "ingest.raw_evidence_store_failed"),
          eq(ledgerEntriesTable.subjectId, findings[0]!.id),
        ),
      );
    expect(events).toHaveLength(1);
    // No PHI leaked into the alert after exhausting retries.
    expect(JSON.stringify(events[0]!.payload)).not.toContain(ssn);
    // The provider/tenant is now latched degraded.
    expect(rawEvidenceStoreDegraded.has(`${provider}::${TENANT}`)).toBe(true);
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

describe("getDeadLetterConfigFromEnv", () => {
  it("returns null (disabled) unless INGEST_DEAD_LETTER_ENABLED is truthy", () => {
    expect(getDeadLetterConfigFromEnv({})).toBeNull();
    expect(getDeadLetterConfigFromEnv({ INGEST_DEAD_LETTER_ENABLED: "" })).toBeNull();
    expect(getDeadLetterConfigFromEnv({ INGEST_DEAD_LETTER_ENABLED: "0" })).toBeNull();
    expect(
      getDeadLetterConfigFromEnv({ INGEST_DEAD_LETTER_ENABLED: "false" }),
    ).toBeNull();
  });

  it("enables with defaults on 1/true and parses overrides", () => {
    expect(
      getDeadLetterConfigFromEnv({ INGEST_DEAD_LETTER_ENABLED: "1" }),
    ).toEqual({ maxAttempts: 3, backoffMs: 100 });
    expect(
      getDeadLetterConfigFromEnv({ INGEST_DEAD_LETTER_ENABLED: "true" }),
    ).toEqual({ maxAttempts: 3, backoffMs: 100 });
    expect(
      getDeadLetterConfigFromEnv({
        INGEST_DEAD_LETTER_ENABLED: "true",
        INGEST_DLQ_MAX_ATTEMPTS: "5",
        INGEST_DLQ_BACKOFF_MS: "0",
      }),
    ).toEqual({ maxAttempts: 5, backoffMs: 0 });
  });
});

describe("ingest dead-letter queue", () => {
  // A record that passes provenance validation but throws inside the upsert
  // (observedAt is not a real Date → .toISOString() throws), mirroring the
  // existing rethrow regression test. This is our deterministic "poison".
  const poison = (over?: Partial<LogRecord>): LogRecord => ({
    tenantId: TENANT,
    sourceType: "fixture",
    sourceName: `dlq-${uniq()}`,
    sourceRecordId: `rec-${uniq()}`,
    observedAt: "not-a-date" as unknown as Date,
    ingestedAt: new Date(),
    payload: "applicant_ssn=222-33-4444",
    ...over,
  });

  it("DLQ off (default): rethrows on terminal failure (byte-identical) and writes no marker", async () => {
    const bus = new InMemoryLogBus();
    const unsub = startIngestPipeline(bus, null);
    try {
      const bad = poison();
      const out = await bus.publish("raw.logs", bad);
      expect(out.delivered).toBe(0);
      expect(out.errors).toHaveLength(1);
      const markers = await db
        .select()
        .from(ingestDeadLetterTable)
        .where(eq(ingestDeadLetterTable.sourceName, bad.sourceName));
      expect(markers).toHaveLength(0);
    } finally {
      unsub();
    }
  });

  it("DLQ on: after exhausting attempts, persists a metadata-only marker, ledgers ingest.dead_lettered, and ACKs", async () => {
    const bus = new InMemoryLogBus();
    // backoffMs: 0 so the test doesn't actually sleep between retries.
    const unsub = startIngestPipeline(bus, { maxAttempts: 3, backoffMs: 0 });
    try {
      const before = await ledgerHeadSeq();
      const bad = poison();
      const out = await bus.publish("raw.logs", bad);

      // ACKed (no rethrow) so the broker stops redelivering the poison.
      expect(out.delivered).toBe(1);
      expect(out.errors).toHaveLength(0);

      // Metadata-only marker: source pointer + hash + counts, NO raw payload.
      const markers = await db
        .select()
        .from(ingestDeadLetterTable)
        .where(eq(ingestDeadLetterTable.sourceName, bad.sourceName));
      expect(markers).toHaveLength(1);
      const m = markers[0]!;
      expect(m.tenantId).toBe(TENANT);
      expect(m.sourceRecordId).toBe(bad.sourceRecordId);
      expect(m.attempts).toBe(3);
      expect(m.payloadBytes).toBe(Buffer.byteLength(bad.payload, "utf8"));
      expect(m.payloadSha256).toMatch(/^[0-9a-f]{64}$/);
      // The raw payload must never be stored in any column.
      for (const v of Object.values(m)) {
        if (typeof v === "string") expect(v).not.toContain("222-33-4444");
      }

      // Ledger event with metadata-only payload.
      const led = await db
        .select({
          eventType: ledgerEntriesTable.eventType,
          tenantId: ledgerEntriesTable.tenantId,
          payload: ledgerEntriesTable.payload,
        })
        .from(ledgerEntriesTable)
        .where(
          and(
            gt(ledgerEntriesTable.seq, before),
            eq(ledgerEntriesTable.eventType, "ingest.dead_lettered"),
            eq(
              ledgerEntriesTable.subjectId,
              `${bad.sourceType}:${bad.sourceName}:${bad.sourceRecordId}`,
            ),
          ),
        );
      expect(led).toHaveLength(1);
      expect(led[0]!.tenantId).toBe(TENANT);
      const lp = led[0]!.payload as Record<string, unknown>;
      expect(lp.attempts).toBe(3);
      expect(lp.payload_sha256).toBe(m.payloadSha256);
      expect(JSON.stringify(lp)).not.toContain("222-33-4444");
    } finally {
      unsub();
    }
  });

  it("DLQ on: a record that succeeds on the first try is not dead-lettered", async () => {
    const bus = new InMemoryLogBus();
    const unsub = startIngestPipeline(bus, { maxAttempts: 3, backoffMs: 0 });
    try {
      const ok = makeRecord({
        sourceName: `dlq-ok-${uniq()}`,
        payload: "applicant_ssn=444-55-6677",
      });
      const out = await bus.publish("raw.logs", ok);
      expect(out.delivered).toBe(1);
      expect(out.errors).toHaveLength(0);
      const markers = await db
        .select()
        .from(ingestDeadLetterTable)
        .where(eq(ingestDeadLetterTable.sourceName, ok.sourceName));
      expect(markers).toHaveLength(0);
    } finally {
      unsub();
    }
  });
});

