// M3: Ingest pipeline. Subscribes to `raw.logs`, runs Stage-1 deterministic
// detectors (`scanForPhi`), produces redacted snippets, and upserts findings
// keyed by fingerprint so repeat hits from the same source coalesce into
// `occurrence_count`.
//
// Raw evidence is stored on the finding (`raw_evidence` jsonb, nullable,
// excluded from `findingSafeColumns`) so the existing break-glass flow
// (POST /api/admin/break-glass/grants → GET /api/admin/findings/:id/raw)
// works against ingested findings without further plumbing. In production
// this column would mirror a WORM-tier blob ref per ARCHITECTURE.md §3 — the
// dev DB is the placeholder for that tier.
//
// Per threat_model §InfoDisclosure: PHI MUST NOT appear in the searchable
// hot tier. The redacted snippet is what lands in `redacted_evidence`
// (BM25-indexed); the raw payload lands in `raw_evidence` (break-glass
// gated). Defense-in-depth: every redacted snippet is re-scanned before
// insert; a regression emits `ingest.redaction_regression` (critical) and
// the snippet falls back to a fully-opaque placeholder so no leftover
// PHI reaches the searchable tier.
//
// Per ARCHITECTURE.md §17.2 ("Stand up ingest end-to-end for one log
// source"): M3 ships the pipeline + the in-memory bus + a static fixture
// source + a CloudWatch interface stub. Real broker (Kafka) and real
// cloud-side fetch loops are post-M3.

import { randomUUID, createHash } from "node:crypto";
import { and, eq, sql } from "drizzle-orm";
import { findingsTable } from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";
import { scanForPhi, redactInline, type PhiHit } from "./redact";
import type { LogBus, LogHandler } from "./log-bus";
import type { LogRecord } from "./log-source";
import { logger } from "./logger";
import {
  getSearchProviderOrNull,
  type LexicalSearchProvider,
} from "./search-config";
import {
  getRawEvidenceStoreOrNull,
  type RawEvidenceStore,
} from "./raw-evidence-store";

export const INGEST_DETECTOR_VERSION = "stage1@m3";

const MAX_REDACTED_SNIPPET_BYTES = 1024;

// Source-provenance bounds. The `LogSource ↔ System` trust boundary in
// threat_model.md treats log content as attacker-controlled. M3 also treats
// the source-provenance fields (tenantId, sourceName, sourceRecordId) as
// attacker-influenced — a compromised log shipper could send pathological
// values. These caps + charset allow-lists run at ingest entry; malformed
// records are dropped with a warning-level ledger entry instead of
// processed. Payload is capped (and truncated downstream) but NOT charset-
// restricted — it IS log content.
const MAX_TENANT_ID_LEN = 64;
const MAX_SOURCE_NAME_LEN = 256;
const MAX_SOURCE_RECORD_ID_LEN = 256;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const TENANT_ID_RE = /^[A-Za-z0-9_-]+$/;
const SOURCE_NAME_RE = /^[A-Za-z0-9._/-]+$/;
const SOURCE_RECORD_ID_RE = /^[A-Za-z0-9._:/-]+$/;

/** Classification → severity. One finding per (source, classification) so a
 *  multi-class record fans out to multiple findings, each with its own
 *  severity. Mirrors the existing seed conventions. */
const SEVERITY_BY_CLASSIFICATION: Record<
  PhiHit["classification"],
  "critical" | "high" | "medium"
> = {
  secrets: "critical",
  phi: "high",
  pii_s: "high",
  pii: "medium",
};

function fingerprintFor(args: {
  classification: string;
  detector: string;
  sourceType: string;
  sourceName: string;
}): string {
  // `v1` suffix mirrors the seed-fingerprint convention so a future scheme
  // change (e.g. adding sub-source granularity) is recognizable as a
  // different fingerprint instead of silently colliding with v1 rows.
  return `${args.classification}:${args.detector}:${args.sourceType}:${args.sourceName}:v1`;
}

function truncateSnippet(s: string): { snippet: string; truncated: boolean } {
  if (Buffer.byteLength(s, "utf8") <= MAX_REDACTED_SNIPPET_BYTES) {
    return { snippet: s, truncated: false };
  }
  // Cheap codepoint-safe trim: shrink in 16-char steps until under budget,
  // then append the truncation marker. Good enough for 1KB snippet cap.
  let end = s.length;
  while (
    end > 0 &&
    Buffer.byteLength(s.slice(0, end), "utf8") > MAX_REDACTED_SNIPPET_BYTES - 16
  ) {
    end -= 16;
  }
  return {
    snippet: s.slice(0, Math.max(0, end)) + "…<TRUNCATED>",
    truncated: true,
  };
}

/** Validate provenance fields at the trust boundary. Returns an error string
 *  if the record is malformed, else null. Caller is expected to ledger the
 *  rejection (so a misbehaving source is auditable) and drop the record. */
function validateProvenance(record: LogRecord): string | null {
  if (
    !record.tenantId ||
    record.tenantId.length > MAX_TENANT_ID_LEN ||
    !TENANT_ID_RE.test(record.tenantId)
  )
    return "tenantId_invalid";
  if (
    !record.sourceName ||
    record.sourceName.length > MAX_SOURCE_NAME_LEN ||
    !SOURCE_NAME_RE.test(record.sourceName)
  )
    return "sourceName_invalid";
  if (
    !record.sourceRecordId ||
    record.sourceRecordId.length > MAX_SOURCE_RECORD_ID_LEN ||
    !SOURCE_RECORD_ID_RE.test(record.sourceRecordId)
  )
    return "sourceRecordId_invalid";
  if (Buffer.byteLength(record.payload, "utf8") > MAX_PAYLOAD_BYTES)
    return "payload_too_large";
  return null;
}

function groupByClassification(
  hits: PhiHit[],
): Map<PhiHit["classification"], PhiHit[]> {
  const m = new Map<PhiHit["classification"], PhiHit[]>();
  for (const h of hits) {
    const arr = m.get(h.classification) ?? [];
    arr.push(h);
    m.set(h.classification, arr);
  }
  return m;
}

export interface IngestResult {
  hits: number;
  findingsCreated: number;
  findingsUpdated: number;
  redactionRegressions: number;
}

/** Injectable deps for tests. Defaults are the real scan + redact, and the
 *  module-registered lexical search provider (or none). */
export interface IngestDeps {
  scan?: typeof scanForPhi;
  redact?: typeof redactInline;
  searchProvider?: LexicalSearchProvider | null;
  rawEvidenceStore?: RawEvidenceStore | null;
}

/** Process a single `LogRecord`. Idempotent at the fingerprint level: a
 *  repeat record from the same source with the same leak class increments
 *  `occurrence_count` and bumps `last_seen_at` on the existing finding
 *  instead of inserting a duplicate row. Returns counters for observability
 *  and tests. */
export async function ingestRecord(
  record: LogRecord,
  deps: IngestDeps = {},
): Promise<IngestResult> {
  const scan = deps.scan ?? scanForPhi;
  const redact = deps.redact ?? redactInline;
  // `undefined` → use the module-registered provider (or none); an explicit
  // `null` disables mirroring (test path). Postgres' no-op provider is skipped
  // below via `maintainsExternalIndex`.
  const searchProvider =
    deps.searchProvider === undefined
      ? getSearchProviderOrNull()
      : deps.searchProvider;
  // Same convention: `undefined` → module-registered store (or none); explicit
  // `null` forces the inline-DB path (test default). `external === true` selects
  // the WORM two-phase write below; otherwise raw stays inline in `raw_evidence`.
  const rawEvidenceStore =
    deps.rawEvidenceStore === undefined
      ? getRawEvidenceStoreOrNull()
      : deps.rawEvidenceStore;
  const externalRaw = rawEvidenceStore?.external ?? false;

  const result: IngestResult = {
    hits: 0,
    findingsCreated: 0,
    findingsUpdated: 0,
    redactionRegressions: 0,
  };

  // Trust-boundary validation. A malformed/oversized record is dropped, not
  // processed — but the drop itself is ledgered so the source's
  // misbehavior is auditable. Detector names + counts only; no raw payload
  // or raw provenance values reach the ledger.
  const provenanceErr = validateProvenance(record);
  if (provenanceErr) {
    await appendLedger({
      // Use the *received* tenant if it's at least syntactically valid;
      // otherwise fall back to null so we don't poison a real tenant's
      // scope with attacker-controlled values.
      tenantId:
        typeof record.tenantId === "string" &&
        record.tenantId.length > 0 &&
        record.tenantId.length <= MAX_TENANT_ID_LEN &&
        TENANT_ID_RE.test(record.tenantId)
          ? record.tenantId
          : null,
      actor: { kind: "system", id: "ingest" },
      eventType: "ingest.malformed_record",
      subjectType: "log_record",
      subjectId: undefined,
      payload: {
        reason: provenanceErr,
        source_type: record.sourceType,
        // Length only — never the raw oversized value.
        source_name_len: record.sourceName?.length ?? 0,
        source_record_id_len: record.sourceRecordId?.length ?? 0,
        payload_bytes: Buffer.byteLength(record.payload ?? "", "utf8"),
      },
    });
    return result;
  }

  const hits = scan(record.payload);
  if (hits.length === 0) return result;
  result.hits = hits.length;

  const sourceStr = `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`;
  const grouped = groupByClassification(hits);

  // Build the redacted snippet ONCE from ALL hits (covers every detector
  // class) — we don't want any other-class leak surviving inside any
  // class's snippet.
  const { snippet: rawRedacted, redactions } = redact(record.payload, hits);

  // Defense-in-depth: re-scan the redacted snippet. If the redactor missed
  // anything, ledger a critical regression event and fall back to a fully
  // opaque snippet. The finding is still recorded (so the leak is auditable)
  // but no payload-derived text reaches the searchable tier.
  let snippet = rawRedacted;
  const regressionHits = scan(rawRedacted);
  if (regressionHits.length > 0) {
    result.redactionRegressions++;
    snippet = `<REDACTED: redactor missed ${regressionHits.length} hit(s) — full opacity applied>`;
    await appendLedger({
      tenantId: record.tenantId,
      actor: { kind: "system", id: "ingest" },
      eventType: "ingest.redaction_regression",
      subjectType: "log_record",
      subjectId: sourceStr,
      payload: {
        source: sourceStr,
        // Detector names only — never the raw matched values.
        missed_detectors: regressionHits.map((h) => h.detector),
        payload_sha256: createHash("sha256")
          .update(record.payload)
          .digest("hex"),
      },
    });
  }

  const capped = truncateSnippet(snippet);

  for (const [classification, classHits] of grouped) {
    const severity = SEVERITY_BY_CLASSIFICATION[classification];
    const dominant = classHits[0]!.detector;
    const fp = fingerprintFor({
      classification,
      detector: dominant,
      sourceType: record.sourceType,
      sourceName: record.sourceName,
    });

    // Upsert by fingerprint.
    //
    // No DB-level UNIQUE on (tenant_id, fingerprint) because the existing
    // chat / tool-policy paths intentionally insert N rows sharing a
    // fingerprint with distinct ids. So the dedupe contract has to be
    // enforced from the ingest side. A naive SELECT-then-INSERT-or-UPDATE
    // races: two concurrent ingests of the same fingerprint can both see
    // zero rows and both insert, producing a duplicate finding AND a
    // duplicate `finding.created` ledger entry — which would violate the
    // claim that `finding.created` is the unique audit anchor for a
    // fingerprint (architect-flagged).
    //
    // Fix: hold a Postgres transaction-scoped advisory lock keyed on
    // (tenant_id, fingerprint) inside the tx, before the SELECT. The lock
    // is namespaced under hashtext('ingest:fingerprint') so it never
    // collides with locks held by other code paths. Released automatically
    // at tx commit/rollback. Concurrent ingests of the same fingerprint
    // serialize; concurrent ingests of different fingerprints do not.
    const occurrenceSnapshot = {
      source_record_id: record.sourceRecordId,
      source_type: record.sourceType,
      source_name: record.sourceName,
      observed_at: record.observedAt.toISOString(),
      ingested_at: record.ingestedAt.toISOString(),
      payload: record.payload,
    };

    const upsert = await withTenant(record.tenantId, async (tx) => {
      await tx.execute(sql`
        SELECT pg_advisory_xact_lock(
          hashtext('ingest:fingerprint'),
          hashtext(${record.tenantId} || ':' || ${fp})
        )
      `);

      const existing = await tx
        .select({
          id: findingsTable.id,
          rawEvidence: findingsTable.rawEvidence,
        })
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.tenantId, record.tenantId),
            eq(findingsTable.fingerprint, fp),
          ),
        )
        .limit(1);
      const existingRow = existing[0];

      const redactedEvidence = {
        snippet: capped.snippet,
        redactions,
        truncated: capped.truncated,
        trust: "untrusted" as const,
      };

      if (existingRow) {
        // Preserve the FIRST occurrence's snapshot for forensic
        // reconstruction (architect-flagged: "An analyst reviewing a
        // 6-month-old finding that just spiked will see only the latest
        // leak"). Latest snapshot also retained so an analyst can see
        // what's currently arriving. Both are break-glass gated.
        //
        // EXTERNAL store: raw lives in the WORM tier, not the column — leave
        // `raw_evidence` untouched (NULL) and update only non-raw fields here;
        // the {first,latest} object refs are written in tx-B after store.put,
        // outside this lock (network I/O must not extend the advisory-lock
        // hold). DB store: keep the inline first/latest merge (unchanged M3
        // behavior).
        const set: Record<string, unknown> = {
          lastSeenAt: new Date(),
          occurrenceCount: sql`${findingsTable.occurrenceCount} + 1`,
          redactedEvidence,
        };
        if (!externalRaw) {
          const existingRaw = existingRow.rawEvidence as
            | { first?: unknown; latest?: unknown; payload?: unknown }
            | null;
          const first =
            (existingRaw && "first" in existingRaw && existingRaw.first) ||
            // Migrate flat-shape (pre-fix) rows on first re-hit: treat the
            // existing row as the first occurrence so we don't lose it.
            (existingRaw && "payload" in existingRaw ? existingRaw : null) ||
            occurrenceSnapshot;
          set["rawEvidence"] = { first, latest: occurrenceSnapshot };
        }
        await tx
          .update(findingsTable)
          .set(set)
          .where(eq(findingsTable.id, existingRow.id));
        return { id: existingRow.id, created: false };
      }

      const id = `F-INGEST-${randomUUID().slice(0, 8)}`;
      await tx.insert(findingsTable).values({
        id,
        tenantId: record.tenantId,
        classification,
        subclass: dominant,
        severity,
        status: "open",
        source: sourceStr,
        fingerprint: fp,
        redactedEvidence,
        // EXTERNAL store: column stays NULL; raw_evidence_ref is set in tx-B.
        // DB store: raw stays inline as the {first,latest} occurrence snapshot.
        rawEvidence: externalRaw
          ? null
          : {
              first: occurrenceSnapshot,
              latest: occurrenceSnapshot,
            },
        detectorVersion: INGEST_DETECTOR_VERSION,
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
        occurrenceCount: 1,
      });
      return { id, created: true };
    });

    if (upsert.created) {
      result.findingsCreated++;
      await appendLedger({
        tenantId: record.tenantId,
        actor: { kind: "system", id: "ingest" },
        eventType: "finding.created",
        subjectType: "finding",
        subjectId: upsert.id,
        payload: {
          finding_id: upsert.id,
          classification,
          severity,
          source: sourceStr,
          fingerprint: fp,
          detector_version: INGEST_DETECTOR_VERSION,
          // Hash only — the raw payload is in `raw_evidence` and reachable
          // only via the break-glass code path, never via the ledger.
          payload_sha256: createHash("sha256")
            .update(record.payload)
            .digest("hex"),
        },
      });
    } else {
      result.findingsUpdated++;
      // Intentionally NOT ledgering every repeat occurrence. Threat-model
      // §Tampering says "updates to underlying tables MUST themselves emit
      // ledger entries" — the intent (per architect review) is *structural*
      // changes (severity, status, classification) that an analyst or agent
      // would have to defend, not operational counters. `occurrence_count++`
      // and `last_seen_at = now()` are pure operational rhythm; the original
      // `finding.created` ledger entry plus the raw_evidence first/latest
      // snapshots are the audit anchor for the leak. Per-occurrence ledger
      // entries at ingest volume would also blow up the chain (one entry per
      // log line) for no investigative gain.
    }

    // tx-B (external WORM store only): write this occurrence's raw payload as a
    // NEW immutable object, then race-safely advance the finding's
    // `raw_evidence_ref`. Done OUTSIDE the dedup advisory lock so the (possibly
    // slow) object-store round-trip never serializes concurrent ingests of the
    // same fingerprint. `first` is set-once via column-level COALESCE
    // (first-writer-wins under concurrency), `latest` always advances to the
    // newest object. Best-effort + LOUD: the finding is already committed (the
    // leak is recorded); if the raw write fails we log at error level and leave
    // `raw_evidence_ref` NULL — a later occurrence's COALESCE will re-seat
    // `first`, and break-glass reports the raw as unresolved rather than
    // silently fabricating one. We deliberately do NOT rethrow: tx-A is
    // committed and a throw would only drive a bus retry that double-counts the
    // occurrence.
    if (externalRaw && rawEvidenceStore) {
      try {
        const uri = await rawEvidenceStore.put({
          findingId: upsert.id,
          tenantId: record.tenantId,
          evidence: occurrenceSnapshot,
        });
        await withTenant(record.tenantId, async (tx) => {
          await tx.execute(sql`
            UPDATE findings
            SET raw_evidence_ref = jsonb_build_object(
              'first', COALESCE(raw_evidence_ref->'first', to_jsonb(${uri}::text)),
              'latest', to_jsonb(${uri}::text)
            )
            WHERE id = ${upsert.id} AND tenant_id = ${record.tenantId}
          `);
        });
      } catch (err) {
        logger.error(
          { err, finding_id: upsert.id, provider: rawEvidenceStore.name },
          "external raw-evidence write failed; finding persisted WITHOUT retrievable raw evidence (raw_evidence_ref left null)",
        );
        // Proactive operator signal: durable raw-evidence capture to the WORM
        // tier is degraded. The finding is committed (the leak is recorded),
        // but its raw PHI is NOT being persisted to durable storage — today
        // this only surfaced reactively at break-glass read time as
        // `raw_unresolved`. For a compliance system, operators must learn
        // *proactively* that raw PHI is not landing in the WORM tier, not
        // discover it mid-incident. Ledger (and thus alert/channel route) the
        // failure with provider + finding id + tenant only — NO PHI, no raw
        // payload, no object URI. Only reachable when an external store is
        // configured (the inline DB store can't fail this way).
        await appendLedger({
          tenantId: record.tenantId,
          actor: { kind: "system", id: "ingest" },
          eventType: "ingest.raw_evidence_store_failed",
          subjectType: "finding",
          subjectId: upsert.id,
          payload: {
            finding_id: upsert.id,
            provider: rawEvidenceStore.name,
            source: sourceStr,
            error: err instanceof Error ? err.name : "unknown",
          },
        });
      }
    }

    // Mirror the redacted projection into the external lexical index (created
    // OR updated, so re-occurrences keep the indexed snippet fresh). Best
    // effort: a search-backend outage must NEVER fail ingest — the finding is
    // already committed to Postgres and the boot reconcile is the backstop.
    // Postgres' no-op provider is skipped via `maintainsExternalIndex`. Only
    // redacted fields are sent — raw PHI never reaches the searchable tier.
    if (searchProvider?.maintainsExternalIndex) {
      try {
        await searchProvider.indexFinding({
          findingId: upsert.id,
          tenantId: record.tenantId,
          classification,
          subclass: dominant,
          severity,
          source: sourceStr,
          snippet: capped.snippet,
        });
      } catch (err) {
        logger.warn(
          { err, finding_id: upsert.id, provider: searchProvider.name },
          "external search index upsert failed; finding persisted, reconcile will backfill",
        );
      }
    }
  }

  return result;
}

/** Subscribe the ingest pipeline to the bus. Returns the unsubscribe
 *  handle so boot ordering / shutdown / tests can release it. */
export function startIngestPipeline(bus: LogBus): () => void {
  const handler: LogHandler = async (record) => {
    try {
      const r = await ingestRecord(record);
      if (r.hits > 0) {
        logger.debug(
          {
            source: `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`,
            hits: r.hits,
            created: r.findingsCreated,
            updated: r.findingsUpdated,
            regressions: r.redactionRegressions,
          },
          "ingest processed record with detector hits",
        );
      }
    } catch (err) {
      // Log here for pipeline-attributable triage context, then RETHROW so
      // bus.publish() can surface the failure in PublishResult.errors[].
      // Swallowing would defeat fix #5 — `/api/admin/ingest/replay` would
      // report `errors: 0` even when ingest actually failed.
      logger.error(
        {
          err,
          source: `${record.sourceType}:${record.sourceName}:${record.sourceRecordId}`,
        },
        "ingest pipeline failed for record",
      );
      throw err;
    }
  };
  return bus.subscribe("raw.logs", handler);
}
