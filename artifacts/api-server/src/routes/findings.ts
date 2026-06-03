import { Router, type IRouter } from "express";
import { sql, and, eq, desc } from "drizzle-orm";
import {
  db,
  findingsTable,
  findingSafeColumns,
  ledgerEntriesTable,
  type FindingSafe,
} from "@workspace/db";
type Finding = FindingSafe;
import { GetFindingResponse as FindingSchema } from "@workspace/api-zod";
import { withTenant } from "../lib/db-context";
import { requireSession } from "../lib/auth";

const router: IRouter = Router();

// Defensively coerce a possibly-partial stored redacted_evidence blob into the
// shape required by the API schema. Findings created via the ingest/replay path
// can land with an evidence record missing required fields (e.g. `truncated`);
// without this, a single bad row makes `FindingSchema.parse` throw and 500s the
// entire list. Missing fields fall back to safe, non-leaking defaults.
function normalizeRedactedEvidence(value: unknown): {
  snippet: string;
  redactions: string[];
  truncated: boolean;
  trust: "trusted" | "untrusted";
} {
  const ev = (value ?? {}) as Record<string, unknown>;
  return {
    snippet: typeof ev.snippet === "string" ? ev.snippet : "",
    redactions: Array.isArray(ev.redactions)
      ? ev.redactions.filter((r): r is string => typeof r === "string")
      : [],
    truncated: typeof ev.truncated === "boolean" ? ev.truncated : false,
    trust: ev.trust === "trusted" ? "trusted" : "untrusted",
  };
}

function toApi(row: Finding): unknown {
  return {
    id: row.id,
    tenant_id: row.tenantId,
    classification: row.classification,
    subclass: row.subclass,
    severity: row.severity,
    status: row.status,
    source: row.source,
    fingerprint: row.fingerprint,
    redacted_evidence: normalizeRedactedEvidence(row.redactedEvidence),
    detector_version: row.detectorVersion,
    first_seen_at: row.firstSeenAt.toISOString(),
    last_seen_at: row.lastSeenAt.toISOString(),
    occurrence_count: row.occurrenceCount,
    agent_review_status: row.agentReviewStatus,
    triage_verdict: row.triageVerdict ?? null,
    verifier_verdict: row.verifierVerdict ?? null,
    last_agent_review_at: row.lastAgentReviewAt
      ? row.lastAgentReviewAt.toISOString()
      : null,
  };
}

router.get("/findings", requireSession, async (req, res): Promise<void> => {
  const status = typeof req.query.status === "string" ? req.query.status : undefined;
  const severity = typeof req.query.severity === "string" ? req.query.severity : undefined;
  const tenantId = req.session!.tenant_id;
  // We read via the underlying table (filtered by RLS). The
  // `findings_redacted` view exists in the DB but only projects the same
  // columns in M0; selecting from the table is equivalent and lets drizzle
  // type the result. Future: switch the route to query the view explicitly
  // once raw_evidence columns are added.
  const rows = await withTenant(tenantId, async (tx) => {
    const filters = [eq(findingsTable.tenantId, tenantId)];
    if (status) filters.push(eq(findingsTable.status, status));
    if (severity) filters.push(eq(findingsTable.severity, severity));
    // M1.6: safe projection — dashboard list endpoint must never carry raw.
    return tx
      .select(findingSafeColumns)
      .from(findingsTable)
      .where(and(...filters))
      .orderBy(desc(findingsTable.severity), desc(findingsTable.lastSeenAt))
      .limit(200);
  });
  // Parse each row defensively: a single malformed finding (e.g. partial
  // redacted_evidence from an older ingest path) must not 500 the whole list.
  // Rows that still fail validation after normalization are skipped and logged
  // rather than dropping the entire response.
  const out: unknown[] = [];
  for (const row of rows) {
    const parsed = FindingSchema.safeParse(toApi(row));
    if (parsed.success) {
      out.push(parsed.data);
    } else {
      req.log.warn(
        { findingId: row.id, issues: parsed.error.issues },
        "skipping finding with unparseable shape in list response",
      );
    }
  }
  res.json(out);
});

router.get("/findings/:id", requireSession, async (req, res): Promise<void> => {
  const id = String(req.params.id);
  const tenantId = req.session!.tenant_id;
  const rows = await withTenant(tenantId, async (tx) =>
    // M1.6: safe projection — single-finding read on the dashboard is the
    // redacted path; raw evidence is reachable only via the step-up-gated
    // /admin/findings/:id/raw endpoint.
    tx
      .select(findingSafeColumns)
      .from(findingsTable)
      .where(
        and(eq(findingsTable.id, id), eq(findingsTable.tenantId, tenantId)),
      )
      .limit(1),
  );
  if (rows.length === 0) {
    res.status(404).json({ error: "finding not found" });
    return;
  }
  res.json(FindingSchema.parse(toApi(rows[0]!)));
});

// Finding-scoped audit history. Surfaces the finding's lifecycle to a reviewer
// inline on the detail page so they don't have to dig through the global Audit
// Ledger: resolve / reopen transitions and break-glass grant / approve / revoke
// events, including the free-text reason where one was recorded.
//
// `ledger_entries` has NO RLS policy (the chain verifier walks every tenant's
// entries to prove integrity — that path stays global by design), so — exactly
// as the global /ledger list route does — we enforce isolation here with an
// explicit `tenant_id` predicate. Entry payloads carry tenant-private free text
// (reopen reason / break-glass justification / approval_note / revoke reason),
// so an unscoped query would leak another tenant's operational audit trail.
// Scoped to `subject_id = :id` so it returns only this finding's events.
// Most-recent-first by `seq`. All free text here was content-policy scanned at
// write time, so it carries no raw PHI/secrets.
router.get(
  "/findings/:id/history",
  requireSession,
  async (req, res): Promise<void> => {
    const id = String(req.params.id);
    const tenantId = req.session!.tenant_id;
    const rows = await db
      .select()
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.tenantId, tenantId),
          eq(ledgerEntriesTable.subjectType, "finding"),
          eq(ledgerEntriesTable.subjectId, id),
        ),
      )
      .orderBy(desc(ledgerEntriesTable.seq))
      .limit(200);
    res.json(
      rows.map((r) => ({
        seq: r.seq,
        ts: r.ts.toISOString(),
        tenant_id: r.tenantId,
        actor: r.actor,
        event_type: r.eventType,
        subject_type: r.subjectType,
        subject_id: r.subjectId,
        payload: r.payload,
        prev_hash: r.prevHash,
        hash: r.hash,
      })),
    );
  },
);

export default router;
// keep sql import used to silence ts-noUnused
void sql;
