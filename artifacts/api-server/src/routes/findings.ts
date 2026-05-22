import { Router, type IRouter } from "express";
import { sql, and, eq, desc } from "drizzle-orm";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
type Finding = FindingSafe;
import { GetFindingResponse as FindingSchema } from "@workspace/api-zod";
import { withTenant } from "../lib/db-context";
import { requireSession } from "../lib/auth";

const router: IRouter = Router();

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
    redacted_evidence: row.redactedEvidence,
    detector_version: row.detectorVersion,
    first_seen_at: row.firstSeenAt.toISOString(),
    last_seen_at: row.lastSeenAt.toISOString(),
    occurrence_count: row.occurrenceCount,
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
  res.json(rows.map(toApi).map((r) => FindingSchema.parse(r)));
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

export default router;
// keep sql import used to silence ts-noUnused
void sql;
