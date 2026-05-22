import { randomUUID } from "node:crypto";
import { Router, type IRouter } from "express";
import { z } from "zod";
import { and, desc, eq, gt, isNull, sql } from "drizzle-orm";
import {
  breakGlassGrantsTable,
  findingsTable,
  type BreakGlassGrant,
  type Finding,
} from "@workspace/db";
import { withTenant } from "../lib/db-context";
import { requireSession, requireStepUp } from "../lib/auth";
import { appendLedger } from "../lib/ledger";

// M1.6: break-glass raw-PHI access flow.
//
// Two-stage gate:
//
//   1. POST /admin/break-glass/grants — requires session + step-up + justifi-
//      cation. Issues a time-boxed grant for a specific finding_id. Ledgered
//      `break_glass.granted` with the justification.
//
//   2. GET /admin/findings/:id/raw — requires session only (the grant
//      itself IS the second-factor gate). Looks up an active unrevoked
//      unexpired grant for (tenant, user, finding) and returns the raw
//      evidence. Ledgered `break_glass.raw_phi_accessed` per access (NOT
//      per grant) so the timeline of every read is reconstructable.
//
// Threat model §EoP "Break-glass scope minimization":
//   - per-finding, time-boxed, justification required, auto-revokes on
//     expiry, ledgered on grant AND on every access.

const router: IRouter = Router();

const MAX_TTL_SECONDS = 15 * 60; // 15 minutes max grant lifetime.
const MIN_JUSTIFICATION_LEN = 10;

const CreateGrantBody = z.object({
  finding_id: z.string().min(1).max(64).regex(/^[A-Za-z0-9_-]+$/),
  justification: z
    .string()
    .min(MIN_JUSTIFICATION_LEN)
    .max(2000),
  ttl_seconds: z
    .number()
    .int()
    .min(60)
    .max(MAX_TTL_SECONDS)
    .optional(),
});

function grantToApi(g: BreakGlassGrant): unknown {
  return {
    id: g.id,
    tenant_id: g.tenantId,
    user_id: g.userId,
    finding_id: g.findingId,
    justification: g.justification,
    granted_at: g.grantedAt.toISOString(),
    expires_at: g.expiresAt.toISOString(),
    revoked_at: g.revokedAt?.toISOString() ?? null,
    active:
      g.revokedAt === null && g.expiresAt.getTime() > Date.now(),
  };
}

// Issue a new break-glass grant. Requires step-up — the grant endpoint is
// what consumes the elevated authority; the subsequent raw-read just rides
// on a (separately ledgered) grant row.
router.post(
  "/admin/break-glass/grants",
  requireSession,
  requireStepUp,
  async (req, res): Promise<void> => {
    const parsed = CreateGrantBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const ttl = parsed.data.ttl_seconds ?? MAX_TTL_SECONDS;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttl * 1000);

    // Verify the finding exists in the caller's tenant. We don't 404 on a
    // raw-evidence-absent finding (most findings have no raw payload in dev);
    // the grant is still meaningful as proof of intent.
    const found = await withTenant(tenantId, async (tx) =>
      tx
        .select({ id: findingsTable.id })
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.id, parsed.data.finding_id),
            eq(findingsTable.tenantId, tenantId),
          ),
        )
        .limit(1),
    );
    if (found.length === 0) {
      res.status(404).json({ error: "finding not found" });
      return;
    }

    const id = `bg_${randomUUID()}`;
    const [row] = await withTenant(tenantId, async (tx) =>
      tx
        .insert(breakGlassGrantsTable)
        .values({
          id,
          tenantId,
          userId,
          findingId: parsed.data.finding_id,
          justification: parsed.data.justification,
          grantedAt: now,
          expiresAt,
        })
        .returning(),
    );

    const led = await appendLedger({
      tenantId,
      actor: { kind: "human", id: userId },
      eventType: "break_glass.granted",
      subjectType: "finding",
      subjectId: parsed.data.finding_id,
      payload: {
        grant_id: id,
        finding_id: parsed.data.finding_id,
        justification: parsed.data.justification,
        ttl_seconds: ttl,
        expires_at: expiresAt.toISOString(),
        step_up_reason: req.stepUp!.reason,
      },
    });
    req.log.warn(
      { grant_id: id, finding_id: parsed.data.finding_id, seq: led.seq },
      "break-glass grant issued",
    );
    res.status(201).json(grantToApi(row!));
  },
);

// List the caller's active grants (for the dashboard's "active break-glass
// grants" badge). Returns at most 50, most-recently-granted first.
router.get(
  "/admin/break-glass/grants",
  requireSession,
  async (req, res): Promise<void> => {
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const rows = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(breakGlassGrantsTable)
        .where(
          and(
            eq(breakGlassGrantsTable.tenantId, tenantId),
            eq(breakGlassGrantsTable.userId, userId),
          ),
        )
        .orderBy(desc(breakGlassGrantsTable.grantedAt))
        .limit(50),
    );
    res.json(rows.map(grantToApi));
  },
);

// Read raw evidence. Requires (a) an active grant for (tenant, user,
// finding_id), and (b) ledgers EVERY access. Returns the raw evidence
// payload if present; if no raw payload exists (most findings in dev), the
// gate still operates and the ledger still records the access, but the
// response carries `raw_evidence: null` plus a marker. This is intentional:
// the security guarantee (justification + ledger trail) does not depend on
// the existence of raw payload.
router.get(
  "/admin/findings/:id/raw",
  requireSession,
  async (req, res): Promise<void> => {
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const findingId = String(req.params.id);

    const now = new Date();
    const grant = await withTenant(tenantId, async (tx) => {
      const [g] = await tx
        .select()
        .from(breakGlassGrantsTable)
        .where(
          and(
            eq(breakGlassGrantsTable.tenantId, tenantId),
            eq(breakGlassGrantsTable.userId, userId),
            eq(breakGlassGrantsTable.findingId, findingId),
            isNull(breakGlassGrantsTable.revokedAt),
            gt(breakGlassGrantsTable.expiresAt, now),
          ),
        )
        .orderBy(desc(breakGlassGrantsTable.grantedAt))
        .limit(1);
      return g;
    });
    if (!grant) {
      res.status(403).json({
        error: "no active break-glass grant for this finding",
        break_glass_required: true,
      });
      return;
    }

    const found = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(findingsTable)
        .where(
          and(
            eq(findingsTable.id, findingId),
            eq(findingsTable.tenantId, tenantId),
          ),
        )
        .limit(1),
    );
    if (found.length === 0) {
      res.status(404).json({ error: "finding not found" });
      return;
    }
    const f = found[0]! as Finding;

    // Ledger the access. Severity is "high" by convention so a verification
    // dashboard can highlight every raw-PHI read.
    const led = await appendLedger({
      tenantId,
      actor: { kind: "human", id: userId },
      eventType: "break_glass.raw_phi_accessed",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        grant_id: grant.id,
        finding_id: findingId,
        finding_classification: f.classification,
        finding_severity: f.severity,
        raw_present: f.rawEvidence !== null,
      },
    });
    req.log.warn(
      {
        grant_id: grant.id,
        finding_id: findingId,
        seq: led.seq,
        raw_present: f.rawEvidence !== null,
      },
      "raw PHI accessed via break-glass",
    );

    res.json({
      finding_id: f.id,
      grant_id: grant.id,
      grant_expires_at: grant.expiresAt.toISOString(),
      classification: f.classification,
      severity: f.severity,
      raw_evidence: f.rawEvidence,
    });
  },
);

export default router;
// keep sql import used to silence ts-noUnused (reserved for future query)
void sql;
