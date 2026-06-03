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
import { validateLedgerSafeText } from "../lib/text-policy";
import {
  getRawEvidenceStoreOrNull,
  resolveRawEvidence,
} from "../lib/raw-evidence-store";
import { resolveFinding, reopenFinding } from "../lib/finding-status";

// M1.6: break-glass raw-PHI access flow.
// M1.7: two-person rule on critical-severity findings.
//
// Three-stage gate for critical findings (two-stage for high/medium/low):
//
//   1. POST /admin/break-glass/grants — requires session + step-up + justifi-
//      cation. Issues a grant for a specific finding_id. If the finding's
//      severity is `critical`, the grant is created PENDING
//      (`approver_user_id IS NULL`) and raw access is blocked until step 2.
//      Ledgered `break_glass.granted` with `requires_second_approval`.
//
//   2. (critical only) POST /admin/break-glass/grants/:id/approve — requires
//      session + step-up by a *different* user in the same tenant.
//      Self-approval is rejected and ledgered `break_glass.approval_denied_
//      self_approval`. Approval ledgered `break_glass.approved`.
//
//   3. GET /admin/findings/:id/raw — requires session only (the grant
//      itself IS the gate). Looks up an active unrevoked unexpired grant
//      for (tenant, user, finding). For pending critical grants, the lookup
//      additionally requires `approver_user_id IS NOT NULL`. Ledgered
//      `break_glass.raw_phi_accessed` per access (NOT per grant) so the
//      timeline of every read is reconstructable.
//
// Threat model §EoP "Break-glass scope minimization":
//   - per-finding, time-boxed, justification required, auto-revokes on
//     expiry, ledgered on grant AND on every access.
//
// Threat model §EoP "Insider threat (rogue analyst)":
//   - per-finding break-glass grants, mandatory justification, ledgered
//     per-access, and weekly review of break-glass activity. The two-person
//     rule on critical findings is the strongest form of "weekly review"
//     compressed to the moment of access: a rogue analyst on their own
//     cannot read raw PHI on critical findings without a second analyst
//     also performing step-up and signing off — both identities are in
//     the ledger and both are visible during routine review.

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

const ApproveGrantBody = z.object({
  approval_note: z.string().min(MIN_JUSTIFICATION_LEN).max(2000),
});

const RevokeGrantBody = z.object({
  // Optional free-text reason — lands in the ledger payload, so it is scanned
  // by the same content policy as justification / approval_note when present.
  reason: z.string().min(1).max(2000).optional(),
});

const ResolveFindingBody = z.object({
  // Only the closed states are accepted here; reopening (back to "open") is a
  // different action and would NOT auto-revoke, so it is deliberately excluded.
  status: z.enum(["resolved", "false_positive"]),
});

const ReopenFindingBody = z.object({
  // Optional free-text reason — lands in the immutable ledger payload, so it is
  // scanned by the same content policy as resolve/revoke justifications when
  // present.
  reason: z.string().min(1).max(2000).optional(),
});

function grantToApi(g: BreakGlassGrant): unknown {
  const now = Date.now();
  const notExpired = g.expiresAt.getTime() > now;
  const notRevoked = g.revokedAt === null;
  const approvalOk =
    !g.requiresSecondApproval || g.approverUserId !== null;
  return {
    id: g.id,
    tenant_id: g.tenantId,
    user_id: g.userId,
    finding_id: g.findingId,
    justification: g.justification,
    granted_at: g.grantedAt.toISOString(),
    expires_at: g.expiresAt.toISOString(),
    revoked_at: g.revokedAt?.toISOString() ?? null,
    requires_second_approval: g.requiresSecondApproval,
    approver_user_id: g.approverUserId,
    approved_at: g.approvedAt?.toISOString() ?? null,
    pending_approval: g.requiresSecondApproval && g.approverUserId === null,
    active: notExpired && notRevoked && approvalOk,
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

    // Boundary scan: the justification lands in the ledger payload. Refuse
    // any text that scans as PHI/secrets or contains the canary token,
    // and ledger the refusal (without the offending text) so that the
    // attempt is auditable. See `lib/text-policy.ts` for rationale.
    const jv = validateLedgerSafeText(parsed.data.justification);
    if (!jv.ok) {
      await appendLedger({
        tenantId,
        actor: { kind: "human", id: userId },
        eventType: "policy.text_field_rejected",
        subjectType: "finding",
        subjectId: parsed.data.finding_id,
        payload: {
          endpoint: "POST /admin/break-glass/grants",
          field: "justification",
          reason: jv.reason,
          detectors: jv.detectors,
        },
      });
      res.status(400).json({
        error: "justification rejected by content policy",
        reason: jv.reason,
      });
      return;
    }
    const ttl = parsed.data.ttl_seconds ?? MAX_TTL_SECONDS;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttl * 1000);

    // Verify the finding exists in the caller's tenant. We also need the
    // severity now (M1.7) to decide whether the grant is born pending. We
    // capture severity at grant-creation time so a later severity downgrade
    // can't bypass the two-person rule retroactively.
    const found = await withTenant(tenantId, async (tx) =>
      tx
        .select({ id: findingsTable.id, severity: findingsTable.severity })
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
    const requiresSecondApproval = found[0]!.severity === "critical";

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
          requiresSecondApproval,
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
        finding_severity: found[0]!.severity,
        justification: parsed.data.justification,
        ttl_seconds: ttl,
        expires_at: expiresAt.toISOString(),
        step_up_reason: req.stepUp!.reason,
        requires_second_approval: requiresSecondApproval,
      },
    });
    req.log.warn(
      {
        grant_id: id,
        finding_id: parsed.data.finding_id,
        seq: led.seq,
        requires_second_approval: requiresSecondApproval,
      },
      "break-glass grant issued",
    );
    res.status(201).json(grantToApi(row!));
  },
);

// M1.7: approve a pending two-person grant. Must be a *different* user in
// the same tenant, with a fresh step-up. We deliberately allow approval
// across users with the same `tenant_id` only — cross-tenant approval is
// impossible because RLS would hide the row.
router.post(
  "/admin/break-glass/grants/:id/approve",
  requireSession,
  requireStepUp,
  async (req, res): Promise<void> => {
    const parsed = ApproveGrantBody.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const tenantId = req.session!.tenant_id;
    const approverId = req.session!.sub;
    const grantId = String(req.params.id);

    // Boundary scan on approval note — same rationale as justification.
    const av = validateLedgerSafeText(parsed.data.approval_note);
    if (!av.ok) {
      await appendLedger({
        tenantId,
        actor: { kind: "human", id: approverId },
        eventType: "policy.text_field_rejected",
        payload: {
          endpoint: "POST /admin/break-glass/grants/:id/approve",
          field: "approval_note",
          reason: av.reason,
          detectors: av.detectors,
          grant_id: grantId,
        },
      });
      res.status(400).json({
        error: "approval_note rejected by content policy",
        reason: av.reason,
      });
      return;
    }

    // Load the grant. We do the self-approval + state checks in app code so
    // we can return precise errors and ledger the denial.
    const [grant] = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(breakGlassGrantsTable)
        .where(
          and(
            eq(breakGlassGrantsTable.id, grantId),
            eq(breakGlassGrantsTable.tenantId, tenantId),
          ),
        )
        .limit(1),
    );
    if (!grant) {
      res.status(404).json({ error: "grant not found" });
      return;
    }
    if (!grant.requiresSecondApproval) {
      res.status(400).json({
        error: "grant does not require second approval",
      });
      return;
    }
    if (grant.approverUserId !== null) {
      res.status(409).json({ error: "grant already approved" });
      return;
    }
    if (grant.revokedAt !== null) {
      res.status(410).json({ error: "grant revoked" });
      return;
    }
    if (grant.expiresAt.getTime() <= Date.now()) {
      res.status(410).json({ error: "grant expired" });
      return;
    }
    if (grant.userId === approverId) {
      // Self-approval is the central threat. Ledger it as its own event so
      // an auditor reviewing break-glass activity sees the attempt even
      // though no raw PHI was disclosed.
      await appendLedger({
        tenantId,
        actor: { kind: "human", id: approverId },
        eventType: "break_glass.approval_denied_self_approval",
        subjectType: "finding",
        subjectId: grant.findingId,
        payload: {
          grant_id: grant.id,
          finding_id: grant.findingId,
          requester_id: grant.userId,
          approver_id: approverId,
        },
      });
      res.status(403).json({
        error: "self-approval is not permitted on two-person grants",
      });
      return;
    }

    const approvedAt = new Date();
    const [updated] = await withTenant(tenantId, async (tx) =>
      tx
        .update(breakGlassGrantsTable)
        .set({
          approverUserId: approverId,
          approvedAt,
          approverStepUpReason: req.stepUp!.reason,
        })
        .where(
          and(
            eq(breakGlassGrantsTable.id, grantId),
            eq(breakGlassGrantsTable.tenantId, tenantId),
            // Compare-and-swap: only flip if still pending. Defense against a
            // double-approve race with two simultaneous approvers (both pass
            // the earlier read, only one wins the UPDATE).
            isNull(breakGlassGrantsTable.approverUserId),
          ),
        )
        .returning(),
    );
    if (!updated) {
      res.status(409).json({ error: "grant already approved" });
      return;
    }

    const led = await appendLedger({
      tenantId,
      actor: { kind: "human", id: approverId },
      eventType: "break_glass.approved",
      subjectType: "finding",
      subjectId: grant.findingId,
      payload: {
        grant_id: grant.id,
        finding_id: grant.findingId,
        requester_id: grant.userId,
        approver_id: approverId,
        approval_note: parsed.data.approval_note,
        approver_step_up_reason: req.stepUp!.reason,
      },
    });
    req.log.warn(
      {
        grant_id: grant.id,
        finding_id: grant.findingId,
        requester_id: grant.userId,
        approver_id: approverId,
        seq: led.seq,
      },
      "break-glass grant approved (two-person rule)",
    );
    res.json(grantToApi(updated));
  },
);

// Revoke a break-glass grant before its TTL elapses. Until now the only way
// to end a grant early was to wait out its (max 15-minute) TTL or write
// `revoked_at` directly in the DB. This endpoint closes the loop on the
// threat model's "MUST auto-revoke / be revocable" requirement: an analyst
// (the requester) or an operator (any other analyst in the same tenant) can
// immediately cut off raw-PHI access if a grant was issued in error or the
// incident is resolved.
//
// Requires session + step-up — ending an authorization is itself a
// privileged action, and keeping the same auth scope as grant/approve means
// a hijacked session without a fresh second factor cannot tamper with the
// grant lifecycle. Tenant-scoped via `withTenant` so cross-tenant rows are
// invisible (RLS) and unrevokable. Revocation is a compare-and-swap on
// `revoked_at IS NULL` so two concurrent revokes can't double-ledger, and the
// already-revoked / expired terminal states return 409 / 410 respectively,
// mirroring the approve route's terminal branches. Ledgered
// `break_glass.revoked`.
router.post(
  "/admin/break-glass/grants/:id/revoke",
  requireSession,
  requireStepUp,
  async (req, res): Promise<void> => {
    const parsed = RevokeGrantBody.safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const grantId = String(req.params.id);

    // Boundary scan on the optional reason — same rationale as justification /
    // approval_note: it lands in the immutable ledger payload, so refuse and
    // ledger any text that scans as PHI/secrets or carries the canary token.
    if (parsed.data.reason !== undefined) {
      const rv = validateLedgerSafeText(parsed.data.reason);
      if (!rv.ok) {
        await appendLedger({
          tenantId,
          actor: { kind: "human", id: userId },
          eventType: "policy.text_field_rejected",
          payload: {
            endpoint: "POST /admin/break-glass/grants/:id/revoke",
            field: "reason",
            reason: rv.reason,
            detectors: rv.detectors,
            grant_id: grantId,
          },
        });
        res.status(400).json({
          error: "reason rejected by content policy",
          reason: rv.reason,
        });
        return;
      }
    }

    const [grant] = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(breakGlassGrantsTable)
        .where(
          and(
            eq(breakGlassGrantsTable.id, grantId),
            eq(breakGlassGrantsTable.tenantId, tenantId),
          ),
        )
        .limit(1),
    );
    if (!grant) {
      res.status(404).json({ error: "grant not found" });
      return;
    }
    if (grant.revokedAt !== null) {
      res.status(409).json({ error: "grant already revoked" });
      return;
    }
    if (grant.expiresAt.getTime() <= Date.now()) {
      // Already terminal — nothing left to cut off.
      res.status(410).json({ error: "grant expired" });
      return;
    }

    const revokedAt = new Date();
    const [updated] = await withTenant(tenantId, async (tx) =>
      tx
        .update(breakGlassGrantsTable)
        .set({ revokedAt })
        .where(
          and(
            eq(breakGlassGrantsTable.id, grantId),
            eq(breakGlassGrantsTable.tenantId, tenantId),
            // Compare-and-swap: only revoke if still un-revoked. Defends
            // against two concurrent revokes both passing the read above.
            isNull(breakGlassGrantsTable.revokedAt),
          ),
        )
        .returning(),
    );
    if (!updated) {
      res.status(409).json({ error: "grant already revoked" });
      return;
    }

    const led = await appendLedger({
      tenantId,
      actor: { kind: "human", id: userId },
      eventType: "break_glass.revoked",
      subjectType: "finding",
      subjectId: grant.findingId,
      payload: {
        grant_id: grant.id,
        finding_id: grant.findingId,
        requester_id: grant.userId,
        revoked_by: userId,
        // Distinguish self-revoke (requester withdrawing their own grant) from
        // operator revoke (a different analyst cutting it off) for audit.
        self_revoke: grant.userId === userId,
        step_up_reason: req.stepUp!.reason,
        ...(parsed.data.reason !== undefined
          ? { reason: parsed.data.reason }
          : {}),
      },
    });
    req.log.warn(
      {
        grant_id: grant.id,
        finding_id: grant.findingId,
        requester_id: grant.userId,
        revoked_by: userId,
        seq: led.seq,
      },
      "break-glass grant revoked",
    );
    res.json(grantToApi(updated));
  },
);

// Resolve / close a finding. When a finding moves to a resolved or
// false_positive state, any active break-glass grants for it are auto-revoked
// (see lib/finding-status.ts) so raw-PHI access ends with the incident instead
// of lingering until each grant's TTL elapses. Idempotent: re-resolving a
// finding that is already in the target state is a no-op (no duplicate ledger
// entry, no re-revoke). Requires session only — closing a finding is routine
// triage, not a raw-PHI action; the auto-revoke it triggers only ever *reduces*
// access. Tenant-scoped via the finding existence check + RLS in the helper.
router.post(
  "/admin/findings/:id/resolve",
  requireSession,
  async (req, res): Promise<void> => {
    const parsed = ResolveFindingBody.safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const findingId = String(req.params.id);

    const found = await withTenant(tenantId, async (tx) =>
      tx
        .select({ id: findingsTable.id })
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

    const result = await resolveFinding({
      tenantId,
      findingId,
      status: parsed.data.status,
      actor: { kind: "human", id: userId },
    });
    if (result.transitioned) {
      req.log.warn(
        {
          finding_id: findingId,
          status: parsed.data.status,
          revoked_grants: result.revokedGrants,
        },
        "finding resolved; active break-glass grants auto-revoked",
      );
    }
    res.json({
      finding_id: findingId,
      status: parsed.data.status,
      transitioned: result.transitioned,
      revoked_grants: result.revokedGrants,
    });
  },
);

// Reopen a finding that was closed in error. Transitions a resolved /
// false_positive finding back to "open". Unlike resolve, reopening does NOT
// touch break-glass access — auto-revoke is an exposure-reducing side effect of
// closing an incident, and reopening is the opposite transition. Idempotent:
// reopening a finding that is already open is a no-op (no duplicate ledger
// entry). Requires session only — like resolve, this is routine triage.
// Tenant-scoped via the finding existence check + RLS in the helper.
router.post(
  "/admin/findings/:id/reopen",
  requireSession,
  async (req, res): Promise<void> => {
    const parsed = ReopenFindingBody.safeParse(req.body ?? {});
    if (!parsed.success) {
      res.status(400).json({ error: parsed.error.message });
      return;
    }
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const findingId = String(req.params.id);

    // Boundary scan on the optional reason — same rationale as resolve/revoke
    // justifications: it lands in the immutable ledger payload, so refuse and
    // ledger any text that scans as PHI/secrets or carries the canary token.
    if (parsed.data.reason !== undefined) {
      const rv = validateLedgerSafeText(parsed.data.reason);
      if (!rv.ok) {
        await appendLedger({
          tenantId,
          actor: { kind: "human", id: userId },
          eventType: "policy.text_field_rejected",
          subjectType: "finding",
          subjectId: findingId,
          payload: {
            endpoint: "POST /admin/findings/:id/reopen",
            field: "reason",
            reason: rv.reason,
            detectors: rv.detectors,
          },
        });
        res.status(400).json({
          error: "reason rejected by content policy",
          reason: rv.reason,
        });
        return;
      }
    }

    const found = await withTenant(tenantId, async (tx) =>
      tx
        .select({ id: findingsTable.id })
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

    const result = await reopenFinding({
      tenantId,
      findingId,
      actor: { kind: "human", id: userId },
      reason: parsed.data.reason,
    });
    if (result.transitioned) {
      req.log.info({ finding_id: findingId }, "finding reopened");
    }
    res.json({
      finding_id: findingId,
      status: "open",
      transitioned: result.transitioned,
    });
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

// M1.7: list grants pending second-approval that the caller is eligible to
// approve (i.e. requester is NOT the caller, in the same tenant, not yet
// approved/revoked/expired). The approver dashboard polls this.
router.get(
  "/admin/break-glass/pending-approvals",
  requireSession,
  async (req, res): Promise<void> => {
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const now = new Date();
    const rows = await withTenant(tenantId, async (tx) =>
      tx
        .select()
        .from(breakGlassGrantsTable)
        .where(
          and(
            eq(breakGlassGrantsTable.tenantId, tenantId),
            eq(breakGlassGrantsTable.requiresSecondApproval, true),
            isNull(breakGlassGrantsTable.approverUserId),
            isNull(breakGlassGrantsTable.revokedAt),
            gt(breakGlassGrantsTable.expiresAt, now),
          ),
        )
        .orderBy(desc(breakGlassGrantsTable.grantedAt))
        .limit(50),
    );
    // Filter out the caller's own grants in app code — the requester cannot
    // approve their own. (Doing it here keeps the index hit clean.)
    res.json(rows.filter((g) => g.userId !== userId).map(grantToApi));
  },
);

// Read raw evidence. Requires (a) an active grant for (tenant, user,
// finding_id), and (b) ledgers EVERY access. Returns the raw evidence
// payload if present; if no raw payload exists (most findings in dev), the
// gate still operates and the ledger still records the access, but the
// response carries `raw_evidence: null` plus a marker. This is intentional:
// the security guarantee (justification + ledger trail) does not depend on
// the existence of raw payload.
//
// M1.7: critical findings additionally require `approver_user_id IS NOT
// NULL` — the two-person approval. A pending grant gates the read with
// 403 `approval_required: true`.
router.get(
  "/admin/findings/:id/raw",
  requireSession,
  async (req, res): Promise<void> => {
    const tenantId = req.session!.tenant_id;
    const userId = req.session!.sub;
    const findingId = String(req.params.id);

    const now = new Date();
    // We look up the most-recent unrevoked unexpired grant for this user +
    // finding without filtering on `approver_user_id` so we can distinguish
    // "no grant at all" (403 step_up_required path) from "grant exists but
    // is pending approval" (403 approval_required path).
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
    if (grant.requiresSecondApproval && grant.approverUserId === null) {
      res.status(403).json({
        error: "grant pending second-person approval",
        approval_required: true,
        grant_id: grant.id,
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

    // Resolve the raw evidence through the shared seam (M10.2/M10.3). Order is
    // EXTERNAL ref first, then the legacy inline `raw_evidence` column as a
    // read-fallback (non-destructive migration keeps the inline column for at
    // least one release cycle), so a mixed-state row survives an external store
    // outage / misconfig instead of failing closed. `raw_unresolved` is surfaced
    // HONESTLY only when raw was expected but could not be produced (no inline
    // fallback available). See resolveRawEvidence() for the full branch matrix.
    const rawStore = getRawEvidenceStoreOrNull();
    const resolution = await resolveRawEvidence({
      rawEvidence: f.rawEvidence,
      rawEvidenceRef: f.rawEvidenceRef,
      tenantId,
      store: rawStore,
    });
    const rawEvidence = resolution.rawEvidence;
    const rawUnresolved = resolution.rawUnresolved;
    const rawPresent = resolution.rawPresent;
    if (resolution.rawUnresolved !== undefined) {
      req.log.error(
        { finding_id: findingId, reason: resolution.rawUnresolved },
        "break-glass: raw evidence unresolved",
      );
    } else if (resolution.fallbackUsed) {
      req.log.warn(
        { finding_id: findingId },
        "break-glass: external raw resolution failed; served legacy inline fallback",
      );
    }

    // Ledger the access. Severity is "high" by convention so a verification
    // dashboard can highlight every raw-PHI read. Ledgered BEFORE the response
    // is built so the audit entry exists even if resolution failed — the
    // attempt itself is the auditable event, not the successful disclosure.
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
        raw_present: rawPresent,
        // Provider name only (no PHI) — records WHERE the raw actually came
        // from (an inline fallback after an external miss records "database").
        raw_source: resolution.rawSource,
        raw_resolved: rawUnresolved === undefined,
        // True when raw was served from the legacy inline column because the
        // external ref could not be resolved (mixed-state migration row).
        raw_fallback_used: resolution.fallbackUsed,
        two_person_approved: grant.requiresSecondApproval,
        approver_user_id: grant.approverUserId,
      },
    });
    req.log.warn(
      {
        grant_id: grant.id,
        finding_id: findingId,
        seq: led.seq,
        raw_present: rawPresent,
        raw_resolved: rawUnresolved === undefined,
        two_person_approved: grant.requiresSecondApproval,
      },
      "raw PHI accessed via break-glass",
    );

    // Degraded durable-read alert. When the external WORM ref could not be
    // resolved and the legacy inline copy was served instead, the read still
    // succeeded but the durable tier is failing READS — an operationally
    // distinct, alertable condition (see ALERT_RULES). Ledgered as its OWN
    // event so it routes through the channel router at `high`, rather than
    // being buried in the per-read `raw_phi_accessed` warning. Payload is
    // finding id + store name + reason only — never raw PHI (the fallback
    // reason names a failure mode, not the payload).
    if (resolution.fallbackUsed) {
      await appendLedger({
        tenantId,
        actor: { kind: "system", id: "break-glass" },
        eventType: "break_glass.raw_fallback_used",
        subjectType: "finding",
        subjectId: findingId,
        payload: {
          finding_id: findingId,
          store: rawStore?.name ?? null,
          reason: resolution.fallbackReason ?? "external resolution failed",
        },
      });
    }

    res.json({
      finding_id: f.id,
      grant_id: grant.id,
      grant_expires_at: grant.expiresAt.toISOString(),
      classification: f.classification,
      severity: f.severity,
      raw_evidence: rawEvidence,
      ...(rawUnresolved !== undefined ? { raw_unresolved: rawUnresolved } : {}),
      two_person_approved: grant.requiresSecondApproval,
      approver_user_id: grant.approverUserId,
    });
  },
);

export default router;
// keep sql import used to silence ts-noUnused (reserved for future query)
void sql;
