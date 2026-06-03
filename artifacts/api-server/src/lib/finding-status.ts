import { and, eq, gt, isNull, ne } from "drizzle-orm";
import {
  breakGlassGrantsTable,
  findingsTable,
  findingSafeColumns,
  type Actor,
} from "@workspace/db";
import { withTenant } from "./db-context";
import { appendLedger } from "./ledger";

// Task: automatically end emergency (break-glass) access when its finding is
// resolved.
//
// Break-glass grants are per-finding and time-boxed, but until now they stayed
// live until their (max 15-min) TTL elapsed or someone manually revoked them —
// even after the underlying finding was already closed. That leaves a raw-PHI
// exposure window open for no operational reason. Auto-revoking a finding's
// active grants the moment it transitions to a resolved/closed state shrinks
// that window without relying on an analyst remembering to revoke, and keeps
// the threat-model guarantee that raw-PHI access is minimized to exactly the
// time it is needed.
//
// The auto-revoke reuses the existing `break_glass.revoked` ledger event so it
// flows through the same audit/alerting path as a manual revoke, but records a
// distinct system actor + `reason: "finding_resolved"` (and `auto_revoked:
// true`) so an auditor can tell an automatic revoke apart from an analyst /
// operator revoke.

/** The "closed" finding states that should end any active break-glass access. */
export const RESOLVED_FINDING_STATUSES = ["resolved", "false_positive"] as const;
export type ResolvedFindingStatus =
  (typeof RESOLVED_FINDING_STATUSES)[number];

/** System actor recorded on auto-revokes triggered by a finding resolution.
 *  Distinct from the human actor on a manual revoke so the ledger trail is
 *  unambiguous about WHY each grant ended. */
export const FINDING_RESOLVER_ACTOR: Actor = {
  kind: "system",
  id: "finding-resolver",
};

/** Reason recorded in the auto-revoke ledger payload. */
export const FINDING_RESOLVED_REVOKE_REASON = "finding_resolved";

/**
 * Revoke every active (un-revoked, un-expired) break-glass grant for a finding,
 * ledgering `break_glass.revoked` per grant. Each revoke is a compare-and-swap
 * on `revoked_at IS NULL`, so a grant that a concurrent manual revoke already
 * claimed is skipped (not double-ledgered). Returns the number of grants this
 * call actually revoked.
 */
export async function revokeActiveGrantsForFinding(args: {
  tenantId: string;
  findingId: string;
  actor: Actor;
  reason: string;
}): Promise<number> {
  const { tenantId, findingId, actor, reason } = args;
  const now = new Date();

  const active = await withTenant(tenantId, async (tx) =>
    tx
      .select()
      .from(breakGlassGrantsTable)
      .where(
        and(
          eq(breakGlassGrantsTable.tenantId, tenantId),
          eq(breakGlassGrantsTable.findingId, findingId),
          isNull(breakGlassGrantsTable.revokedAt),
          gt(breakGlassGrantsTable.expiresAt, now),
        ),
      ),
  );

  let revoked = 0;
  for (const grant of active) {
    const [updated] = await withTenant(tenantId, async (tx) =>
      tx
        .update(breakGlassGrantsTable)
        .set({ revokedAt: new Date() })
        .where(
          and(
            eq(breakGlassGrantsTable.id, grant.id),
            eq(breakGlassGrantsTable.tenantId, tenantId),
            // CAS: only this call revokes the grant; a concurrent manual revoke
            // that already won leaves nothing to do here.
            isNull(breakGlassGrantsTable.revokedAt),
          ),
        )
        .returning(),
    );
    if (!updated) continue;
    revoked += 1;
    await appendLedger({
      tenantId,
      actor,
      eventType: "break_glass.revoked",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        grant_id: grant.id,
        finding_id: findingId,
        requester_id: grant.userId,
        revoked_by: actor.id,
        // Distinguishes an automatic, finding-resolution-driven revoke from a
        // human-initiated one (which carries `self_revoke` + a step-up reason).
        auto_revoked: true,
        reason,
      },
    });
  }
  return revoked;
}

/**
 * Transition a finding to a resolved/closed state and end any active break-glass
 * access for it. The status update is a compare-and-swap (`status != target`)
 * so a repeated resolve is idempotent — no duplicate `finding.resolved` ledger
 * entry and no re-revoke pass. On a real transition we ledger `finding.resolved`
 * (the human/agent actor that resolved it) and then auto-revoke the finding's
 * active grants under the system actor + `finding_resolved` reason.
 */
export async function resolveFinding(args: {
  tenantId: string;
  findingId: string;
  status: ResolvedFindingStatus;
  actor: Actor;
}): Promise<{ transitioned: boolean; revokedGrants: number }> {
  const { tenantId, findingId, status, actor } = args;

  const [updated] = await withTenant(tenantId, async (tx) =>
    tx
      .update(findingsTable)
      .set({ status })
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, tenantId),
          ne(findingsTable.status, status),
        ),
      )
      .returning(findingSafeColumns),
  );

  if (!updated) {
    // Already in the target state (or no such finding in this tenant) — nothing
    // transitioned, so there is nothing new to revoke or ledger.
    return { transitioned: false, revokedGrants: 0 };
  }

  await appendLedger({
    tenantId,
    actor,
    eventType: "finding.resolved",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      status,
    },
  });

  const revokedGrants = await revokeActiveGrantsForFinding({
    tenantId,
    findingId,
    actor: FINDING_RESOLVER_ACTOR,
    reason: FINDING_RESOLVED_REVOKE_REASON,
  });

  return { transitioned: true, revokedGrants };
}

/**
 * Reopen a previously closed finding by transitioning it back to "open". This
 * is the inverse of {@link resolveFinding} for a finding that was closed in
 * error. Like resolve, the status update is a compare-and-swap (`status !=
 * "open"`) so reopening a finding that is already open is idempotent — no
 * duplicate `finding.reopened` ledger entry.
 *
 * Crucially, reopening does NOT auto-revoke break-glass grants. Auto-revoke is
 * an exposure-*reducing* side effect tied to closing an incident; reopening is
 * the opposite transition and must not touch raw-PHI access. A real transition
 * ledgers `finding.reopened` under the human/agent actor that reopened it,
 * optionally capturing a free-text `reason` (caller is responsible for content-
 * policy scanning it before this point — see `routes/admin.ts`).
 */
export async function reopenFinding(args: {
  tenantId: string;
  findingId: string;
  actor: Actor;
  reason?: string;
}): Promise<{ transitioned: boolean }> {
  const { tenantId, findingId, actor, reason } = args;

  const [updated] = await withTenant(tenantId, async (tx) =>
    tx
      .update(findingsTable)
      .set({ status: "open" })
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, tenantId),
          ne(findingsTable.status, "open"),
        ),
      )
      .returning(findingSafeColumns),
  );

  if (!updated) {
    // Already open (or no such finding in this tenant) — nothing transitioned,
    // so there is nothing new to ledger.
    return { transitioned: false };
  }

  await appendLedger({
    tenantId,
    actor,
    eventType: "finding.reopened",
    subjectType: "finding",
    subjectId: findingId,
    payload: {
      finding_id: findingId,
      status: "open",
      ...(reason !== undefined ? { reason } : {}),
    },
  });

  return { transitioned: true };
}
