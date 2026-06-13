import { Router, type IRouter } from "express";
import { and, asc, desc, eq, gt, inArray, sql } from "drizzle-orm";
import {
  db,
  ledgerEntriesTable,
  ledgerCheckpointsTable,
  GENESIS_PREV_HASH,
} from "@workspace/db";
import {
  ListLedgerResponse as LedgerPage,
  VerifyLedgerResponse as LedgerVerifyResult,
} from "@workspace/api-zod";
import { verifyChain } from "../lib/ledger";
import { verifyCheckpoints } from "../lib/notarization";
import { requireSession } from "../lib/auth";

const router: IRouter = Router();

router.get("/ledger", requireSession, async (req, res): Promise<void> => {
  const afterSeq = req.query.after_seq ? Number(req.query.after_seq) : 0;
  const limit = req.query.limit
    ? Math.min(Math.max(Number(req.query.limit), 1), 500)
    : 100;
  // M12.4 (cross-tenant escalation guard): the in-app ledger *view* is scoped
  // to the caller's tenant. `ledger_entries` is a single global hash chain with
  // NO RLS policy (the chain verifier + notarizer must walk every tenant's
  // entries to prove integrity — that path stays global by design), so we
  // enforce isolation here with an explicit `tenant_id` predicate. Entry
  // payloads carry tenant-private free text (break-glass justification /
  // approval_note / revoke reason), so an unscoped list would leak another
  // tenant's operational audit trail. `head` is likewise the caller-tenant
  // head, so the response never exposes the global cross-tenant event count.
  const tenantId = req.session!.tenant_id;
  // `actor` pivots the list to a single human actor's full trail ("show me
  // everything this analyst did"). Filtering server-side — instead of in the
  // client over a recent window — is what makes the trail complete for a busy
  // or long-lived actor. The `actor` jsonb column carries `{kind,id,...}`; we
  // match human actors by id so agent/system rows never collide with a human id.
  const actor =
    typeof req.query.actor === "string" && req.query.actor.length > 0
      ? req.query.actor
      : null;
  const actorPredicate = actor
    ? sql`${ledgerEntriesTable.actor}->>'kind' = 'human' and ${ledgerEntriesTable.actor}->>'id' = ${actor}`
    : undefined;
  const rows = await db
    .select()
    .from(ledgerEntriesTable)
    .where(
      and(
        eq(ledgerEntriesTable.tenantId, tenantId),
        gt(ledgerEntriesTable.seq, Number.isFinite(afterSeq) ? afterSeq : 0),
        actorPredicate,
      ),
    )
    .orderBy(asc(ledgerEntriesTable.seq))
    .limit(limit);
  const [head] = await db
    .select()
    .from(ledgerEntriesTable)
    .where(eq(ledgerEntriesTable.tenantId, tenantId))
    .orderBy(desc(ledgerEntriesTable.seq))
    .limit(1);
  res.json(
    LedgerPage.parse({
      entries: rows.map((r) => ({
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
      head_seq: head?.seq ?? 0,
      head_hash: head?.hash ?? GENESIS_PREV_HASH,
    }),
  );
});

router.get("/admin/ledger/verify", requireSession, async (_req, res): Promise<void> => {
  const result = await verifyChain();
  res.json(LedgerVerifyResult.parse(result));
});

// M2: list external notarization checkpoints. Audit surface — an external
// auditor compares these against an independently-retained copy from the
// separate trust zone (in production: the WORM bucket in the notarization
// account). `verify` flag also runs the live cross-check so the response
// answers both "what checkpoints exist" and "do they still match the
// ledger" in one call. No PHI involved; session-gated like /ledger.
router.get(
  "/admin/ledger/checkpoints",
  requireSession,
  async (req, res): Promise<void> => {
    const limit = req.query.limit
      ? Math.min(Math.max(Number(req.query.limit), 1), 500)
      : 100;
    const rows = await db
      .select()
      .from(ledgerCheckpointsTable)
      .orderBy(desc(ledgerCheckpointsTable.seq))
      .limit(limit);
    const verify =
      req.query.verify === "1" || req.query.verify === "true"
        ? await verifyCheckpoints()
        : null;
    res.json({
      checkpoints: rows.map((r) => ({
        id: r.id,
        seq: r.seq,
        head_hash: r.headHash,
        notarized_at: r.notarizedAt.toISOString(),
        signature: r.signature,
        signing_key_id: r.signingKeyId,
      })),
      verify,
    });
  },
);

// M10.6: read-only activity counts for the two opt-in cache-pruning jobs
// (M10.4 raw-evidence tiering, M10.5 memory eviction). Both are default-inert,
// so on an untuned deployment every count is simply 0 — the panel still tells
// an operator "the jobs have never run here", which is the honest answer. Like
// the ledger list above, this is scoped to the caller's tenant by an explicit
// `tenant_id` predicate (the ledger has no RLS — the verifier walks it
// globally). The aggregated payloads carry only counts + provider names, never
// finding ids or object URIs, so nothing PHI-adjacent crosses the boundary.
const MAINTENANCE_EVENT_TYPES = [
  "memory.evicted",
  "memory.evict_failed",
  "raw_evidence.tiered",
  "raw_evidence.tier_failed",
] as const;

function laterIso(a: unknown, b: unknown): string | null {
  const da = a == null ? null : new Date(a as string | Date);
  const db_ = b == null ? null : new Date(b as string | Date);
  if (!da) return db_ ? db_.toISOString() : null;
  if (!db_) return da.toISOString();
  return (da > db_ ? da : db_).toISOString();
}

router.get(
  "/admin/metrics/maintenance",
  requireSession,
  async (req, res): Promise<void> => {
    const tenantId = req.session!.tenant_id;
    const rows = await db
      .select({
        eventType: ledgerEntriesTable.eventType,
        count: sql<number>`count(*)::int`,
        lastTs: sql<string | null>`max(${ledgerEntriesTable.ts})`,
        // Only `memory.evicted` payloads carry an `evicted` integer; the cast
        // is NULL→0 for the other event types, so the coalesced sum is safe to
        // run across the whole grouped set.
        evictedSum: sql<number>`coalesce(sum((${ledgerEntriesTable.payload}->>'evicted')::int), 0)::int`,
      })
      .from(ledgerEntriesTable)
      .where(
        and(
          eq(ledgerEntriesTable.tenantId, tenantId),
          inArray(ledgerEntriesTable.eventType, [...MAINTENANCE_EVENT_TYPES]),
        ),
      )
      .groupBy(ledgerEntriesTable.eventType);

    const byType = new Map(rows.map((r) => [r.eventType, r]));
    const memEvicted = byType.get("memory.evicted");
    const memFailed = byType.get("memory.evict_failed");
    const tiered = byType.get("raw_evidence.tiered");
    const tierFailed = byType.get("raw_evidence.tier_failed");

    // Returned plain (not via the generated Zod response schema): that schema
    // models `last_run_at` as `union([coerce.date(), null])`, and
    // `coerce.date()` greedily coerces `null` → `new Date(null)` (epoch 0), so
    // parsing would silently rewrite a genuine "never run" null into
    // 1970-01-01. The notarization-checkpoints route above skips the parse for
    // the same reason; the response shape is covered by the route test instead.
    res.json({
      memory: {
        runs: memEvicted?.count ?? 0,
        embeddings_evicted: memEvicted?.evictedSum ?? 0,
        failures: memFailed?.count ?? 0,
        last_run_at: laterIso(memEvicted?.lastTs, memFailed?.lastTs),
      },
      tiering: {
        findings_tiered: tiered?.count ?? 0,
        failures: tierFailed?.count ?? 0,
        last_run_at: laterIso(tiered?.lastTs, tierFailed?.lastTs),
      },
    });
  },
);

export default router;
