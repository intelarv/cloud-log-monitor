import { Router, type IRouter } from "express";
import { asc, desc, gt } from "drizzle-orm";
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
  const rows = await db
    .select()
    .from(ledgerEntriesTable)
    .where(gt(ledgerEntriesTable.seq, Number.isFinite(afterSeq) ? afterSeq : 0))
    .orderBy(asc(ledgerEntriesTable.seq))
    .limit(limit);
  const [head] = await db
    .select()
    .from(ledgerEntriesTable)
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

export default router;
