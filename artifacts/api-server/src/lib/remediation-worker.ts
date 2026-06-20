// Executing remediation worker (Task: turn CONFIRMED proposals into actions).
//
// The HITL plane writes a proposal (PENDING), a human confirms it (CONFIRMED).
// Historically that was the end of the line in-system. This worker is the
// OPT-IN bridge from authorized→acted-on: when an operator selects a
// `RemediationExecutor` via `REMEDIATION_EXECUTOR`, this worker polls CONFIRMED
// rows and drives each one through:
//
//   confirmed --CAS--> executing --(executor.execute)--> executed
//                                \--(ok:false / throw)--> execution_failed
//
// Safety properties:
//   - Leader lock: a single pg advisory lock (distinct key) means at most one
//     instance executes per cadence across a multi-replica deployment, so the
//     executor is never invoked twice concurrently for the same row.
//   - CAS everywhere: confirmed→executing and executing→executed|failed are
//     `UPDATE ... WHERE status = <prior> RETURNING`, so a row claimed by one
//     pass cannot be re-claimed; a crash mid-execute leaves the row `executing`
//     (visible/operable, surfaced in the list UI) rather than silently lost.
//   - Idempotency: a claimed row records executed_at + external_ref on success;
//     the poll only ever selects status='confirmed', so an executed row is never
//     re-acted-on (ARCHITECTURE.md §23.22).
//   - PHI posture: only the redacted, already-PHI-scanned summary/rationale + ids
//     reach the executor; the ledger payload carries ids + action_type +
//     executor_kind + a STATIC reason only — never raw error text or evidence.
//   - Default-inert: `executor === null` (REMEDIATION_EXECUTOR unset/none) ⇒ the
//     worker is never scheduled, no rows move, the eval gate stays byte-identical.
//
// Cross-tenant scan mirrors raw-evidence-tiering / memory-eviction: enumerate
// tenants with a raw `SELECT DISTINCT tenant_id` (the maintenance role), then do
// every read + write inside `withTenant()` so RLS stays enforced per tenant.

import { sql } from "drizzle-orm";
import { db, pool, remediationProposalsTable } from "@workspace/db";
import { logger } from "./logger";
import { appendLedger } from "./ledger";
import { withTenant } from "./db-context";
import { validateLedgerSafeText } from "./text-policy";
import type { WorkflowEngine } from "./agents/workflow-engine";
import {
  buildRemediationExecutorFromEnv,
  type RemediationExecutor,
  type RemediationExecutionInput,
} from "./remediation-executor";

// Distinct from LEDGER_LOCK_KEY (ledger.ts) and the chain-verifier LOCK_KEYS
// (chain-verifier.ts) — single 64-bit advisory keyspace, arbitrary fixed value.
const REMEDIATION_WORKER_LOCK_KEY = 7331_4242_0000_0020n;

// In-process tick cadence + Temporal cron. The poller is cheap (indexed
// tenant+status scan, bounded batch), so a short cadence keeps confirmed→executed
// latency low without load concern. Temporal uses the cron; in-process the ms.
const DEFAULT_INTERVAL_MS = 60_000;
const REMEDIATION_WORKER_CRON = "* * * * *";

// Max proposals executed per tenant per tick — bounds executor I/O / blast
// radius on a backlog, exactly like the tiering/eviction sweeps.
const DEFAULT_BATCH_PER_TENANT = 25;

// A row sits in `executing` only for the brief window between its claim CAS and
// its terminal CAS. If a worker crashes (or its DB/ledger write fails) in that
// window the row is stranded `executing` forever — the poll only ever scans
// `confirmed`. Before each claim we reset rows that have been `executing` longer
// than this threshold back to `confirmed` so the next claim retries them. This
// is at-least-once recovery and is only safe because the `RemediationExecutor`
// contract requires idempotent `execute()`; the threshold is far longer than any
// real execution so an in-flight row is never reset out from under a live run.
const STALE_EXECUTING_MS = 10 * 60_000;

// Bound on the executor-supplied failure reason persisted to `execution_error`.
// The reason is operator-facing (surfaced in the list UI) but executor-authored,
// so it is untrusted: truncate it and PHI/secret/canary-scan it before it lands
// in the DB or any API response.
const MAX_FAILURE_REASON_LEN = 200;

/** Normalize an executor-supplied failure reason into a bounded, PHI-safe
 *  string. A real backend can return arbitrary error text that may embed PHI or
 *  secrets; truncate first, then refuse anything that scans unsafe (replacing it
 *  with a static placeholder) so `execution_error` can never become a PHI sink.
 *  The ledger already records only a static `reason` — this protects the DB
 *  column + the tenant-visible API/UI. */
function safeFailureReason(reason: string | undefined): string {
  if (!reason) return "unknown";
  const bounded = reason.slice(0, MAX_FAILURE_REASON_LEN);
  return validateLedgerSafeText(bounded).ok ? bounded : "redacted_unsafe_reason";
}

export interface RemediationWorkerOptions {
  /** Max proposals processed per tenant per tick. */
  batchPerTenant?: number;
}

/** Run the action through the executor with a bounded outcome. Any throw is
 *  normalized to a PHI-safe failure reason (the error name only — never the
 *  message, which could embed PHI from a misbehaving executor). */
async function runExecutor(
  executor: RemediationExecutor,
  input: RemediationExecutionInput,
): Promise<{ ok: boolean; externalRef?: string; reason?: string }> {
  try {
    const result = await executor.execute(input);
    if (result.ok) return { ok: true, externalRef: result.externalRef };
    return { ok: false, reason: safeFailureReason(result.reason) };
  } catch {
    // A thrown error is reduced to a single static constant — never the message
    // OR the name. `Error.name` is executor-controlled and a glued token (e.g.
    // "FailureForSSN_123-45-6789") can slip past the PHI scanner's word
    // boundaries, so the only fully-safe choice is to emit no executor-authored
    // bytes at all. The execution_failed status + alert already signal the
    // failure; richer diagnostics belong in the executor's own (trusted) logs.
    return { ok: false, reason: "executor_threw" };
  }
}

/** Execute one already-claimed (status='executing') proposal and CAS it to its
 *  terminal state with a ledger entry. Isolated per row so one failure never
 *  aborts the rest of the batch. */
async function finalizeClaimed(
  executor: RemediationExecutor,
  tenantId: string,
  row: {
    id: string;
    findingId: string;
    actionType: string;
    summary: string;
    rationale: string;
  },
): Promise<"executed" | "execution_failed"> {
  const outcome = await runExecutor(executor, {
    proposalId: row.id,
    tenantId,
    findingId: row.findingId,
    actionType: row.actionType,
    summary: row.summary,
    rationale: row.rationale,
  });

  if (outcome.ok) {
    const updated = await withTenant(tenantId, async (tx) => {
      const r = await tx.execute<{ id: string }>(sql`
        UPDATE remediation_proposals
        SET status = 'executed',
            executed_at = now(),
            external_ref = ${outcome.externalRef ?? null},
            executor_kind = ${executor.kind}
        WHERE id = ${row.id} AND status = 'executing'
        RETURNING id
      `);
      return r.rows[0];
    });
    // Only ledger if THIS pass made the transition (CAS won) — defends against a
    // double-finalize racing on the same claimed row.
    if (updated) {
      await appendLedger({
        tenantId,
        actor: { kind: "system", id: "remediation_worker" },
        eventType: "remediation.executed",
        subjectType: "finding",
        subjectId: row.findingId,
        payload: {
          proposal_id: row.id,
          finding_id: row.findingId,
          action_type: row.actionType,
          executor_kind: executor.kind,
          external_ref: outcome.externalRef ?? null,
        },
      });
    }
    return "executed";
  }

  const updated = await withTenant(tenantId, async (tx) => {
    const r = await tx.execute<{ id: string }>(sql`
      UPDATE remediation_proposals
      SET status = 'execution_failed',
          executed_at = now(),
          execution_error = ${outcome.reason ?? "unknown"},
          executor_kind = ${executor.kind}
      WHERE id = ${row.id} AND status = 'executing'
      RETURNING id
    `);
    return r.rows[0];
  });
  if (updated) {
    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "remediation_worker" },
      eventType: "remediation.execution_failed",
      subjectType: "finding",
      subjectId: row.findingId,
      payload: {
        proposal_id: row.id,
        finding_id: row.findingId,
        action_type: row.actionType,
        executor_kind: executor.kind,
        // Static, bounded reason only — the executor's failure reason is
        // recorded in execution_error (DB), never widened onto the ledger where
        // it could leak. Auditors see "it failed"; operators read the column.
        reason: "execution_failed",
      },
    });
  }
  return "execution_failed";
}

/** One sweep across all tenants: claim CONFIRMED proposals (CAS) and execute
 *  them. Leader-locked so only one instance runs the batch at a time. Returns a
 *  small summary (counts only) for logging/tests. No-op when `executor` is null
 *  (default-inert) — the public entry points never pass null, but the guard
 *  keeps the function safe to call directly in any state. */
export async function runRemediationExecutionOnce(
  executor: RemediationExecutor | null,
  opts: RemediationWorkerOptions = {},
): Promise<{ executed: number; failed: number; tenants: number }> {
  if (!executor) return { executed: 0, failed: 0, tenants: 0 };
  const batch = opts.batchPerTenant ?? DEFAULT_BATCH_PER_TENANT;

  const client = await pool.connect();
  let locked = false;
  try {
    const lockRes = await client.query<{ locked: boolean }>(
      "SELECT pg_try_advisory_lock($1) AS locked",
      [REMEDIATION_WORKER_LOCK_KEY.toString()],
    );
    locked = lockRes.rows[0]?.locked === true;
    if (!locked) {
      // Another instance holds the lock; that instance is doing the work.
      return { executed: 0, failed: 0, tenants: 0 };
    }

    // Enumerate tenants that have actionable rows: `confirmed` (to claim) OR
    // `executing` (possibly stranded by a prior crash — the per-tenant stale
    // recovery below resets those). A tenant whose only proposal is a stranded
    // `executing` row would otherwise never be scanned, so recovery would never
    // reach it.
    const tenantRows = await db.execute<{ tenant_id: string }>(
      sql`SELECT DISTINCT tenant_id FROM remediation_proposals WHERE status IN ('confirmed', 'executing')`,
    );

    let executed = 0;
    let failed = 0;
    for (const { tenant_id } of tenantRows.rows) {
      // Recover rows stranded `executing` by a prior crash/finalize failure:
      // reset them to `confirmed` (clearing the stale attempt-start time) so the
      // claim below re-picks them. Bounded by STALE_EXECUTING_MS so a row being
      // worked by a live run in this generation is never reset.
      const recovered = await withTenant(tenant_id, async (tx) => {
        const r = await tx.execute<{ id: string }>(sql`
          UPDATE remediation_proposals
          SET status = 'confirmed', executed_at = NULL, executor_kind = NULL
          WHERE tenant_id = ${tenant_id}
            AND status = 'executing'
            AND executed_at IS NOT NULL
            AND executed_at < now() - make_interval(secs => ${STALE_EXECUTING_MS / 1000})
          RETURNING id
        `);
        return r.rows;
      });
      if (recovered.length > 0) {
        logger.warn(
          { tenant_id, recovered: recovered.length },
          "reset stale 'executing' remediation proposals to 'confirmed' for retry",
        );
      }

      // Claim a bounded batch CONFIRMED→EXECUTING in one CAS statement so no
      // other pass can re-claim the same rows, then execute each outside the
      // claim so a slow executor never holds rows hostage. `executed_at` is
      // stamped here as the attempt-start marker the stale-recovery above reads;
      // the terminal CAS overwrites it with the completion time.
      const claimed = await withTenant(tenant_id, async (tx) => {
        const r = await tx.execute<{
          id: string;
          finding_id: string;
          action_type: string;
          summary: string;
          rationale: string;
        }>(sql`
          UPDATE remediation_proposals
          SET status = 'executing', executed_at = now()
          WHERE id IN (
            SELECT id FROM remediation_proposals
            WHERE tenant_id = ${tenant_id} AND status = 'confirmed'
            ORDER BY created_at ASC
            LIMIT ${batch}
            FOR UPDATE SKIP LOCKED
          )
          RETURNING id, finding_id, action_type, summary, rationale
        `);
        return r.rows;
      });

      for (const c of claimed) {
        try {
          const terminal = await finalizeClaimed(executor, tenant_id, {
            id: c.id,
            findingId: c.finding_id,
            actionType: c.action_type,
            summary: c.summary,
            rationale: c.rationale,
          });
          if (terminal === "executed") executed += 1;
          else failed += 1;
        } catch (err) {
          // A DB/ledger error finalizing one row leaves it 'executing' (operable,
          // surfaced in the UI) and must not abort the rest of the batch.
          failed += 1;
          logger.error(
            {
              error_name: err instanceof Error ? err.name : "unknown",
              tenant_id,
              proposal_id: c.id,
            },
            "remediation execution finalize failed; row left executing, will be retried operationally",
          );
        }
      }
    }

    if (executed > 0 || failed > 0) {
      logger.info(
        { executed, failed, tenants: tenantRows.rows.length },
        "remediation execution sweep complete",
      );
    }
    return { executed, failed, tenants: tenantRows.rows.length };
  } finally {
    if (locked) {
      try {
        await client.query("SELECT pg_advisory_unlock($1)", [
          REMEDIATION_WORKER_LOCK_KEY.toString(),
        ]);
      } catch {
        // If unlock fails, drop the client so the session (and its lock) is
        // reclaimed by the pool rather than reused while still holding the lock.
        client.release(true);
        return { executed: 0, failed: 0, tenants: 0 };
      }
    }
    client.release();
  }
}

/** Activity entry point for both engines: build the executor from env and run
 *  one sweep. No-op (returns early) when REMEDIATION_EXECUTOR is unset/none. */
export async function runRemediationExecutionTick(): Promise<void> {
  await runRemediationExecutionOnce(buildRemediationExecutorFromEnv());
}

/** Schedule the worker through the WorkflowEngine seam (mirrors startNotarizer /
 *  startChainVerifier). When `executor` is null the worker is NOT scheduled and
 *  this returns a no-op stop handle, so the feature is fully default-inert. */
export function startRemediationWorker(
  engine: WorkflowEngine,
  executor: RemediationExecutor | null,
  opts: RemediationWorkerOptions = {},
): () => void {
  if (!executor) {
    logger.info(
      {},
      "remediation executor unset (REMEDIATION_EXECUTOR); executing worker inert",
    );
    return () => {};
  }

  const stop = engine.schedulePeriodic({
    name: "remediation-worker",
    intervalMs: DEFAULT_INTERVAL_MS,
    cronSchedule: REMEDIATION_WORKER_CRON,
    workflowType: "remediationExecutionWorkflow",
    run: () => runRemediationExecutionOnce(executor, opts).then(() => {}),
  });

  logger.info(
    { engine: engine.kind, executor: executor.kind },
    "remediation executing worker scheduled via workflow engine",
  );
  return stop;
}
