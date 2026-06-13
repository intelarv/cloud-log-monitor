// Supervisor facade (Triage -> Verifier on every new finding).
//
// The per-finding orchestration, the in-memory queue, the per-tenant cost
// breaker, and the replayable review steps were extracted in the Temporal
// refactor so the same logic can run on either backend behind the
// `WorkflowEngine` seam:
//
//   - review-orchestration.ts — PURE step sequence (shared by both engines).
//   - review-steps.ts         — the side-effecting activity implementations.
//   - agent-budget.ts         — per-tenant LLM cost-budget breaker (M12.3).
//   - workflow-engine.ts      — the seam + in-process engine + factory.
//   - temporal-engine.ts      — default-inert Temporal adapter (opt-in).
//
// This module keeps the original public surface (`enqueueReview`,
// `startAgentSupervisor`, `maybeEnqueueReviewFromLedger`, the budget/start/stop
// test hooks) so `index.ts`, `ledger.ts`, and the existing supervisor tests are
// unchanged. All it does now is dispatch through the active engine.

import { logger } from "../logger";
import {
  getWorkflowEngine,
  initWorkflowEngineFromEnv,
  __getInProcessEngineForTest,
} from "./workflow-engine";

// Re-export the per-tenant budget test hooks from their new home so existing
// imports (`from "./supervisor"`) keep resolving.
export {
  __resetSupervisorBudgetForTest,
  __getSupervisorBudgetForTest,
  __forceBudgetExhaustForTest,
} from "./agent-budget";

/** Public: enqueue a finding for supervisor review. Fire-and-forget.
 *
 *  Called from the ledger post-commit hook on `finding.created`. Safe to call
 *  multiple times for the same finding — the CAS in the review steps (plus
 *  Temporal's workflow-id idempotency, when that engine is active) ensures the
 *  work runs exactly once. */
export function enqueueReview(findingId: string, tenantId: string): void {
  getWorkflowEngine().submitReview(findingId, tenantId);
}

/** Select the engine from `WORKFLOW_ENGINE`, start it, and return a stop fn.
 *  Mirrors the previous start/stop contract; production `index.ts` calls this
 *  once after the ingest pipeline is wired. */
export function startAgentSupervisor(): () => void {
  const engine = initWorkflowEngineFromEnv();
  void Promise.resolve(engine.start()).catch((err) => {
    // Fail-closed for the durable backend: a selected-but-unstartable Temporal
    // engine would silently drop every `finding.created` review (no worker to
    // run the workflow), which defeats the point of choosing a durable engine.
    // Crash boot instead of degrading to a review-losing state — same posture
    // as a failed DB connection. The default in-process engine's start() is
    // synchronous and cannot reject, so this branch never fires for it.
    if (engine.kind === "temporal") {
      logger.error({ err }, "temporal workflow engine failed to start; aborting boot");
      process.exit(1);
    }
    logger.error({ err }, "workflow engine failed to start");
  });
  return () => {
    void Promise.resolve(engine.stop()).catch((err) => {
      logger.error({ err }, "workflow engine failed to stop");
    });
  };
}

/** Called from `appendLedger` after a successful insert. Enqueues a supervisor
 *  review for every `finding.created` event. The supervisor's own agent.* events
 *  don't match `finding.created`, so they don't recurse. */
export function maybeEnqueueReviewFromLedger(entry: {
  eventType: string;
  subjectType: string | null;
  subjectId: string | null;
  tenantId: string | null;
}): void {
  if (entry.eventType !== "finding.created") return;
  if (entry.subjectType !== "finding") return;
  if (!entry.subjectId || !entry.tenantId) return;
  enqueueReview(entry.subjectId, entry.tenantId);
}

// ---------------------------------------------------------------------------
// Test-only lifecycle hooks. Tests run exclusively on the in-process engine;
// these resolve it and drive its start/stop/drain.
// ---------------------------------------------------------------------------

/** Test-only: explicit start used by supervisor tests; mirrors production. */
export function __startSupervisorForTest(): void {
  __getInProcessEngineForTest().start();
}
/** Test-only: stop + drain queue between tests. */
export function __stopSupervisorForTest(): void {
  __getInProcessEngineForTest().stop();
}
/** Test/shutdown helper: drain the queue. */
export async function __drainSupervisorForTest(timeoutMs = 30_000): Promise<void> {
  await __getInProcessEngineForTest().drain(timeoutMs);
}
