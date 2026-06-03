// M5: Supervisor orchestrator. Wires the multi-agent loop on every new
// finding: Triage → Verifier, with idempotency CAS, bounded concurrency,
// a daily cost-budget circuit breaker, and full ledger trails per
// ARCH §7 ("Supervisor + Specialist agents") and §23.15 (cost breaker).
//
// Architecture:
//   - On `finding.created` (ledger post-commit hook), `enqueueReview(id, tenant)`
//     is called fire-and-forget.
//   - The in-memory queue runs at most CONCURRENCY workers in parallel.
//     Demo-scale; production swaps for Temporal per ARCH §17 item 4.
//   - Each worker acquires the finding via CAS on agent_review_status
//     (pending → in_progress). A second `finding.created` for the same
//     id (e.g. a double-emit on restart) is a no-op.
//   - Both agents see only `findingSafeColumns` — rawEvidence cannot
//     reach a prompt. Defense-in-depth: the Verifier's rationale text is
//     re-scanned with scanForPhi before persist; PHI in agent output is
//     a finding-about-the-agent per threat_model §Info Disclosure.
//   - Every step ledgers agent.* events with full {agent, version,
//     model, prompt_hash} so an auditor can reconstruct exactly which
//     prompt+model produced the verdict.

import { and, eq, sql } from "drizzle-orm";
import { findingsTable, findingSafeColumns, type FindingSafe } from "@workspace/db";
import { db } from "@workspace/db";
import { withTenant } from "../db-context";
import { appendLedger } from "../ledger";
import { scanForPhi } from "../redact";
import {
  triageAgentIdentity,
  type TriageVerdict,
} from "./triage";
import {
  verifierAgentIdentity,
  type VerifierVerdict,
} from "./verifier";
import { getAgentInvoker } from "../a2a";

// Concurrency = 2 keeps the LLM cost bounded and avoids storms on bulk
// ingest replays. Production with a real queue would size this from
// per-tenant rate limits + provider quotas.
const CONCURRENCY = 2;

// Daily cost budget per process. Approximate; real billing comes from
// the provider. The point is a hard process-level kill-switch so a
// runaway loop or a malicious ingest burst cannot drain the LLM budget.
// Per ARCH §23.15 ("LLM cost circuit breaker").
// Architect-flagged M5 fix: validate the env. `Number(undefined)` is `NaN`,
// and `tokensUsed >= NaN` is always `false` — i.e. an invalid env value
// would silently DISABLE the breaker. Fall back to the default on any
// non-finite or non-positive value and log a boot warning at first read.
const DAILY_TOKEN_BUDGET = (() => {
  const raw = process.env["AGENT_DAILY_TOKEN_BUDGET"];
  if (raw === undefined) return 1_000_000;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) {
    // eslint-disable-next-line no-console
    console.warn(
      `[supervisor] AGENT_DAILY_TOKEN_BUDGET=${raw} is not a positive finite number; falling back to 1,000,000`,
    );
    return 1_000_000;
  }
  return n;
})();

interface BudgetState {
  dayKey: string;
  tokensUsed: number;
}
const budget: BudgetState = { dayKey: utcDayKey(new Date()), tokensUsed: 0 };

function utcDayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

function chargeBudget(tokens: number): void {
  const today = utcDayKey(new Date());
  if (today !== budget.dayKey) {
    budget.dayKey = today;
    budget.tokensUsed = 0;
  }
  budget.tokensUsed += tokens;
}

function budgetExceeded(): boolean {
  const today = utcDayKey(new Date());
  if (today !== budget.dayKey) {
    budget.dayKey = today;
    budget.tokensUsed = 0;
  }
  return budget.tokensUsed >= DAILY_TOKEN_BUDGET;
}

// Test-only knobs.
export function __resetSupervisorBudgetForTest(): void {
  budget.dayKey = utcDayKey(new Date());
  budget.tokensUsed = 0;
}
export function __getSupervisorBudgetForTest(): Readonly<BudgetState> {
  return { ...budget };
}
/** Test-only: jam the budget so the next review takes the skip path. */
export function __forceBudgetExhaustForTest(): void {
  budget.dayKey = utcDayKey(new Date());
  budget.tokensUsed = DAILY_TOKEN_BUDGET + 1;
}

// ---------------------------------------------------------------------------
// Queue
// ---------------------------------------------------------------------------

interface ReviewJob {
  findingId: string;
  tenantId: string;
}
const pending: ReviewJob[] = [];
let active = 0;
// Default OFF. Production `index.ts` calls `startAgentSupervisor()` after
// the ingest pipeline is wired; tests opt in per-test. This avoids the
// global-state bleed where one test's `finding.created` triggers an LLM
// call inside a later test's run and pollutes the shared dev ledger.
let stopped = true;

/** Public: enqueue a finding for supervisor review. Fire-and-forget.
 *
 *  Called from the ledger post-commit hook on `finding.created`. Safe to
 *  call multiple times for the same finding — the CAS in `reviewOne`
 *  ensures the work runs exactly once.
 */
export function enqueueReview(findingId: string, tenantId: string): void {
  if (stopped) return;
  pending.push({ findingId, tenantId });
  pump();
}

function pump(): void {
  while (active < CONCURRENCY && pending.length > 0 && !stopped) {
    const job = pending.shift()!;
    active += 1;
    void reviewOne(job).finally(() => {
      active -= 1;
      pump();
    });
  }
}

/** Test/shutdown helper: drain the queue. */
export async function __drainSupervisorForTest(timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while ((pending.length > 0 || active > 0) && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 25));
  }
}

export function startAgentSupervisor(): () => void {
  stopped = false;
  return () => {
    stopped = true;
    pending.length = 0;
  };
}

/** Test-only: explicit start used by supervisor tests; mirrors production. */
export function __startSupervisorForTest(): void {
  stopped = false;
}
/** Test-only: stop + drain queue between tests. */
export function __stopSupervisorForTest(): void {
  stopped = true;
  pending.length = 0;
}

// ---------------------------------------------------------------------------
// Per-finding orchestration
// ---------------------------------------------------------------------------

// CAS: pending → in_progress. Returns the row or null if already taken.
async function acquireFinding(
  tenantId: string,
  findingId: string,
): Promise<FindingSafe | null> {
  return withTenant(tenantId, async (tx) => {
    const updated = await tx
      .update(findingsTable)
      .set({ agentReviewStatus: "in_progress" })
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, tenantId),
          eq(findingsTable.agentReviewStatus, "pending"),
        ),
      )
      .returning(findingSafeColumns);
    return updated[0] ?? null;
  });
}

async function persistVerdicts(
  tenantId: string,
  findingId: string,
  status: "completed" | "failed" | "skipped",
  triage: TriageVerdict | null,
  verifier: VerifierVerdict | null,
): Promise<void> {
  await withTenant(tenantId, async (tx) => {
    await tx
      .update(findingsTable)
      .set({
        agentReviewStatus: status,
        triageVerdict: triage,
        verifierVerdict: verifier,
        lastAgentReviewAt: new Date(),
      })
      .where(
        and(
          eq(findingsTable.id, findingId),
          eq(findingsTable.tenantId, tenantId),
        ),
      );
  });
}

async function reviewOne(job: ReviewJob): Promise<void> {
  const { findingId, tenantId } = job;
  const finding = await acquireFinding(tenantId, findingId);
  if (!finding) {
    // Already reviewed or in progress. Idempotency win — no ledger write
    // for this silent-skip because the original `finding.created` already
    // exists in the ledger as the audit anchor.
    return;
  }

  // Cost-budget circuit breaker. Skip cleanly, mark status='skipped' so
  // the dashboard can surface it, and ledger the skip so it's auditable.
  if (budgetExceeded()) {
    await persistVerdicts(tenantId, findingId, "skipped", null, null);
    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.review_skipped_budget",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        reason: "daily_token_budget_exceeded",
        tokens_used_today: budget.tokensUsed,
        daily_budget: DAILY_TOKEN_BUDGET,
      },
    });
    return;
  }

  let triage: TriageVerdict | null = null;
  let verifier: VerifierVerdict | null = null;
  try {
    // -----------------------------------------------------------------
    // Triage step.
    // -----------------------------------------------------------------
    const invoker = getAgentInvoker();
    const t = await invoker.triage(finding);
    triage = t.verdict;
    chargeBudget(t.approxOutputTokens);

    // ARCHITECT-FLAGGED M5 FIX (info-disclosure / immutable-ledger):
    // PHI scan on agent rationale MUST happen BEFORE the rationale lands
    // in the append-only ledger. The old ordering ledgered triage first
    // then scanned both verdicts together, so a PHI-bearing triage
    // rationale would already be in `agent.triage_complete` payload by
    // the time the scan ran — and the ledger is immutable. We now scan
    // and (if hit) replace the rationale before every ledger write that
    // includes it.
    {
      const hits = scanForPhi(triage.rationale);
      if (hits.length > 0) {
        await appendLedger({
          tenantId,
          actor: { kind: "system", id: "supervisor" },
          eventType: "agent.output_phi_detected",
          subjectType: "finding",
          subjectId: findingId,
          payload: {
            finding_id: findingId,
            stage: "triage",
            detectors: Array.from(new Set(hits.map((h) => h.detector))),
            agent_identity: triageAgentIdentity(t.modelId),
          },
        });
        triage = { ...triage, rationale: "<REDACTED: agent output contained PHI/secrets>" };
      }
    }

    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.triage_complete",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        agent_identity: triageAgentIdentity(t.modelId),
        verdict: triage,
        approx_output_tokens: t.approxOutputTokens,
      },
    });

    // ARCHITECT-FLAGGED M5 FIX (DoS / cost): re-check the budget BETWEEN
    // triage and verifier. Otherwise with CONCURRENCY=2, multiple jobs
    // can each pass the pre-check then both run two LLM calls before any
    // charges land — overshooting the daily cap by ~2x. Re-checking
    // halves the overshoot window. The triage verdict is already
    // persisted below; we mark partial completion.
    if (budgetExceeded()) {
      await persistVerdicts(tenantId, findingId, "skipped", triage, null);
      await appendLedger({
        tenantId,
        actor: { kind: "system", id: "supervisor" },
        eventType: "agent.review_skipped_budget",
        subjectType: "finding",
        subjectId: findingId,
        payload: {
          finding_id: findingId,
          reason: "daily_token_budget_exceeded_after_triage",
          tokens_used_today: budget.tokensUsed,
          daily_budget: DAILY_TOKEN_BUDGET,
        },
      });
      return;
    }

    // -----------------------------------------------------------------
    // Verifier step.
    // -----------------------------------------------------------------
    const v = await invoker.verify(finding, triage);
    verifier = v.verdict;
    chargeBudget(v.approxOutputTokens);

    // Same PHI-scan-before-ledger ordering for the verifier rationale.
    {
      const hits = scanForPhi(verifier.rationale);
      if (hits.length > 0) {
        await appendLedger({
          tenantId,
          actor: { kind: "system", id: "supervisor" },
          eventType: "agent.output_phi_detected",
          subjectType: "finding",
          subjectId: findingId,
          payload: {
            finding_id: findingId,
            stage: "verifier",
            detectors: Array.from(new Set(hits.map((h) => h.detector))),
            agent_identity: verifierAgentIdentity(v.modelId),
          },
        });
        verifier = { ...verifier, rationale: "<REDACTED: agent output contained PHI/secrets>" };
      }
    }

    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.verifier_complete",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        agent_identity: verifierAgentIdentity(v.modelId),
        verdict: verifier,
        approx_output_tokens: v.approxOutputTokens,
      },
    });

    await persistVerdicts(tenantId, findingId, "completed", triage, verifier);
  } catch (err) {
    // Mark failed (NOT back to pending — avoid infinite retry loops on a
    // permanently malformed finding) and ledger the failure with the
    // last-good partial verdicts if any. Operators replay manually after
    // fixing root cause.
    await persistVerdicts(tenantId, findingId, "failed", triage, verifier);
    await appendLedger({
      tenantId,
      actor: { kind: "system", id: "supervisor" },
      eventType: "agent.review_failed",
      subjectType: "finding",
      subjectId: findingId,
      payload: {
        finding_id: findingId,
        error: (err as Error).message?.slice(0, 500) ?? "unknown",
        had_triage: triage !== null,
        had_verifier: verifier !== null,
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Ledger post-commit hook
// ---------------------------------------------------------------------------

/** Called from `appendLedger` after a successful insert. Enqueues a
 *  supervisor review for every `finding.created` event. The supervisor
 *  itself produces ledger entries (agent.* events) but those go through
 *  the same hook — they don't match `finding.created` so they don't
 *  recurse. Other event types are ignored.
 */
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

// Suppress unused import warning (sql is exposed for future advisory-lock
// migration when we move to multi-instance).
void sql;
void db;
