---
name: Retryable side-effect step idempotency (ledger-gated)
description: How review/agent activities are made safe to auto-retry — gate on the ledger idempotency key, order non-ledger side effects after the gate write.
---

# Making a non-idempotent step safe under auto-retry

When an activity/step does (a) an append-only ledger write AND (b) another
side effect (e.g. per-tenant LLM budget charge), and you want to enable bounded
auto-retry (Temporal `REVIEW_ACTIVITY_OPTIONS`, or any retrying engine):

**The rule:**
1. Derive a stable per-step key = `workflowIdFor(tenantId, findingId)` + `:step`.
   `workflowIdFor` lives in `agents/workflow-id.ts` (extracted to avoid a
   circular import with `temporal-engine.ts`).
2. Pass it as `appendLedger({ ..., idempotencyKey })`. `appendLedger` dedupes
   inside its single advisory-locked txn against the `ledger_idempotency_key_uniq`
   unique index and, on a hit, returns the existing row AND skips the
   post-commit fan-out (alert / supervisor enqueue / channel dispatch) so a
   retry never double-fires those.
3. At the TOP of the step, `getLedgerEntryByIdempotencyKey(completeKey)`; if it
   exists, recover the recorded result from `row.payload` and return WITHOUT
   re-calling the LLM / re-charging / re-writing. Live reads (budget state) are
   recomputed — they are reads, not side effects.
4. Order the non-ledger side effect (budget charge) **AFTER** the dedupe-gate
   ledger write AND gate it on a *fresh insert*: the write must report whether it
   deduped (return `{row, deduped}`), and the side effect runs only when
   `deduped===false`. Ordering-after alone is NOT enough — two attempts running
   *concurrently* both pass the top read-gate, both reach the write, and one
   inserts while one dedupes; only the inserting one may charge. The advisory
   lock serializes the write so exactly one sees `deduped===false`. Residual: a
   crash in the tiny window between the insert and the charge causes a rare
   single-step undercount — acceptable for a per-process best-effort budget;
   never a double-charge.

**Why:** the ledger is the durable exactly-once anchor; using its unique index
as the dedupe gate means the audit record and the side-effect guard are the same
fact, so they can't disagree under partial-failure + retry.

**Invariants that keep it byte-identical:**
- `idempotencyKey` is NOT part of `computeLedgerHash`, so the chain is unchanged
  and pre-existing NULL-keyed rows coexist (Postgres treats NULLs as distinct in
  the unique index).
- The in-process engine never retries, so its dedupe check always misses ⇒
  behavior + offline eval gate stay byte-identical. Only Temporal retries.

**Gotcha:** SQL kept in a JS template literal (`setup-sql.ts`) — never put a
backtick inside the SQL comment text; it closes the template literal and the
comment gets parsed as TS. Use plain quotes in comments.

**Replay vs transient-retry (per-finding attempt discriminator):** the per-step
key must distinguish a *transient same-execution retry* (must dedupe) from an
*operator replay* (reset `agent_review_status`→pending + re-enqueue; must
RE-run the LLM). Solution: a monotonic `findings.agent_review_attempt` int,
bumped atomically inside `acquireFinding`'s pending→in_progress CAS
(`SET agent_review_attempt = agent_review_attempt + 1`). The step key becomes
`workflowIdFor:attempt:${attempt}:${step}`. Transient retries don't re-acquire,
so attempt is fixed ⇒ keys match ⇒ dedupe. A replay re-acquires ⇒ attempt bumps
⇒ fresh keys ⇒ fresh LLM + fresh ledger completes. **Why not change
`workflow-id.ts`:** Temporal's default `WorkflowIdReusePolicy=AllowDuplicate`
already permits re-dispatching the same workflow id after the prior execution
closed, so the discriminator belongs in the *ledger* key, not the workflow id.
Capture `const attempt = finding.agentReviewAttempt` once after acquire in the
orchestration body and thread it to skip/fail steps; triage/verifier read it off
`finding`. The column is additive (in `findingSafeColumns`, default 0); added via
`ADD COLUMN IF NOT EXISTS` in setup-sql so bootstrap seats it (drizzle `push`
prompts interactively on a possible rename — rely on bootstrap, not push).
