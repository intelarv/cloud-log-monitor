---
name: Nightly eval gate hard-fail policy
description: Why the AI-backed nightly eval suites page on absolute floor, not score delta
---

# Nightly eval gate hard-fail policy

The deterministic per-change eval gate fails on any >5pt regression vs baseline.
The nightly AI-backed gate (`eval:gate:llm`, EVAL_LLM=1 → citation-live +
agent-agreement) does NOT apply the same delta rule to those two suites.

Rule:
- Deterministic suite regressions (>5pt) → always hard-fail.
- Live-suite execution failure (crash / no result) → always hard-fail (vitest
  exits non-zero before the gate even runs).
- Live-suite *score* regressions → warning by default. Opt-in absolute floor
  `EVAL_LLM_MIN_SCORE` (0..1) turns a sub-floor live score into a hard fail.

**Why:** citation-live and agent-agreement are non-deterministic (real LLM).
Delta-based paging on them would flap run-to-run and train people to ignore the
page. An absolute floor pages only on catastrophic collapse, which is the signal
worth waking someone for.

**How to apply:** if asked to make the nightly job stricter, set
`EVAL_LLM_MIN_SCORE` (Helm: `evalGate.nightly.llmMinScore`) rather than
reintroducing delta thresholds for the live suites. Floor enforcement lives in
`evals/gate.mjs`'s warnings loop for NON_DETERMINISTIC suites.
