// M11.1 — Eval harness.
//
// Fixture-based, score-emitting eval infrastructure shared by every eval
// suite. Evals are NOT unit tests: a unit test asserts a single behavior is
// correct; an eval measures a *quality metric* (precision/recall/trip-rate)
// against a labeled fixture set and records the number so regressions are
// visible over time.
//
// Why separate from `*.test.ts`:
//   - The normal test glob is `src/**/*.test.ts` (see vitest.config.ts);
//     eval suites are `src/evals/*.eval.ts` and run only via
//     `vitest run --config vitest.eval.config.ts` (the `eval` npm script).
//     So `pnpm test` never pays the eval cost.
//   - Live (LLM/DB-backed) suites are gated behind EVAL_LLM=1 so the default
//     eval run is deterministic and needs no model credentials.
//
// Each suite calls `recordEvalResult(...)` in an `afterAll` hook. Results are
// written one-JSON-per-suite under `<pkg>/evals/results/`. After the vitest
// run, `evals/gate.mjs` compares those results against `evals/baseline.json`
// and fails the run if any score regresses by more than REGRESSION_TOLERANCE.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/** Live suites (real LLM + DB) only run when EVAL_LLM=1. Off by default so
 *  the committed baseline + CI gate stay deterministic and credential-free. */
export const EVAL_LLM = process.env["EVAL_LLM"] === "1";

/** A suite's recorded outcome. `score` is the single gated metric in [0,1],
 *  higher = better. `breakdown` carries the component metrics for humans. */
export interface EvalResult {
  suite: string;
  score: number;
  breakdown: Record<string, number>;
  meta?: Record<string, unknown>;
}

// Results land in `<cwd>/evals/results`. The `eval` npm script runs with cwd
// = the package root (pnpm --filter), so this resolves to
// artifacts/api-server/evals/results.
export const RESULTS_DIR = join(process.cwd(), "evals", "results");

export function recordEvalResult(result: EvalResult): void {
  mkdirSync(RESULTS_DIR, { recursive: true });
  const payload = { ...result, ts: new Date().toISOString() };
  writeFileSync(
    join(RESULTS_DIR, `${result.suite}.json`),
    JSON.stringify(payload, null, 2) + "\n",
    "utf8",
  );
  // Surface the headline number in the eval run output too.
  const pct = (result.score * 100).toFixed(1);
  // eslint-disable-next-line no-console
  console.log(`\n[eval] ${result.suite}: score=${pct}%`, result.breakdown);
}

/** Half-open span [start, end) into some source text. */
export interface Span {
  start: number;
  end: number;
}

/** First-occurrence span of `sub` in `text`. Throws if absent so a typo in a
 *  fixture is a loud failure rather than a silently mislabeled span. Fixtures
 *  must keep labeled substrings unique within their text. */
export function spanOf(text: string, sub: string): Span {
  const start = text.indexOf(sub);
  if (start < 0) {
    throw new Error(`fixture substring not found in text: ${JSON.stringify(sub)}`);
  }
  return { start, end: start + sub.length };
}

/** Two half-open spans overlap iff each starts before the other ends. */
export function overlaps(a: Span, b: Span): boolean {
  return a.start < b.end && b.start < a.end;
}

/** Precision / recall / F1 from confusion counts. Empty denominators score
 *  1.0 (vacuously perfect) so a suite with no positives/negatives doesn't
 *  drag the number down. */
export function prf(tp: number, fp: number, fn: number): {
  precision: number;
  recall: number;
  f1: number;
} {
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return { precision, recall, f1 };
}

/** Round to 4 dp for stable, diff-friendly recorded scores. */
export function round4(n: number): number {
  return Math.round(n * 1e4) / 1e4;
}
