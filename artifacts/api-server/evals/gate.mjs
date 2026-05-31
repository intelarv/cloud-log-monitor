// M11.1 — Eval regression gate (pure Node ESM; no TS runner needed).
//
// Reads every suite result written under evals/results/ and compares each
// score against evals/baseline.json. Fails (exit 1) if any suite regresses by
// more than REGRESSION_TOLERANCE, or if a baselined suite produced no result.
//
// Usage:
//   node evals/gate.mjs            compare results against baseline (CI gate)
//   node evals/gate.mjs --update   (re)write baseline.json from current results
//
// New suites present in results but absent from the baseline are reported as
// a warning, not a failure — run --update to adopt them as the new baseline.

import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from "node:fs";
import { join } from "node:path";

const REGRESSION_TOLERANCE = 0.05;
// Non-deterministic, credential-gated suites (EVAL_LLM=1). They are reported as
// warnings when present but NEVER written into baseline.json — the committed
// baseline is the deterministic, credential-free anchor by design.
const NON_DETERMINISTIC = new Set(["citation-live", "agent-agreement"]);

// Nightly hard-fail floor for the non-deterministic suites. The per-change
// gate (deploy/scripts/eval-gate.sh) never runs these suites and never sets
// this; the nightly job (deploy/scripts/eval-gate-llm.sh) may. When
// EVAL_LLM_MIN_SCORE is a number in (0,1], any non-deterministic suite that
// produced a result and scored BELOW the floor fails the run; jitter above the
// floor stays a non-fatal warning. We use an ABSOLUTE floor (not a baseline
// delta) on purpose: the LLM suites are non-deterministic, so delta-based
// paging would be flaky. Execution failures (a live suite that crashes or
// emits no result) already hard-fail before the gate via the vitest run.
const llmFloorRaw = process.env.EVAL_LLM_MIN_SCORE;
const llmFloor =
  llmFloorRaw !== undefined && llmFloorRaw.trim() !== "" ? Number(llmFloorRaw) : NaN;
const enforceLlmFloor = Number.isFinite(llmFloor) && llmFloor > 0;
const ROOT = join(process.cwd(), "evals");
const RESULTS_DIR = join(ROOT, "results");
const BASELINE_PATH = join(ROOT, "baseline.json");
const SUMMARY_PATH = join(RESULTS_DIR, "gate-summary.json");
const update = process.argv.includes("--update");

/** Persist the gate verdict so the nightly notifier (evals/notify.mjs) can
 *  post a concise pass/fail summary to configured channels. Lives in the
 *  gitignored results dir (regenerated every run). Best-effort: a write
 *  failure must never change the gate's own exit code. */
function writeSummary(summary) {
  try {
    mkdirSync(RESULTS_DIR, { recursive: true });
    writeFileSync(SUMMARY_PATH, JSON.stringify(summary, null, 2) + "\n", "utf8");
  } catch (err) {
    console.error(`[gate] failed to write gate-summary.json: ${err?.message ?? err}`);
  }
}

function loadResults() {
  if (!existsSync(RESULTS_DIR)) return {};
  const scores = {};
  for (const file of readdirSync(RESULTS_DIR)) {
    if (!file.endsWith(".json")) continue;
    const data = JSON.parse(readFileSync(join(RESULTS_DIR, file), "utf8"));
    if (typeof data.suite === "string" && typeof data.score === "number") {
      scores[data.suite] = data.score;
    }
  }
  return scores;
}

const results = loadResults();
const resultSuites = Object.keys(results);

if (resultSuites.length === 0) {
  console.error("[gate] no eval results found under evals/results — did the eval run produce output?");
  if (!update) {
    writeSummary({
      ok: false,
      executionFailure: true,
      failures: ["no eval results found under evals/results — the eval run produced no output"],
      warnings: [],
      suites: {},
      floor: { active: enforceLlmFloor, value: enforceLlmFloor ? llmFloor : null },
      ts: new Date().toISOString(),
    });
  }
  process.exit(1);
}

if (update) {
  mkdirSync(ROOT, { recursive: true });
  const deterministic = resultSuites.filter((s) => !NON_DETERMINISTIC.has(s)).sort();
  const skipped = resultSuites.filter((s) => NON_DETERMINISTIC.has(s)).sort();
  const ordered = {};
  for (const s of deterministic) ordered[s] = results[s];
  writeFileSync(BASELINE_PATH, JSON.stringify(ordered, null, 2) + "\n", "utf8");
  console.log(`[gate] baseline updated with ${deterministic.length} deterministic suite(s):`);
  for (const s of deterministic) console.log(`  ${s} = ${(results[s] * 100).toFixed(1)}%`);
  for (const s of skipped) console.log(`[gate] skipped non-deterministic suite (not baselined): ${s}`);
  process.exit(0);
}

const baseline = existsSync(BASELINE_PATH)
  ? JSON.parse(readFileSync(BASELINE_PATH, "utf8"))
  : {};
const baselineSuites = Object.keys(baseline);

const failures = [];
const warnings = [];
// Per-suite machine-readable verdict, consumed by the nightly channel
// notifier (evals/notify.mjs) so a failing run can post scores + which
// check tripped to Slack / webhook. Scores + suite names only — never PHI.
const suiteSummary = {};

function round1(n) {
  return Math.round(n * 10) / 10;
}

for (const suite of baselineSuites) {
  const base = baseline[suite];
  if (!(suite in results)) {
    failures.push(`${suite}: baselined but produced no result this run`);
    suiteSummary[suite] = { baseline: base, status: "missing" };
    continue;
  }
  const score = results[suite];
  const delta = score - base;
  const status =
    delta < -REGRESSION_TOLERANCE ? "FAIL" : delta < 0 ? "drop" : "ok";
  const line = `${suite}: ${(score * 100).toFixed(1)}% (baseline ${(base * 100).toFixed(1)}%, ${delta >= 0 ? "+" : ""}${(delta * 100).toFixed(1)}pt) [${status}]`;
  suiteSummary[suite] = { score, baseline: base, deltaPt: round1(delta * 100), status };
  if (status === "FAIL") failures.push(line);
  else console.log(`[gate] ${line}`);
}

for (const suite of resultSuites) {
  if (suite in baseline) continue;
  const score = results[suite];
  if (enforceLlmFloor && NON_DETERMINISTIC.has(suite)) {
    if (score < llmFloor) {
      failures.push(
        `${suite}: ${(score * 100).toFixed(1)}% below nightly floor ${(llmFloor * 100).toFixed(1)}% (EVAL_LLM_MIN_SCORE)`,
      );
      suiteSummary[suite] = { score, floor: llmFloor, status: "BELOW_FLOOR" };
    } else {
      console.log(
        `[gate] ${suite}: ${(score * 100).toFixed(1)}% (nightly floor ${(llmFloor * 100).toFixed(1)}% — ok; not baselined)`,
      );
      suiteSummary[suite] = { score, floor: llmFloor, status: "floor-ok" };
    }
    continue;
  }
  warnings.push(`${suite}: ${(score * 100).toFixed(1)}% (no baseline — run --update to adopt)`);
  suiteSummary[suite] = { score, status: "no-baseline" };
}

for (const w of warnings) console.log(`[gate] WARN ${w}`);

const ok = failures.length === 0;
writeSummary({
  ok,
  failures,
  warnings,
  suites: suiteSummary,
  floor: { active: enforceLlmFloor, value: enforceLlmFloor ? llmFloor : null },
  ts: new Date().toISOString(),
});

if (!ok) {
  console.error(`\n[gate] FAILED — ${failures.length} suite(s) regressed > ${(REGRESSION_TOLERANCE * 100).toFixed(0)}%:`);
  for (const f of failures) console.error(`  ${f}`);
  process.exit(1);
}

console.log(`\n[gate] PASS — ${baselineSuites.length} baselined suite(s) within tolerance.`);
process.exit(0);
