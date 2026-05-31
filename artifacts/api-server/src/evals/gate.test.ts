import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

// Absolute path to the gate script under test. This file lives at
// artifacts/api-server/src/evals/gate.test.ts; gate.mjs is at
// artifacts/api-server/evals/gate.mjs.
const GATE = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "evals", "gate.mjs");

// gate.mjs resolves evals/results and evals/baseline.json relative to
// process.cwd(), so each scenario gets a throwaway cwd seeded with synthetic
// result files + baseline. No live LLM/DB is touched — these are canned JSON.
const tmpDirs: string[] = [];

function setupGateDir(opts: {
  results: Record<string, number>;
  baseline: Record<string, number>;
}): string {
  const dir = mkdtempSync(join(tmpdir(), "gate-test-"));
  tmpDirs.push(dir);
  const resultsDir = join(dir, "evals", "results");
  mkdirSync(resultsDir, { recursive: true });
  for (const [suite, score] of Object.entries(opts.results)) {
    writeFileSync(join(resultsDir, `${suite}.json`), JSON.stringify({ suite, score }));
  }
  writeFileSync(join(dir, "evals", "baseline.json"), JSON.stringify(opts.baseline));
  return dir;
}

function runGate(
  dir: string,
  env: Record<string, string | undefined> = {},
  args: string[] = [],
) {
  const result = spawnSync(process.execPath, [GATE, ...args], {
    cwd: dir,
    encoding: "utf8",
    env: { ...process.env, EVAL_LLM_MIN_SCORE: undefined, ...env },
  });
  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

afterEach(() => {
  while (tmpDirs.length > 0) {
    const dir = tmpDirs.pop();
    if (dir) rmSync(dir, { recursive: true, force: true });
  }
});

describe("eval gate — nightly hard-fail floor", () => {
  // A clean baseline the deterministic suites always satisfy.
  const baseline = {
    "detector-phi": 1,
    "detector-secrets": 1,
  };
  const passingDeterministic = {
    "detector-phi": 1,
    "detector-secrets": 1,
  };

  it("floor unset: a low-scoring live suite is a warning, not a failure (exit 0)", () => {
    const dir = setupGateDir({
      results: { ...passingDeterministic, "agent-agreement": 0.2 },
      baseline,
    });
    const r = runGate(dir);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("PASS");
  });

  it("floor set, live score above floor: pass (exit 0)", () => {
    const dir = setupGateDir({
      results: { ...passingDeterministic, "agent-agreement": 0.9 },
      baseline,
    });
    const r = runGate(dir, { EVAL_LLM_MIN_SCORE: "0.8" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("nightly floor");
    expect(r.stdout).toContain("PASS");
  });

  it("floor set, live score below floor: hard fail (exit 1)", () => {
    const dir = setupGateDir({
      results: { ...passingDeterministic, "agent-agreement": 0.5 },
      baseline,
    });
    const r = runGate(dir, { EVAL_LLM_MIN_SCORE: "0.8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("below nightly floor");
    expect(r.stderr).toContain("agent-agreement");
  });

  it("deterministic regression always fails regardless of floor (exit 1)", () => {
    const dir = setupGateDir({
      // detector-phi collapses well past the 5pt tolerance; live suite is fine.
      results: {
        "detector-phi": 0.5,
        "detector-secrets": 1,
        "agent-agreement": 0.95,
      },
      baseline,
    });
    // Floor set and live suite is above it, yet the deterministic regression
    // must still fail the run.
    const r = runGate(dir, { EVAL_LLM_MIN_SCORE: "0.8" });
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("detector-phi");
    expect(r.stderr).toContain("FAILED");
  });

  it("deterministic regression fails even with no floor set (exit 1)", () => {
    const dir = setupGateDir({
      results: { "detector-phi": 0.5, "detector-secrets": 1 },
      baseline,
    });
    const r = runGate(dir);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("detector-phi");
  });

  it("empty floor string is treated as unset (low live suite stays a warning)", () => {
    const dir = setupGateDir({
      results: { ...passingDeterministic, "agent-agreement": 0.1 },
      baseline,
    });
    const r = runGate(dir, { EVAL_LLM_MIN_SCORE: "  " });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("PASS");
  });
});

describe("eval gate — baseline writing and comparison branches", () => {
  it("--update rewrites baseline.json with deterministic suites only, skipping non-deterministic (exit 0)", () => {
    const dir = setupGateDir({
      // Stale baseline that --update must overwrite wholesale.
      baseline: { "stale-suite": 0.42 },
      results: {
        "detector-phi": 0.97,
        "detector-secrets": 0.88,
        "agent-agreement": 0.91,
        "citation-live": 0.83,
      },
    });
    const r = runGate(dir, {}, ["--update"]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("baseline updated with 2 deterministic suite(s)");
    expect(r.stdout).toContain("skipped non-deterministic suite (not baselined): agent-agreement");
    expect(r.stdout).toContain("skipped non-deterministic suite (not baselined): citation-live");

    const written = JSON.parse(
      readFileSync(join(dir, "evals", "baseline.json"), "utf8"),
    );
    // Deterministic results only; non-deterministic + stale entry excluded.
    expect(written).toEqual({
      "detector-phi": 0.97,
      "detector-secrets": 0.88,
    });
  });

  it("a baselined suite missing from results hard-fails (exit 1)", () => {
    const dir = setupGateDir({
      baseline: { "detector-phi": 1, "detector-secrets": 1 },
      // detector-secrets disappeared from this run's output.
      results: { "detector-phi": 1 },
    });
    const r = runGate(dir);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("detector-secrets: baselined but produced no result this run");
    expect(r.stderr).toContain("FAILED");
  });

  it("a brand-new non-baselined deterministic suite is a warning, not a failure (exit 0)", () => {
    const dir = setupGateDir({
      baseline: { "detector-phi": 1 },
      results: { "detector-phi": 1, "detector-newcheck": 0.9 },
    });
    const r = runGate(dir);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("WARN detector-newcheck");
    expect(r.stdout).toContain("no baseline — run --update to adopt");
    expect(r.stdout).toContain("PASS");
  });

  it("an empty results directory hard-fails before comparison (exit 1)", () => {
    const dir = setupGateDir({
      baseline: { "detector-phi": 1 },
      results: {},
    });
    const r = runGate(dir);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("no eval results found under evals/results");
  });
});
