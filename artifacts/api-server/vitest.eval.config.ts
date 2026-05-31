import { defineConfig } from "vitest/config";

// M11.1 — Eval runner config. Separate from vitest.config.ts so `pnpm test`
// (glob: src/**/*.test.ts) never picks up eval suites, and `pnpm run eval`
// (glob: src/evals/**/*.eval.ts) never picks up unit tests.
//
// fileParallelism:false mirrors the unit config — the LLM-gated suites share
// the dev DB / global ledger and must not race. testTimeout is generous so the
// live (EVAL_LLM=1) suites have headroom for real model round-trips.
export default defineConfig({
  test: {
    include: ["src/evals/**/*.eval.ts"],
    environment: "node",
    globals: false,
    reporters: "default",
    fileParallelism: false,
    testTimeout: 60_000,
  },
});
