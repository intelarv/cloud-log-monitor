import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    environment: "node",
    globals: false,
    reporters: "default",
    // Serialize across files: many integration tests share the dev DB
    // and write to the global ledger (M1.9 pollution gotcha). Parallel
    // file workers create cross-file races on head-sequence invariants
    // (notably notarization idempotency). Single fork removes the race
    // without making per-test cleanup invasive.
    fileParallelism: false,
  },
});
