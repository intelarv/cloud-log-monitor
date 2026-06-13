import { afterEach, describe, expect, it, vi } from "vitest";
import {
  loadEmbeddingsPartitioningFromEnv,
  initEmbeddingsPartitioningFromEnv,
  isEmbeddingsPartitioned,
  reconcileEmbeddingsPartitioningFromDb,
  __setEmbeddingsPartitionedForTest,
} from "./embeddings-partition-config";
import * as db from "@workspace/db";

// M12.2: the per-tenant pgvector partitioning switch must default OFF (so the
// dev + credential-free eval-gate path is byte-identical to pre-M12.2) and only
// flip on with an explicit, recognized truthy env value.

afterEach(() => {
  __setEmbeddingsPartitionedForTest(false);
});

describe("loadEmbeddingsPartitioningFromEnv", () => {
  it("defaults to false when the var is unset", () => {
    expect(loadEmbeddingsPartitioningFromEnv({})).toBe(false);
  });

  it("treats recognized truthy values as on", () => {
    for (const v of ["1", "true", "on", "yes", "TRUE", " On "]) {
      expect(
        loadEmbeddingsPartitioningFromEnv({
          EMBEDDINGS_TENANT_PARTITIONING: v,
        }),
      ).toBe(true);
    }
  });

  it("treats recognized falsy values (incl. empty) as off", () => {
    for (const v of ["", "0", "false", "off", "no", "FALSE"]) {
      expect(
        loadEmbeddingsPartitioningFromEnv({
          EMBEDDINGS_TENANT_PARTITIONING: v,
        }),
      ).toBe(false);
    }
  });

  it("throws on an unrecognized value rather than silently defaulting", () => {
    expect(() =>
      loadEmbeddingsPartitioningFromEnv({
        EMBEDDINGS_TENANT_PARTITIONING: "maybe",
      }),
    ).toThrow(/not a boolean/);
  });
});

describe("initEmbeddingsPartitioningFromEnv / isEmbeddingsPartitioned", () => {
  it("sets the module switch from env and reflects it", () => {
    expect(initEmbeddingsPartitioningFromEnv({})).toBe(false);
    expect(isEmbeddingsPartitioned()).toBe(false);

    expect(
      initEmbeddingsPartitioningFromEnv({
        EMBEDDINGS_TENANT_PARTITIONING: "on",
      }),
    ).toBe(true);
    expect(isEmbeddingsPartitioned()).toBe(true);
  });
});

describe("reconcileEmbeddingsPartitioningFromDb", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("trusts the catalog over env intent (partitioned table + switch off ⇒ on)", async () => {
    // Drift case the architect flagged: env says single (switch off) but the
    // live table is still partitioned. The ON CONFLICT arbiter MUST follow the
    // table, so reconcile must flip the runtime switch to true.
    __setEmbeddingsPartitionedForTest(false);
    vi.spyOn(db, "isFindingEmbeddingsPartitionedInDb").mockResolvedValue(true);
    expect(await reconcileEmbeddingsPartitioningFromDb()).toBe(true);
    expect(isEmbeddingsPartitioned()).toBe(true);
  });

  it("reconciles to single when the catalog reports a single table", async () => {
    __setEmbeddingsPartitionedForTest(true);
    vi.spyOn(db, "isFindingEmbeddingsPartitionedInDb").mockResolvedValue(false);
    expect(await reconcileEmbeddingsPartitioningFromDb()).toBe(false);
    expect(isEmbeddingsPartitioned()).toBe(false);
  });
});
