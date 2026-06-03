import { afterEach, describe, expect, it, vi } from "vitest";

// Mock the DB context so hybridSearchFindings can run without a live Postgres.
// `withTenant` is used by BOTH the vector retriever and the final hydrate, in
// that order, so we queue per-call return values.
const withTenantQueue: unknown[] = [];
vi.mock("./db-context", () => ({
  withTenant: vi.fn(async () => {
    if (withTenantQueue.length === 0) return [];
    return withTenantQueue.shift();
  }),
}));

import { hybridSearchFindings } from "./search";
import type { Embedder } from "./embeddings";
import type { LexicalSearchProvider } from "./search-config";

const fakeEmbedder: Embedder = {
  version: "test",
  dim: 4,
  async embed() {
    return [0, 0, 0, 0];
  },
};

afterEach(() => {
  withTenantQueue.length = 0;
  vi.clearAllMocks();
});

describe("hybridSearchFindings lexical-leg resilience", () => {
  it("degrades to vector-only results when the lexical provider throws", async () => {
    const throwingProvider: LexicalSearchProvider = {
      name: "opensearch",
      maintainsExternalIndex: true,
      async search() {
        throw new Error("opensearch unreachable");
      },
      async indexFinding() {},
    };

    // 1st withTenant() call = vectorSearch → one vector hit.
    withTenantQueue.push([{ finding_id: "V1", rank: 1 }]);
    // 2nd withTenant() call = hydrate → the row for that id.
    withTenantQueue.push([{ id: "V1", classification: "phi" }]);

    const res = await hybridSearchFindings("t1", "ssn", {
      embedder: fakeEmbedder,
      searchProvider: throwingProvider,
    });

    // The whole turn resolved (no rejection) and the vector leg carried it.
    expect(res.fused.map((f) => f.finding_id)).toEqual(["V1"]);
    expect(res.fused[0]!.sources).toEqual(["vector"]);
    expect(res.findings).toHaveLength(1);
  });

  it("still fuses both legs when the lexical provider succeeds", async () => {
    const okProvider: LexicalSearchProvider = {
      name: "opensearch",
      maintainsExternalIndex: true,
      async search() {
        return [{ finding_id: "L1", rank: 1 }];
      },
      async indexFinding() {},
    };

    withTenantQueue.push([{ finding_id: "V1", rank: 1 }]); // vectorSearch
    withTenantQueue.push([
      { id: "L1", classification: "phi" },
      { id: "V1", classification: "phi" },
    ]); // hydrate

    const res = await hybridSearchFindings("t1", "ssn", {
      embedder: fakeEmbedder,
      searchProvider: okProvider,
    });

    expect(res.fused.map((f) => f.finding_id).sort()).toEqual(["L1", "V1"]);
    const l1 = res.fused.find((f) => f.finding_id === "L1")!;
    expect(l1.sources).toEqual(["bm25"]);
  });
});
