import { afterEach, describe, expect, it } from "vitest";
import {
  PostgresLexicalSearchProvider,
  createSearchProvider,
  getSearchProvider,
  getSearchProviderOrNull,
  initSearchProviderFromEnv,
  loadSearchProviderConfigFromEnv,
  resetSearchProviderForTests,
  setSearchProvider,
} from "./search-config";
import {
  OpenSearchLexicalProvider,
  buildIsmPolicy,
  createOpenSearchProvider,
  loadIlmConfigFromEnv,
  safeTenantSegment,
  type OpenSearchClient,
} from "./cloud-search";
import { planReindexResume, resolveReindexBatchSize } from "./search";

afterEach(() => resetSearchProviderForTests());

describe("loadSearchProviderConfigFromEnv", () => {
  it("defaults to postgres when unset", () => {
    expect(loadSearchProviderConfigFromEnv({}).provider).toBe("postgres");
  });

  it("honors an explicit SEARCH_PROVIDER (case-insensitive)", () => {
    expect(
      loadSearchProviderConfigFromEnv({ SEARCH_PROVIDER: "OpenSearch" })
        .provider,
    ).toBe("opensearch");
    expect(
      loadSearchProviderConfigFromEnv({ SEARCH_PROVIDER: "postgres" }).provider,
    ).toBe("postgres");
  });

  it("does NOT auto-select from DEPLOYMENT_TARGET (no cloud shortcut)", () => {
    // OpenSearch always needs an explicit endpoint, so a bare cloud target
    // must not flip the provider — that would break embedder-only deployments.
    expect(
      loadSearchProviderConfigFromEnv({ DEPLOYMENT_TARGET: "aws" }).provider,
    ).toBe("postgres");
  });

  it("throws on an unknown provider rather than falling back", () => {
    expect(() =>
      loadSearchProviderConfigFromEnv({ SEARCH_PROVIDER: "elastic" }),
    ).toThrow(/not a known provider/);
  });
});

describe("createSearchProvider", () => {
  it("builds the Postgres provider (no external index)", () => {
    const p = createSearchProvider({ provider: "postgres" });
    expect(p).toBeInstanceOf(PostgresLexicalSearchProvider);
    expect(p.name).toBe("postgres");
    expect(p.maintainsExternalIndex).toBe(false);
  });

  it("Postgres indexFinding is a no-op that resolves", async () => {
    const p = new PostgresLexicalSearchProvider();
    await expect(
      p.indexFinding({
        findingId: "F-1",
        tenantId: "t1",
        classification: "phi",
        subclass: "name",
        severity: "high",
        source: "s",
        snippet: "redacted",
      }),
    ).resolves.toBeUndefined();
  });

  it("builds the OpenSearch provider when endpoint is present", () => {
    const p = createSearchProvider(
      { provider: "opensearch" },
      { OPENSEARCH_ENDPOINT: "https://os.example:9200" },
    );
    expect(p).toBeInstanceOf(OpenSearchLexicalProvider);
    expect(p.name).toBe("opensearch");
    expect(p.maintainsExternalIndex).toBe(true);
  });

  it("throws when SEARCH_PROVIDER=opensearch but endpoint is missing", () => {
    expect(() => createSearchProvider({ provider: "opensearch" }, {})).toThrow(
      /OPENSEARCH_ENDPOINT/,
    );
  });
});

describe("provider registry", () => {
  it("getSearchProvider throws before init; getOrNull returns null", () => {
    resetSearchProviderForTests();
    expect(getSearchProviderOrNull()).toBeNull();
    expect(() => getSearchProvider()).toThrow(/not initialized/);
  });

  it("set/get round-trips and reset clears", () => {
    const p = new PostgresLexicalSearchProvider();
    setSearchProvider(p);
    expect(getSearchProvider()).toBe(p);
    expect(getSearchProviderOrNull()).toBe(p);
    resetSearchProviderForTests();
    expect(getSearchProviderOrNull()).toBeNull();
  });

  it("initSearchProviderFromEnv registers the configured provider", () => {
    const { config, provider } = initSearchProviderFromEnv({});
    expect(config.provider).toBe("postgres");
    expect(getSearchProvider()).toBe(provider);
  });
});

// ---------------------------------------------------------------------------
// OpenSearch provider against an in-memory fake client — deterministic, no
// real cluster and no SDK install required.
// ---------------------------------------------------------------------------

/** Records every call and returns scripted ids, so we can assert on the
 *  query body (tenant filter, fields) and the index doc shape. */
function makeFakeClient(scriptedIds: string[]): {
  client: OpenSearchClient;
  calls: {
    ensured: string[];
    indexed: Array<{ index: string; id: string; body: Record<string, unknown> }>;
    searched: Array<{ index: string; body: Record<string, unknown> }>;
  };
} {
  const calls = {
    ensured: [] as string[],
    indexed: [] as Array<{
      index: string;
      id: string;
      body: Record<string, unknown>;
    }>,
    searched: [] as Array<{ index: string; body: Record<string, unknown> }>,
  };
  const client: OpenSearchClient = {
    async ensureIndex(index) {
      calls.ensured.push(index);
    },
    async indexDoc(index, id, body) {
      calls.indexed.push({ index, id, body });
    },
    async searchIds(index, body) {
      calls.searched.push({ index, body });
      return scriptedIds;
    },
  };
  return { client, calls };
}

describe("OpenSearchLexicalProvider (fake client)", () => {
  it("maps scored hits to 1-based RetrievalHit ranks", async () => {
    const { client } = makeFakeClient(["F-3", "F-1", "F-2"]);
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      clientFactory: async () => client,
    });
    const hits = await provider.search("t1", "social security", 10);
    expect(hits).toEqual([
      { finding_id: "F-3", rank: 1 },
      { finding_id: "F-1", rank: 2 },
      { finding_id: "F-2", rank: 3 },
    ]);
  });

  it("applies a mandatory tenant_id term filter on every query", async () => {
    const { client, calls } = makeFakeClient([]);
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });
    await provider.search("tenant-xyz", "ssn", 5);
    const body = calls.searched[0]!.body as {
      size: number;
      query: { bool: { filter: Array<{ term: { tenant_id: string } }> } };
    };
    expect(calls.searched[0]!.index).toBe("idx");
    expect(body.size).toBe(5);
    expect(body.query.bool.filter).toContainEqual({
      term: { tenant_id: "tenant-xyz" },
    });
  });

  it("short-circuits an empty query without hitting the client", async () => {
    const { client, calls } = makeFakeClient(["X"]);
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      clientFactory: async () => client,
    });
    expect(await provider.search("t1", "   ", 5)).toEqual([]);
    expect(calls.searched).toHaveLength(0);
  });

  it("indexes only redacted fields plus tenant_id, keyed by finding id", async () => {
    const { client, calls } = makeFakeClient([]);
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });
    await provider.indexFinding({
      findingId: "F-9",
      tenantId: "t1",
      classification: "secrets",
      subclass: "aws_key",
      severity: "critical",
      source: "cloudwatch:billing",
      snippet: "AWS key <REDACTED>",
    });
    expect(calls.indexed).toHaveLength(1);
    expect(calls.indexed[0]!.index).toBe("idx");
    expect(calls.indexed[0]!.id).toBe("F-9");
    expect(calls.indexed[0]!.body).toEqual({
      tenant_id: "t1",
      classification: "secrets",
      subclass: "aws_key",
      severity: "critical",
      source: "cloudwatch:billing",
      snippet: "AWS key <REDACTED>",
    });
  });
});

// ---------------------------------------------------------------------------
// Per-tenant index isolation (OPENSEARCH_PER_TENANT_INDEX)
// ---------------------------------------------------------------------------

/** A fake client that stores indexed docs keyed by the index they were written
 *  to, and on search returns ONLY the ids living in the exact queried index.
 *  This proves physical isolation: a query against tenant A's index can never
 *  surface a document written into tenant B's index. */
function makePerIndexClient(): {
  client: OpenSearchClient;
  byIndex: Map<string, Set<string>>;
  searched: Array<{ index: string; body: Record<string, unknown> }>;
} {
  const byIndex = new Map<string, Set<string>>();
  const searched: Array<{ index: string; body: Record<string, unknown> }> = [];
  const client: OpenSearchClient = {
    async ensureIndex(index) {
      if (!byIndex.has(index)) byIndex.set(index, new Set());
    },
    async indexDoc(index, id) {
      const set = byIndex.get(index) ?? new Set<string>();
      set.add(id);
      byIndex.set(index, set);
    },
    async searchIds(index, body) {
      searched.push({ index, body });
      return [...(byIndex.get(index) ?? new Set<string>())];
    },
  };
  return { client, byIndex, searched };
}

describe("OpenSearchLexicalProvider per-tenant index isolation", () => {
  it("safeTenantSegment is collision-free for ids that sanitize alike", () => {
    // `a/b` and `a-b` both sanitize to the readable `a-b`; the raw-id hash
    // suffix must keep their full segments distinct.
    expect(safeTenantSegment("a/b")).not.toBe(safeTenantSegment("a-b"));
    // Deterministic for a given id.
    expect(safeTenantSegment("tenant-xyz")).toBe(safeTenantSegment("tenant-xyz"));
  });

  it("routes each tenant to its own physical index and keeps the tenant filter", async () => {
    const { client, searched } = makePerIndexClient();
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      perTenantIndex: true,
      clientFactory: async () => client,
    });

    await provider.search("tenant-a", "ssn", 5);
    await provider.search("tenant-b", "ssn", 5);

    const idxA = searched[0]!.index;
    const idxB = searched[1]!.index;
    expect(idxA).toBe(`idx-${safeTenantSegment("tenant-a")}`);
    expect(idxB).toBe(`idx-${safeTenantSegment("tenant-b")}`);
    expect(idxA).not.toBe(idxB);
    expect(idxA).not.toBe("idx"); // not the shared index

    // Belt-and-suspenders: the mandatory tenant_id term filter still rides
    // every query even though the index is already physically separated.
    const body = searched[0]!.body as {
      query: { bool: { filter: Array<{ term: { tenant_id: string } }> } };
    };
    expect(body.query.bool.filter).toContainEqual({
      term: { tenant_id: "tenant-a" },
    });
  });

  it("a query for tenant A can never read tenant B's index", async () => {
    const { client } = makePerIndexClient();
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      perTenantIndex: true,
      clientFactory: async () => client,
    });

    // Index a finding owned by tenant B.
    await provider.indexFinding({
      findingId: "F-B1",
      tenantId: "tenant-b",
      classification: "phi",
      subclass: null,
      severity: "high",
      source: "cloudwatch:b",
      snippet: "<REDACTED>",
    });

    // Tenant A searches — its index is physically separate, so B's doc is
    // unreachable.
    const aHits = await provider.search("tenant-a", "redacted", 10);
    expect(aHits).toEqual([]);

    // Tenant B searches its own index and finds it.
    const bHits = await provider.search("tenant-b", "redacted", 10);
    expect(bHits.map((h) => h.finding_id)).toEqual(["F-B1"]);
  });

  it("defaults to a single shared index when per-tenant is off (backward compat)", async () => {
    const { client, searched } = makePerIndexClient();
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });
    await provider.search("tenant-a", "ssn", 5);
    await provider.search("tenant-b", "ssn", 5);
    expect(searched[0]!.index).toBe("idx");
    expect(searched[1]!.index).toBe("idx");
  });
});

// ---------------------------------------------------------------------------
// Bulk reindex path (#42)
// ---------------------------------------------------------------------------

describe("OpenSearchLexicalProvider.indexFindingBulk", () => {
  function doc(id: string, tenantId = "t1") {
    return {
      findingId: id,
      tenantId,
      classification: "phi",
      subclass: null,
      severity: "high",
      source: "cloudwatch:x",
      snippet: "<REDACTED>",
    };
  }

  it("mirrors a batch in one _bulk round-trip when the client supports it", async () => {
    const bulkCalls: Array<{
      index: string;
      docs: ReadonlyArray<{ id: string; body: Record<string, unknown> }>;
    }> = [];
    const client: OpenSearchClient = {
      async ensureIndex() {},
      async indexDoc() {
        throw new Error("should not fall back to indexDoc when bulkIndex exists");
      },
      async bulkIndex(index, docs) {
        bulkCalls.push({ index, docs });
      },
      async searchIds() {
        return [];
      },
    };
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });

    await provider.indexFindingBulk([doc("F-1"), doc("F-2"), doc("F-3")]);

    expect(bulkCalls).toHaveLength(1);
    expect(bulkCalls[0]!.index).toBe("idx");
    expect(bulkCalls[0]!.docs.map((d) => d.id)).toEqual(["F-1", "F-2", "F-3"]);
    // Each doc carries the redacted projection + tenant_id, never raw evidence.
    expect(bulkCalls[0]!.docs[0]!.body).toMatchObject({
      tenant_id: "t1",
      classification: "phi",
      snippet: "<REDACTED>",
    });
    expect(bulkCalls[0]!.docs[0]!.body).not.toHaveProperty("rawEvidence");
  });

  it("falls back to per-doc indexDoc when the client lacks bulkIndex", async () => {
    const indexed: Array<{ index: string; id: string }> = [];
    const client: OpenSearchClient = {
      async ensureIndex() {},
      async indexDoc(index, id) {
        indexed.push({ index, id });
      },
      async searchIds() {
        return [];
      },
    };
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });

    await provider.indexFindingBulk([doc("F-1"), doc("F-2")]);

    expect(indexed).toEqual([
      { index: "idx", id: "F-1" },
      { index: "idx", id: "F-2" },
    ]);
  });

  it("routes a bulk batch to the tenant's own index when per-tenant is on", async () => {
    const bulkCalls: Array<{ index: string }> = [];
    const client: OpenSearchClient = {
      async ensureIndex() {},
      async indexDoc() {},
      async bulkIndex(index) {
        bulkCalls.push({ index });
      },
      async searchIds() {
        return [];
      },
    };
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      perTenantIndex: true,
      clientFactory: async () => client,
    });

    await provider.indexFindingBulk([doc("F-1", "tenant-a")]);
    expect(bulkCalls[0]!.index).toBe(`idx-${safeTenantSegment("tenant-a")}`);
  });

  it("is a no-op for an empty batch", async () => {
    let called = false;
    const client: OpenSearchClient = {
      async ensureIndex() {
        called = true;
      },
      async indexDoc() {
        called = true;
      },
      async bulkIndex() {
        called = true;
      },
      async searchIds() {
        return [];
      },
    };
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      clientFactory: async () => client,
    });
    await provider.indexFindingBulk([]);
    expect(called).toBe(false);
  });
});

describe("resolveReindexBatchSize", () => {
  it("defaults to 500 when unset", () => {
    expect(resolveReindexBatchSize({})).toBe(500);
  });
  it("uses a valid configured value", () => {
    expect(resolveReindexBatchSize({ SEARCH_REINDEX_BATCH_SIZE: "1000" })).toBe(
      1000,
    );
  });
  it("falls back to default on non-numeric / non-integer / out-of-range", () => {
    expect(resolveReindexBatchSize({ SEARCH_REINDEX_BATCH_SIZE: "abc" })).toBe(
      500,
    );
    expect(resolveReindexBatchSize({ SEARCH_REINDEX_BATCH_SIZE: "1.5" })).toBe(
      500,
    );
    expect(resolveReindexBatchSize({ SEARCH_REINDEX_BATCH_SIZE: "0" })).toBe(500);
    expect(
      resolveReindexBatchSize({ SEARCH_REINDEX_BATCH_SIZE: "999999" }),
    ).toBe(500);
  });
});

describe("planReindexResume", () => {
  it("starts every tenant from the top when there is no resume point", () => {
    expect(planReindexResume(["a", "b", "c"])).toEqual([
      { tenantId: "a", cursor: null },
      { tenantId: "b", cursor: null },
      { tenantId: "c", cursor: null },
    ]);
    expect(planReindexResume(["a", "b"], null)).toEqual([
      { tenantId: "a", cursor: null },
      { tenantId: "b", cursor: null },
    ]);
  });

  it("skips tenants before the resume tenant and seeds it with sinceId", () => {
    // Interrupted while working tenant "b" at finding id "f5": "a" is already
    // fully mirrored and must not be re-scanned; "b" resumes after f5; later
    // tenants start from the top.
    expect(
      planReindexResume(["a", "b", "c"], { tenantId: "b", sinceId: "f5" }),
    ).toEqual([
      { tenantId: "b", cursor: "f5" },
      { tenantId: "c", cursor: null },
    ]);
  });

  it("resuming on the first tenant only seeds that tenant", () => {
    expect(
      planReindexResume(["a", "b"], { tenantId: "a", sinceId: "f9" }),
    ).toEqual([
      { tenantId: "a", cursor: "f9" },
      { tenantId: "b", cursor: null },
    ]);
  });

  it("resuming on the last tenant yields just that tenant", () => {
    expect(
      planReindexResume(["a", "b", "c"], { tenantId: "c", sinceId: "f1" }),
    ).toEqual([{ tenantId: "c", cursor: "f1" }]);
  });

  it("returns nothing when the resume tenant is absent (e.g. deleted)", () => {
    // A global `id >` filter would instead silently mis-scan other tenants;
    // here a vanished resume tenant is an explicit no-op the caller can warn on.
    expect(
      planReindexResume(["a", "b"], { tenantId: "zz", sinceId: "f1" }),
    ).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// M30: OpenSearch ILM (ISM) lifecycle tiering — opt-in, default-inert
// ---------------------------------------------------------------------------

describe("loadIlmConfigFromEnv", () => {
  it("returns undefined (inert) when OPENSEARCH_ILM_ENABLED is unset", () => {
    expect(loadIlmConfigFromEnv({})).toBeUndefined();
    expect(
      loadIlmConfigFromEnv({ OPENSEARCH_ILM_HOT_MAX_AGE: "30d" }),
    ).toBeUndefined();
  });

  it("parses the configured ages and defaults the policy name from the prefix", () => {
    const cfg = loadIlmConfigFromEnv({
      OPENSEARCH_ILM_ENABLED: "true",
      OPENSEARCH_ILM_HOT_MAX_AGE: "30d",
      OPENSEARCH_ILM_WARM_MAX_AGE: "90d",
      OPENSEARCH_ILM_DELETE_MIN_AGE: "365d",
    });
    expect(cfg).toEqual({
      policyName: "phi-audit-findings-ilm",
      hotMaxAge: "30d",
      warmMaxAge: "90d",
      deleteMinAge: "365d",
    });
  });

  it("honors an explicit policy name and derives the default from a custom prefix", () => {
    expect(
      loadIlmConfigFromEnv({
        OPENSEARCH_ILM_ENABLED: "1",
        OPENSEARCH_ILM_HOT_MAX_AGE: "7d",
        OPENSEARCH_ILM_POLICY_NAME: "my-policy",
      })?.policyName,
    ).toBe("my-policy");
    expect(
      loadIlmConfigFromEnv({
        OPENSEARCH_ILM_ENABLED: "1",
        OPENSEARCH_ILM_HOT_MAX_AGE: "7d",
        OPENSEARCH_INDEX_PREFIX: "acme-findings",
      })?.policyName,
    ).toBe("acme-findings-ilm");
  });

  it("throws when enabled but no lifecycle age is configured", () => {
    expect(() =>
      loadIlmConfigFromEnv({ OPENSEARCH_ILM_ENABLED: "true" }),
    ).toThrow(/no lifecycle ages/);
  });

  it("throws on a malformed duration", () => {
    expect(() =>
      loadIlmConfigFromEnv({
        OPENSEARCH_ILM_ENABLED: "true",
        OPENSEARCH_ILM_HOT_MAX_AGE: "30 days",
      }),
    ).toThrow(/OPENSEARCH_ILM_HOT_MAX_AGE/);
  });
});

describe("buildIsmPolicy", () => {
  it("builds the full hot→warm→cold→delete chain with min_index_age transitions", () => {
    const doc = buildIsmPolicy(
      {
        policyName: "p",
        hotMaxAge: "30d",
        warmMaxAge: "90d",
        deleteMinAge: "365d",
      },
      "phi-audit-findings",
    ) as {
      policy: {
        default_state: string;
        states: Array<{
          name: string;
          transitions: Array<{
            state_name: string;
            conditions: { min_index_age: string };
          }>;
        }>;
        ism_template: Array<{ index_patterns: string[] }>;
      };
    };
    expect(doc.policy.default_state).toBe("hot");
    expect(doc.policy.states.map((s) => s.name)).toEqual([
      "hot",
      "warm",
      "cold",
      "delete",
    ]);
    const byName = Object.fromEntries(
      doc.policy.states.map((s) => [s.name, s]),
    );
    expect(byName["hot"]!.transitions).toEqual([
      { state_name: "warm", conditions: { min_index_age: "30d" } },
    ]);
    expect(byName["warm"]!.transitions).toEqual([
      { state_name: "cold", conditions: { min_index_age: "90d" } },
    ]);
    expect(byName["cold"]!.transitions).toEqual([
      { state_name: "delete", conditions: { min_index_age: "365d" } },
    ]);
    expect(byName["delete"]!.transitions).toEqual([]);
    // Auto-attaches to every index under the prefix (shared + per-tenant).
    expect(doc.policy.ism_template[0]!.index_patterns).toEqual([
      "phi-audit-findings*",
    ]);
  });

  it("emits only reachable tiers — delete-only yields hot→delete", () => {
    const doc = buildIsmPolicy(
      { policyName: "p", deleteMinAge: "180d" },
      "idx",
    ) as {
      policy: {
        states: Array<{
          name: string;
          transitions: Array<{ state_name: string }>;
        }>;
      };
    };
    expect(doc.policy.states.map((s) => s.name)).toEqual(["hot", "delete"]);
    expect(doc.policy.states[0]!.transitions[0]!.state_name).toBe("delete");
  });
});

describe("OpenSearchLexicalProvider ILM application (fake client)", () => {
  function makeIlmClient(): {
    client: OpenSearchClient;
    ilmCalls: Array<{ name: string; body: Record<string, unknown> }>;
    ensured: string[];
  } {
    const ilmCalls: Array<{ name: string; body: Record<string, unknown> }> = [];
    const ensured: string[] = [];
    const client: OpenSearchClient = {
      async ensureIndex(index) {
        ensured.push(index);
      },
      async indexDoc() {},
      async searchIds() {
        return [];
      },
      async ensureIlmPolicy(name, body) {
        ilmCalls.push({ name, body });
      },
    };
    return { client, ilmCalls, ensured };
  }

  it("applies the policy exactly once before index creation when ILM is enabled", async () => {
    const { client, ilmCalls } = makeIlmClient();
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      ilm: { policyName: "idx-ilm", hotMaxAge: "30d", deleteMinAge: "365d" },
      clientFactory: async () => client,
    });
    await provider.search("t1", "ssn", 5);
    await provider.search("t2", "name", 5);
    await provider.indexFinding({
      findingId: "F-1",
      tenantId: "t1",
      classification: "phi",
      subclass: null,
      severity: "high",
      source: "s",
      snippet: "<REDACTED>",
    });
    // Applied once across all operations.
    expect(ilmCalls).toHaveLength(1);
    expect(ilmCalls[0]!.name).toBe("idx-ilm");
    const body = ilmCalls[0]!.body as {
      policy: { ism_template: Array<{ index_patterns: string[] }> };
    };
    expect(body.policy.ism_template[0]!.index_patterns).toEqual(["idx*"]);
  });

  it("never calls ensureIlmPolicy when ILM is not configured (byte-identical)", async () => {
    const { client, ilmCalls } = makeIlmClient();
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      clientFactory: async () => client,
    });
    await provider.search("t1", "ssn", 5);
    expect(ilmCalls).toHaveLength(0);
  });

  it("is silently skipped when the client cannot apply ISM", async () => {
    const ensured: string[] = [];
    const legacyClient: OpenSearchClient = {
      async ensureIndex(index) {
        ensured.push(index);
      },
      async indexDoc() {},
      async searchIds() {
        return [];
      },
    };
    const provider = new OpenSearchLexicalProvider({
      endpoint: "https://os",
      indexPrefix: "idx",
      ilm: { policyName: "idx-ilm", hotMaxAge: "30d" },
      clientFactory: async () => legacyClient,
    });
    // No throw even though the client lacks ensureIlmPolicy; index still ensured.
    await provider.search("t1", "ssn", 5);
    expect(ensured).toEqual(["idx"]);
  });
});

describe("createOpenSearchProvider ILM wiring", () => {
  it("passes ILM config through from env", () => {
    const p = createOpenSearchProvider({
      OPENSEARCH_ENDPOINT: "https://os.example:9200",
      OPENSEARCH_ILM_ENABLED: "true",
      OPENSEARCH_ILM_HOT_MAX_AGE: "30d",
    });
    expect(p).toBeInstanceOf(OpenSearchLexicalProvider);
  });

  it("surfaces an ILM misconfiguration as a loud boot failure", () => {
    expect(() =>
      createOpenSearchProvider({
        OPENSEARCH_ENDPOINT: "https://os.example:9200",
        OPENSEARCH_ILM_ENABLED: "true",
      }),
    ).toThrow(/no lifecycle ages/);
  });
});
