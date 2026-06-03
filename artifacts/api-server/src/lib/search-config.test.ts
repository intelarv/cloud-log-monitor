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
  type OpenSearchClient,
} from "./cloud-search";

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
