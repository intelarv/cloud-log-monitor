import { describe, expect, it } from "vitest";
import {
  ALL_PROVIDERS,
  createEmbedder,
  DEFAULT_DIM,
  DEFAULT_MODEL_BY_PROVIDER,
  isEmbedderProvider,
  loadEmbedderConfigFromEnv,
  PROVIDER_BY_DEPLOYMENT_TARGET,
} from "./embedder-config";

describe("loadEmbedderConfigFromEnv", () => {
  it("defaults to featurehash when nothing is set", () => {
    const cfg = loadEmbedderConfigFromEnv({});
    expect(cfg.provider).toBe("featurehash");
    expect(cfg.model).toBe(null);
    expect(cfg.dim).toBe(DEFAULT_DIM);
  });

  it.each([
    ["aws", "bedrock"],
    ["gcp", "vertex"],
    ["azure", "azure-openai"],
    ["local", "featurehash"],
    ["replit", "featurehash"],
  ])("maps DEPLOYMENT_TARGET=%s to provider=%s", (target, provider) => {
    const cfg = loadEmbedderConfigFromEnv({ DEPLOYMENT_TARGET: target });
    expect(cfg.provider).toBe(provider);
    expect(cfg.model).toBe(
      DEFAULT_MODEL_BY_PROVIDER[provider as keyof typeof DEFAULT_MODEL_BY_PROVIDER],
    );
  });

  it("EMBEDDING_PROVIDER overrides DEPLOYMENT_TARGET", () => {
    const cfg = loadEmbedderConfigFromEnv({
      DEPLOYMENT_TARGET: "aws",
      EMBEDDING_PROVIDER: "tei",
    });
    expect(cfg.provider).toBe("tei");
  });

  it("EMBEDDING_MODEL overrides the per-provider default", () => {
    const cfg = loadEmbedderConfigFromEnv({
      EMBEDDING_PROVIDER: "bedrock",
      EMBEDDING_MODEL: "cohere.embed-english-v3",
    });
    expect(cfg.model).toBe("cohere.embed-english-v3");
  });

  it("EMBEDDING_DIM is parsed as integer; defaults to 256", () => {
    expect(loadEmbedderConfigFromEnv({}).dim).toBe(256);
    expect(loadEmbedderConfigFromEnv({ EMBEDDING_DIM: "512" }).dim).toBe(512);
  });

  it("rejects unknown EMBEDDING_PROVIDER", () => {
    expect(() =>
      loadEmbedderConfigFromEnv({ EMBEDDING_PROVIDER: "openai-direct" }),
    ).toThrow(/not a known provider/);
  });

  it("rejects non-integer EMBEDDING_DIM", () => {
    expect(() =>
      loadEmbedderConfigFromEnv({ EMBEDDING_DIM: "not-a-number" }),
    ).toThrow(/EMBEDDING_DIM must be a positive integer/);
    expect(() =>
      loadEmbedderConfigFromEnv({ EMBEDDING_DIM: "-1" }),
    ).toThrow(/positive integer/);
    expect(() =>
      loadEmbedderConfigFromEnv({ EMBEDDING_DIM: "10.5" }),
    ).toThrow(/positive integer/);
  });

  it("falls back to featurehash on unknown DEPLOYMENT_TARGET", () => {
    expect(loadEmbedderConfigFromEnv({ DEPLOYMENT_TARGET: "moon" }).provider).toBe(
      "featurehash",
    );
  });
});

describe("isEmbedderProvider", () => {
  it("accepts every advertised provider", () => {
    for (const p of ALL_PROVIDERS) expect(isEmbedderProvider(p)).toBe(true);
  });
  it("rejects junk", () => {
    expect(isEmbedderProvider("openai")).toBe(false);
    expect(isEmbedderProvider("")).toBe(false);
  });
});

describe("createEmbedder", () => {
  it("constructs a featurehash embedder with correct dim and version", () => {
    const e = createEmbedder(
      { provider: "featurehash", model: null, dim: 256 },
      {},
    );
    expect(e.dim).toBe(256);
    // PhiGuard always wraps.
    expect(e.version).toMatch(/^phi-guard\+/);
    expect(e.version).toContain("featurehash");
  });

  it("respects custom dim for featurehash", () => {
    const e = createEmbedder(
      { provider: "featurehash", model: null, dim: 128 },
      {},
    );
    expect(e.dim).toBe(128);
  });

  it("constructs bedrock without making network calls (lazy SDK load)", () => {
    const e = createEmbedder(
      { provider: "bedrock", model: "amazon.titan-embed-text-v2:0", dim: 256 },
      { AWS_REGION: "us-east-1" },
    );
    expect(e.dim).toBe(256);
    expect(e.version).toBe("phi-guard+bedrock:amazon.titan-embed-text-v2:0:256");
  });

  it("rejects unsupported dim for bedrock titan v2", () => {
    expect(() =>
      createEmbedder(
        { provider: "bedrock", model: "amazon.titan-embed-text-v2:0", dim: 999 },
        {},
      ),
    ).toThrow(/dim ∈ \{256, 512, 1024\}/);
  });

  it("requires GCP_PROJECT_ID for vertex", () => {
    expect(() =>
      createEmbedder(
        { provider: "vertex", model: "text-embedding-005", dim: 256 },
        {},
      ),
    ).toThrow(/GCP_PROJECT_ID is required/);
  });

  it("constructs vertex with required env", () => {
    const e = createEmbedder(
      { provider: "vertex", model: "text-embedding-005", dim: 256 },
      { GCP_PROJECT_ID: "my-proj", GCP_LOCATION: "us-central1" },
    );
    expect(e.dim).toBe(256);
    expect(e.version).toContain("vertex:text-embedding-005:256");
  });

  it("requires Azure endpoint/api-key/deployment", () => {
    expect(() =>
      createEmbedder(
        { provider: "azure-openai", model: "text-embedding-3-small", dim: 256 },
        {},
      ),
    ).toThrow(/AZURE_OPENAI_ENDPOINT is required/);
  });

  it("constructs azure-openai with required env", () => {
    const e = createEmbedder(
      { provider: "azure-openai", model: "text-embedding-3-small", dim: 256 },
      {
        AZURE_OPENAI_ENDPOINT: "https://x.openai.azure.com",
        AZURE_OPENAI_API_KEY: "k",
        AZURE_OPENAI_DEPLOYMENT: "my-embed",
      },
    );
    expect(e.version).toContain("azure-openai:text-embedding-3-small:256");
  });

  it("requires TEI_ENDPOINT for tei", () => {
    expect(() =>
      createEmbedder({ provider: "tei", model: null, dim: 256 }, {}),
    ).toThrow(/TEI_ENDPOINT is required/);
  });

  it("constructs tei with endpoint", () => {
    const e = createEmbedder(
      { provider: "tei", model: "nomic-embed-text-v1.5", dim: 768 },
      { TEI_ENDPOINT: "http://tei.svc:80" },
    );
    expect(e.dim).toBe(768);
    expect(e.version).toContain("tei:nomic-embed-text-v1.5:768");
  });

  it("PhiGuard wraps every provider (defense-in-depth on outbound text)", () => {
    const each = [
      createEmbedder({ provider: "featurehash", model: null, dim: 256 }, {}),
      createEmbedder(
        { provider: "tei", model: "x", dim: 256 },
        { TEI_ENDPOINT: "http://x" },
      ),
    ];
    for (const e of each) expect(e.version.startsWith("phi-guard+")).toBe(true);
  });
});

describe("provider/target tables (documentation invariants)", () => {
  it("every provider has a default model entry", () => {
    for (const p of ALL_PROVIDERS) {
      expect(p in DEFAULT_MODEL_BY_PROVIDER).toBe(true);
    }
  });
  it("every deployment-target shortcut maps to a real provider", () => {
    for (const v of Object.values(PROVIDER_BY_DEPLOYMENT_TARGET)) {
      expect(ALL_PROVIDERS).toContain(v);
    }
  });
});
