import { logger } from "./logger";
import {
  FeatureHashEmbedder,
  PhiGuardEmbedder,
  type Embedder,
} from "./embeddings";
import {
  AzureOpenAIEmbedder,
  BedrockTitanEmbedder,
  TextEmbeddingsInferenceEmbedder,
  VertexAIEmbedder,
} from "./cloud-embedders";

// ---------------------------------------------------------------------------
// Cloud-aware embedder selection
// ---------------------------------------------------------------------------
//
// Production swaps embedders per deployment target via env config; dev uses
// the deterministic FeatureHashEmbedder. The hybrid-search code, the
// embedding column, and the backfill job do not change — only the bound
// implementation behind getEmbedder() changes.
//
// Configuration precedence (highest to lowest):
//   1. EMBEDDING_PROVIDER         — explicit override (any value below)
//   2. DEPLOYMENT_TARGET          — cloud-shortcut: aws / gcp / azure / local
//   3. (default)                  — featurehash
//
// Each provider has a default model that is BAA-friendly and Matryoshka-
// truncatable to 256 dims. EMBEDDING_MODEL overrides per-provider default.
// EMBEDDING_DIM overrides the target dim (must match the DB column).
// ---------------------------------------------------------------------------

export type EmbedderProvider =
  | "featurehash"
  | "bedrock"
  | "vertex"
  | "azure-openai"
  | "tei";

export const ALL_PROVIDERS: readonly EmbedderProvider[] = [
  "featurehash",
  "bedrock",
  "vertex",
  "azure-openai",
  "tei",
];

// Default model per provider. All chosen to be BAA-eligible (where applicable)
// and to natively support 256-dim output via Matryoshka, so the DB column dim
// stays portable across providers without retraining.
export const DEFAULT_MODEL_BY_PROVIDER: Record<EmbedderProvider, string | null> = {
  featurehash: null, // No model — feature hashing.
  bedrock: "amazon.titan-embed-text-v2:0", // 256 / 512 / 1024-dim Matryoshka
  vertex: "text-embedding-005", // outputDimensionality Matryoshka
  "azure-openai": "text-embedding-3-small", // `dimensions` Matryoshka
  tei: "self-hosted", // model is decided by the TEI server's launch flags
};

// Deployment-target → provider shortcut. Operators on each cloud usually pick
// the provider native to that cloud's BAA story; this saves them setting two
// env vars.
export const PROVIDER_BY_DEPLOYMENT_TARGET: Record<string, EmbedderProvider> = {
  aws: "bedrock",
  gcp: "vertex",
  azure: "azure-openai",
  local: "featurehash",
  dev: "featurehash",
  replit: "featurehash",
};

export const DEFAULT_DIM = 256;

export interface EmbedderConfig {
  provider: EmbedderProvider;
  model: string | null;
  dim: number;
}

export function isEmbedderProvider(s: string): s is EmbedderProvider {
  return (ALL_PROVIDERS as readonly string[]).includes(s);
}

/**
 * Parse env vars into an EmbedderConfig. Pure function: no I/O, no side
 * effects, no SDK loading. Throws on invalid input rather than silently
 * falling back.
 */
export function loadEmbedderConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): EmbedderConfig {
  const explicit = env["EMBEDDING_PROVIDER"]?.trim().toLowerCase();
  const target = env["DEPLOYMENT_TARGET"]?.trim().toLowerCase();

  let provider: EmbedderProvider;
  if (explicit) {
    if (!isEmbedderProvider(explicit)) {
      throw new Error(
        `EMBEDDING_PROVIDER=${explicit} is not a known provider. ` +
          `Valid: ${ALL_PROVIDERS.join(", ")}`,
      );
    }
    provider = explicit;
  } else if (target && target in PROVIDER_BY_DEPLOYMENT_TARGET) {
    provider = PROVIDER_BY_DEPLOYMENT_TARGET[target]!;
  } else {
    provider = "featurehash";
  }

  const model = env["EMBEDDING_MODEL"]?.trim() || DEFAULT_MODEL_BY_PROVIDER[provider];

  const dimStr = env["EMBEDDING_DIM"]?.trim();
  const dim = dimStr ? Number(dimStr) : DEFAULT_DIM;
  if (!Number.isFinite(dim) || dim <= 0 || !Number.isInteger(dim)) {
    throw new Error(`EMBEDDING_DIM must be a positive integer, got: ${dimStr}`);
  }

  return { provider, model, dim };
}

/**
 * Construct the embedder for a given config. The PhiGuardEmbedder is always
 * wrapped around the inner provider — outbound text to a third-party model
 * endpoint is PHI-scanned before it ever reaches the wire. (Defense in depth:
 * the pipeline already feeds redacted text only.)
 */
export function createEmbedder(
  cfg: EmbedderConfig,
  env: NodeJS.ProcessEnv = process.env,
): Embedder {
  let inner: Embedder;
  switch (cfg.provider) {
    case "featurehash":
      inner = new FeatureHashEmbedder({ dim: cfg.dim });
      break;
    case "bedrock":
      inner = new BedrockTitanEmbedder({
        model: cfg.model ?? DEFAULT_MODEL_BY_PROVIDER.bedrock!,
        dim: cfg.dim,
        region: env["AWS_REGION"] ?? "us-east-1",
      });
      break;
    case "vertex":
      inner = new VertexAIEmbedder({
        model: cfg.model ?? DEFAULT_MODEL_BY_PROVIDER.vertex!,
        dim: cfg.dim,
        project: requireEnv(env, "GCP_PROJECT_ID"),
        location: env["GCP_LOCATION"] ?? "us-central1",
      });
      break;
    case "azure-openai":
      inner = new AzureOpenAIEmbedder({
        model: cfg.model ?? DEFAULT_MODEL_BY_PROVIDER["azure-openai"]!,
        dim: cfg.dim,
        endpoint: requireEnv(env, "AZURE_OPENAI_ENDPOINT"),
        apiKey: requireEnv(env, "AZURE_OPENAI_API_KEY"),
        deployment: requireEnv(env, "AZURE_OPENAI_DEPLOYMENT"),
        apiVersion: env["AZURE_OPENAI_API_VERSION"] ?? "2024-02-01",
      });
      break;
    case "tei":
      inner = new TextEmbeddingsInferenceEmbedder({
        endpoint: requireEnv(env, "TEI_ENDPOINT"),
        dim: cfg.dim,
        modelName: cfg.model ?? "self-hosted",
        ...(env["TEI_BEARER_TOKEN"]
          ? { bearerToken: env["TEI_BEARER_TOKEN"] }
          : {}),
      });
      break;
  }
  return new PhiGuardEmbedder(inner);
}

function requireEnv(env: NodeJS.ProcessEnv, name: string): string {
  const v = env[name]?.trim();
  if (!v) {
    throw new Error(
      `${name} is required for the configured embedder provider`,
    );
  }
  return v;
}

// ---------------------------------------------------------------------------
// Module-level embedder registry
// ---------------------------------------------------------------------------
//
// Set once at boot by initEmbedderFromEnv(). Consumed by search.ts and
// backfillEmbeddings via getEmbedder(). Tests inject explicitly via the
// existing `opts.embedder` override on search functions — no global state in
// the test path.

let currentEmbedder: Embedder | null = null;

export function setEmbedder(e: Embedder): void {
  currentEmbedder = e;
}

export function getEmbedder(): Embedder {
  if (!currentEmbedder) {
    throw new Error(
      "Embedder not initialized. Call initEmbedderFromEnv() at boot.",
    );
  }
  return currentEmbedder;
}

/** For tests that need to reset module state between cases. */
export function resetEmbedderForTests(): void {
  currentEmbedder = null;
}

export function initEmbedderFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { config: EmbedderConfig; embedder: Embedder } {
  const config = loadEmbedderConfigFromEnv(env);
  const embedder = createEmbedder(config, env);
  setEmbedder(embedder);
  logger.info(
    {
      provider: config.provider,
      model: config.model,
      dim: config.dim,
      version: embedder.version,
    },
    "Embedder initialized",
  );
  return { config, embedder };
}
