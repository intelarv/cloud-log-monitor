import { logger } from "./logger";
import { type NerProvider, NoopNerProvider } from "./ner";
import {
  AwsComprehendNerProvider,
  GcpDlpNerProvider,
  AzureLanguageNerProvider,
} from "./cloud-ner";
import { PresidioNerProvider } from "./presidio-ner";
import { LocalGazetteerNerProvider } from "./local-ner";

// ---------------------------------------------------------------------------
// Cloud-aware Stage-2 NER provider selection.
//
// Mirrors the embedder / lexical-search / raw-evidence factories: a pure env
// parse, a lazy provider construction, and a module-level registry set once at
// boot. The default is `none` (NoopNerProvider) so Stage-2 is INERT — the
// offline eval gate stays byte-identical and no cloud SDK is imported until an
// operator opts in with `NER_PROVIDER`.
//
// Like SEARCH_PROVIDER (and unlike the embedder/LLM factories) there is NO
// DEPLOYMENT_TARGET shortcut: every NER backend needs its own explicit
// endpoint/region/credentials, and auto-selecting one from DEPLOYMENT_TARGET
// would silently start shipping log text to a service the operator never
// provisioned. Selection is therefore always explicit.
//
// `presidio` is the credential-account-free production backend: a self-hosted
// Microsoft Presidio Analyzer (a real spaCy/transformer NER engine) reached
// over HTTP. Unlike the three cloud SaaS backends it needs no cloud BAA — the
// analyzer is operator-hosted in the deployment's own trust zone (see
// presidio-ner.ts). It is still default-OFF and uses no SDK (global fetch), so
// the credential-free eval gate stays byte-identical.
//
// `local` is the credential-free, NO-service option (local-ner.ts): a pure
// in-process gazetteer over the Stage-1 name dictionaries that recalls the
// un-anchored dictionary-name slice Stage-1 omits for precision. No SDK, no
// network, no model weights — so it can't OOM the dev sandbox and the
// credential-free eval gate stays byte-identical (it is still default-OFF).
//
// Configuration precedence (highest to lowest):
//   1. NER_PROVIDER  — explicit ("none" | "local" | "presidio" | "aws-comprehend" | "gcp-dlp" | "azure-language")
//   2. (default)     — none
// ---------------------------------------------------------------------------

export type NerProviderKind =
  | "none"
  | "local"
  | "presidio"
  | "aws-comprehend"
  | "gcp-dlp"
  | "azure-language";

export const ALL_NER_PROVIDERS: readonly NerProviderKind[] = [
  "none",
  "local",
  "presidio",
  "aws-comprehend",
  "gcp-dlp",
  "azure-language",
];

export function isNerProviderKind(s: string): s is NerProviderKind {
  return (ALL_NER_PROVIDERS as readonly string[]).includes(s);
}

export interface NerProviderConfig {
  provider: NerProviderKind;
}

/** Parse env into a NerProviderConfig. Pure: no I/O, no SDK loading. Throws on
 *  an unknown provider rather than silently falling back to none. */
export function loadNerProviderConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): NerProviderConfig {
  const explicit = env["NER_PROVIDER"]?.trim().toLowerCase();
  let provider: NerProviderKind = "none";
  if (explicit) {
    if (!isNerProviderKind(explicit)) {
      throw new Error(
        `NER_PROVIDER=${explicit} is not a known provider. ` +
          `Valid: ${ALL_NER_PROVIDERS.join(", ")}`,
      );
    }
    provider = explicit;
  }
  return { provider };
}

/** Construct the provider for a config. Cloud impls are lazy — their SDKs are
 *  only imported when `detect()` first runs (see cloud-ner.ts), so a dev /
 *  eval install never pulls a cloud NER SDK. Throws when a selected cloud
 *  provider is missing its required endpoint/region/credentials env. */
export function createNerProvider(
  cfg: NerProviderConfig,
  env: NodeJS.ProcessEnv = process.env,
): NerProvider {
  switch (cfg.provider) {
    case "none":
      return new NoopNerProvider();
    case "local": {
      const raw = env["NER_LOCAL_MIN_TOKEN_LEN"]?.trim();
      let minTokenLen: number | undefined;
      if (raw) {
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 1) {
          throw new Error(
            `NER_LOCAL_MIN_TOKEN_LEN must be a positive integer, got "${raw}"`,
          );
        }
        minTokenLen = n;
      }
      const capRaw = env["NER_LOCAL_CAPITALIZED_ONLY"]?.trim().toLowerCase();
      // Default true; only an explicit "false"/"0" lowers precision to recall
      // lowercased names.
      const capitalizedOnly = !(capRaw === "false" || capRaw === "0");
      return new LocalGazetteerNerProvider({ minTokenLen, capitalizedOnly });
    }
    case "presidio": {
      const raw = env["NER_PRESIDIO_SCORE_THRESHOLD"]?.trim();
      // Reject NaN / out-of-range so a typo silently disabling filtering (NaN
      // comparisons are always false ⇒ every span kept) fails loud at boot
      // rather than degrading precision in production.
      let scoreThreshold: number | undefined;
      if (raw) {
        const n = Number(raw);
        if (!Number.isFinite(n) || n < 0 || n > 1) {
          throw new Error(
            `NER_PRESIDIO_SCORE_THRESHOLD must be a number in [0,1], got "${raw}"`,
          );
        }
        scoreThreshold = n;
      }
      return new PresidioNerProvider({
        endpoint: requireEnv(env, "NER_PRESIDIO_ENDPOINT"),
        language: env["NER_PRESIDIO_LANGUAGE"]?.trim() || "en",
        scoreThreshold,
      });
    }
    case "aws-comprehend":
      return new AwsComprehendNerProvider({
        region: requireEnv(env, "NER_AWS_REGION", "AWS_REGION"),
        languageCode: env["NER_LANGUAGE"]?.trim() || "en",
      });
    case "gcp-dlp":
      return new GcpDlpNerProvider({
        projectId: requireEnv(env, "NER_GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT"),
      });
    case "azure-language":
      return new AzureLanguageNerProvider({
        endpoint: requireEnv(env, "NER_AZURE_ENDPOINT"),
        apiKey: requireEnv(env, "NER_AZURE_API_KEY"),
        language: env["NER_LANGUAGE"]?.trim() || "en",
      });
  }
}

function requireEnv(
  env: NodeJS.ProcessEnv,
  primary: string,
  fallback?: string,
): string {
  const v = env[primary]?.trim() || (fallback ? env[fallback]?.trim() : undefined);
  if (!v) {
    throw new Error(
      `NER provider requires ${primary}${fallback ? ` (or ${fallback})` : ""} to be set.`,
    );
  }
  return v;
}

// ---------------------------------------------------------------------------
// Module-level provider registry
// ---------------------------------------------------------------------------
//
// Set once at boot by initNerProviderFromEnv(). Consumed by the ingest hot path
// via getNerProviderOrNull(), which returns null when NER is inert so ingest
// skips the async Stage-2 call entirely (no extra await on the default path).
// Tests inject explicitly.

let currentProvider: NerProvider | null = null;

export function setNerProvider(p: NerProvider): void {
  currentProvider = p;
}

/** The active provider, or null when NER is unconfigured/inert. Ingest treats
 *  null (and the noop provider) as "skip Stage-2". */
export function getNerProviderOrNull(): NerProvider | null {
  if (!currentProvider || currentProvider.name === "noop") return null;
  return currentProvider;
}

/** For tests that need to reset module state between cases. */
export function resetNerProviderForTests(): void {
  currentProvider = null;
}

export function initNerProviderFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { config: NerProviderConfig; provider: NerProvider } {
  const config = loadNerProviderConfigFromEnv(env);
  const provider = createNerProvider(config, env);
  setNerProvider(provider);
  logger.info({ provider: config.provider }, "Stage-2 NER provider initialized");
  return { config, provider };
}
