import { sql } from "drizzle-orm";
import { withTenant } from "./db-context";
import { logger } from "./logger";
import { createOpenSearchProvider } from "./cloud-search";
import type { RetrievalHit } from "./search";

// ---------------------------------------------------------------------------
// Cloud-aware lexical (BM25) search provider selection
// ---------------------------------------------------------------------------
//
// The hybrid retriever fuses a lexical (BM25) leg with a dense (pgvector) leg
// via RRF (see search.ts). The lexical leg is the part that scales out in
// production — dev runs it on Postgres FTS (`search_tsv` + `ts_rank_cd`);
// production can route it to a managed OpenSearch cluster instead. This module
// is the seam: it selects + holds the active LexicalSearchProvider, mirroring
// the embedder registry in embedder-config.ts.
//
// The dense leg, the RRF fusion, and the RLS-checked hydrate in search.ts do
// NOT change when the lexical provider changes — only the bound implementation
// behind getSearchProvider() does.
//
// Configuration precedence (highest to lowest):
//   1. SEARCH_PROVIDER   — explicit override ("postgres" | "opensearch")
//   2. (default)         — postgres
//
// NOTE: unlike the embedder/LLM factories, there is intentionally NO
// DEPLOYMENT_TARGET shortcut here. OpenSearch is cloud-agnostic (AWS managed
// OpenSearch, self-hosted on any cloud, etc.) and ALWAYS needs an explicit
// `OPENSEARCH_ENDPOINT`; a bare cloud shortcut could not actually connect.
// Auto-selecting it from DEPLOYMENT_TARGET would also silently break existing
// cloud deployments that set DEPLOYMENT_TARGET only for the embedder/LLM but
// never provisioned an OpenSearch cluster. Selection is therefore explicit.
// ---------------------------------------------------------------------------

export type SearchProvider = "postgres" | "opensearch";

export const ALL_SEARCH_PROVIDERS: readonly SearchProvider[] = [
  "postgres",
  "opensearch",
];

export function isSearchProvider(s: string): s is SearchProvider {
  return (ALL_SEARCH_PROVIDERS as readonly string[]).includes(s);
}

export interface SearchProviderConfig {
  provider: SearchProvider;
}

/** A redacted, safe-projection document mirrored into an external lexical
 *  index. NEVER carries raw evidence — only the same redacted fields the
 *  agent prompt and findings_redacted view already expose (threat_model
 *  §Information Disclosure: PHI must not enter a searchable hot tier). */
export interface LexicalSearchDoc {
  findingId: string;
  tenantId: string;
  classification: string;
  subclass: string | null;
  severity: string;
  source: string;
  snippet: string;
}

/** The lexical-retriever seam. `search` returns ranked finding ids
 *  (rank-1 first) scoped to the tenant; `indexFinding` mirrors a redacted
 *  doc into the backend's index. */
export interface LexicalSearchProvider {
  readonly name: string;
  /** Whether this provider maintains its own external index that must be
   *  populated on ingest + reconciled at boot. False for Postgres, whose
   *  generated `search_tsv` column is always in sync with the row. */
  readonly maintainsExternalIndex: boolean;
  search(
    tenantId: string,
    query: string,
    limit: number,
  ): Promise<RetrievalHit[]>;
  indexFinding(doc: LexicalSearchDoc): Promise<void>;
  /** Mirror a batch of redacted docs in one round-trip. Optional: providers
   *  that don't maintain an external index (Postgres) omit it; callers that
   *  want batching fall back to per-doc `indexFinding` when it's absent. All
   *  docs in a single call MUST belong to the same tenant (the reconcile loop
   *  batches inside a per-tenant `withTenant` scope). */
  indexFindingBulk?(docs: ReadonlyArray<LexicalSearchDoc>): Promise<void>;
}

// ---------------------------------------------------------------------------
// Postgres FTS provider (dev default)
// ---------------------------------------------------------------------------

/** Default lexical provider: Postgres full-text search over the generated
 *  `search_tsv` column. Runs inside `withTenant(...)` so RLS isolates the
 *  caller's tenant regardless of any bug here. `indexFinding` is a no-op
 *  because the tsv column is maintained by Postgres on every row write. */
export class PostgresLexicalSearchProvider implements LexicalSearchProvider {
  readonly name = "postgres";
  readonly maintainsExternalIndex = false;

  async search(
    tenantId: string,
    query: string,
    limit: number,
  ): Promise<RetrievalHit[]> {
    return withTenant(tenantId, async (tx) => {
      // `websearch_to_tsquery` parses Google-style queries; empty/no-match
      // queries return zero rows rather than erroring.
      const rows = await tx.execute<{ id: string }>(sql`
        SELECT id
        FROM findings
        WHERE tenant_id = ${tenantId}
          AND search_tsv @@ websearch_to_tsquery('english', ${query})
        ORDER BY ts_rank_cd(search_tsv, websearch_to_tsquery('english', ${query})) DESC,
                 last_seen_at DESC,
                 id
        LIMIT ${limit}
      `);
      return rows.rows.map((r, i) => ({ finding_id: r.id, rank: i + 1 }));
    });
  }

  async indexFinding(_doc: LexicalSearchDoc): Promise<void> {
    // No-op: the `search_tsv` generated column keeps the lexical index in
    // lockstep with the row, so there is nothing to mirror.
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Parse env into a SearchProviderConfig. Pure: no I/O, no SDK loading.
 *  Throws on an unknown provider rather than silently falling back. */
export function loadSearchProviderConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): SearchProviderConfig {
  const explicit = env["SEARCH_PROVIDER"]?.trim().toLowerCase();
  let provider: SearchProvider = "postgres";
  if (explicit) {
    if (!isSearchProvider(explicit)) {
      throw new Error(
        `SEARCH_PROVIDER=${explicit} is not a known provider. ` +
          `Valid: ${ALL_SEARCH_PROVIDERS.join(", ")}`,
      );
    }
    provider = explicit;
  }
  return { provider };
}

/** Construct the provider for a config. The OpenSearch impl is lazy — its
 *  SDK is only imported when a query/index actually runs (see cloud-search.ts),
 *  so a dev install never pulls `@opensearch-project/opensearch`. */
export function createSearchProvider(
  cfg: SearchProviderConfig,
  env: NodeJS.ProcessEnv = process.env,
): LexicalSearchProvider {
  switch (cfg.provider) {
    case "postgres":
      return new PostgresLexicalSearchProvider();
    case "opensearch":
      return createOpenSearchProvider(env);
  }
}

// ---------------------------------------------------------------------------
// Module-level provider registry
// ---------------------------------------------------------------------------
//
// Set once at boot by initSearchProviderFromEnv(). Consumed by search.ts
// (hybridSearchFindings, reconcileSearchIndex) via getSearchProvider() and by
// ingest.ts via getSearchProviderOrNull() (ingest never throws on an
// unconfigured provider — it just skips mirroring). Tests inject explicitly.

let currentProvider: LexicalSearchProvider | null = null;

export function setSearchProvider(p: LexicalSearchProvider): void {
  currentProvider = p;
}

export function getSearchProvider(): LexicalSearchProvider {
  if (!currentProvider) {
    throw new Error(
      "Search provider not initialized. Call initSearchProviderFromEnv() at boot.",
    );
  }
  return currentProvider;
}

/** Like getSearchProvider() but returns null instead of throwing when no
 *  provider is registered. Used by the ingest hot path so an unconfigured
 *  (or test) environment simply skips external indexing. */
export function getSearchProviderOrNull(): LexicalSearchProvider | null {
  return currentProvider;
}

/** For tests that need to reset module state between cases. */
export function resetSearchProviderForTests(): void {
  currentProvider = null;
}

export function initSearchProviderFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { config: SearchProviderConfig; provider: LexicalSearchProvider } {
  const config = loadSearchProviderConfigFromEnv(env);
  const provider = createSearchProvider(config, env);
  setSearchProvider(provider);
  logger.info(
    {
      provider: config.provider,
      maintains_external_index: provider.maintainsExternalIndex,
    },
    "Lexical search provider initialized",
  );
  return { config, provider };
}
