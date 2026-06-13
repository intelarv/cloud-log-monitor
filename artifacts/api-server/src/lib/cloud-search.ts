// M10.1: OpenSearch lexical-search provider.
//
// Mirrors the lazy-load pattern in cloud-embedders.ts / cloud-log-sources.ts:
// the SDK import is hidden from the TS static analyzer via a variable-aliased
// dynamic import, so `@opensearch-project/opensearch` is an OPTIONAL
// dependency — a dev install never pulls it. Operators install it only when
// they set SEARCH_PROVIDER=opensearch.
//
// Per threat_model §Information Disclosure: only redacted, safe-projection
// fields are ever indexed (LexicalSearchDoc), so raw PHI never enters the
// searchable hot tier. Every query carries a mandatory `tenant_id` term
// filter; the RLS-checked hydrate in search.ts is the backstop so a missing
// filter can never leak cross-tenant rows into a prompt.

import { createHash } from "node:crypto";
import { logger } from "./logger";
import type { LexicalSearchDoc, LexicalSearchProvider } from "./search-config";
import type { RetrievalHit } from "./search";

// ----- SDK lazy loader -------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

// ----- Thin, SDK-agnostic client shape ---------------------------------

/** The minimal client surface the provider uses. The real
 *  `@opensearch-project/opensearch` client returns `{ body: ... }` envelopes;
 *  the lazy loader adapts those to this shape so the provider stays
 *  SDK-agnostic and trivial to mock in tests via `clientFactory`. */
export interface OpenSearchClient {
  ensureIndex(index: string): Promise<void>;
  indexDoc(
    index: string,
    id: string,
    body: Record<string, unknown>,
  ): Promise<void>;
  /** Bulk-index many docs into ONE index in a single round-trip (`_bulk`).
   *  Optional: a custom/legacy client may omit it, in which case the provider
   *  falls back to per-doc `indexDoc`. */
  bulkIndex?(
    index: string,
    docs: ReadonlyArray<{ id: string; body: Record<string, unknown> }>,
  ): Promise<void>;
  /** Returns the matched document ids in score order (best first). */
  searchIds(index: string, body: Record<string, unknown>): Promise<string[]>;
}

export interface OpenSearchProviderOpts {
  readonly endpoint: string;
  readonly indexPrefix?: string;
  readonly username?: string;
  readonly password?: string;
  /** When true, each tenant's findings live in their OWN index
   *  (`${indexPrefix}-${safeTenantSegment(tenantId)}`) instead of one shared
   *  index scoped only by a `tenant_id` term filter. Off by default ⇒
   *  byte-identical to the pre-isolation single-index behavior. */
  readonly perTenantIndex?: boolean;
  /** Test injection: bypass the real SDK loader. */
  readonly clientFactory?: () => Promise<OpenSearchClient>;
}

const DEFAULT_INDEX_PREFIX = "phi-audit-findings";

/** Derive a per-tenant index suffix that is a valid OpenSearch index segment
 *  AND collision-free across tenants. OpenSearch index names must be lowercase
 *  and exclude `\\ / * ? " < > | , #` / spaces, so we (1) lowercase + replace
 *  every unsafe char with `-` for a human-readable, bounded prefix, then (2)
 *  append a short hash of the RAW tenant id. The hash guarantees two distinct
 *  tenant ids can never sanitize to the same index — without it, e.g. `a/b` and
 *  `a-b` would collide and physically co-mingle two tenants' documents, which
 *  is exactly the cross-tenant leak this isolation is meant to prevent. */
export function safeTenantSegment(tenantId: string): string {
  const readable = tenantId
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, "-")
    .replace(/^[-_]+/, "")
    .slice(0, 40);
  const hash = createHash("sha256").update(tenantId).digest("hex").slice(0, 12);
  return readable ? `${readable}-${hash}` : hash;
}

export class OpenSearchLexicalProvider implements LexicalSearchProvider {
  readonly name = "opensearch";
  readonly maintainsExternalIndex = true;
  private clientPromise: Promise<OpenSearchClient> | null = null;
  private readonly ensured = new Set<string>();
  private readonly indexPrefix: string;
  private readonly perTenantIndex: boolean;

  constructor(private readonly opts: OpenSearchProviderOpts) {
    this.indexPrefix = opts.indexPrefix ?? DEFAULT_INDEX_PREFIX;
    this.perTenantIndex = opts.perTenantIndex ?? false;
  }

  /** The index a given tenant's documents live in. By default this is a single
   *  shared index scoped only by the mandatory per-query `tenant_id` filter.
   *  When `perTenantIndex` is on, each tenant gets a physically separate index
   *  so a search-layer bug can never even address another tenant's documents —
   *  the term filter remains as defense-in-depth on top. */
  private indexName(tenantId: string): string {
    return this.perTenantIndex
      ? `${this.indexPrefix}-${safeTenantSegment(tenantId)}`
      : this.indexPrefix;
  }

  private async getClient(): Promise<OpenSearchClient> {
    if (this.opts.clientFactory) return this.opts.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          mod = await loadOptional("@opensearch-project/opensearch");
        } catch {
          throw new Error(
            "SEARCH_PROVIDER=opensearch selected but " +
              "@opensearch-project/opensearch is not installed. Run: " +
              "pnpm --filter @workspace/api-server add @opensearch-project/opensearch",
          );
        }
        const auth =
          this.opts.username && this.opts.password
            ? { username: this.opts.username, password: this.opts.password }
            : undefined;
        const native = new mod.Client({
          node: this.opts.endpoint,
          ...(auth ? { auth } : {}),
        });
        return {
          async ensureIndex(index: string): Promise<void> {
            const existsResp = await native.indices.exists({ index });
            // opensearch-js returns `{ body: boolean }`; some transports
            // return the boolean directly. Handle both.
            const exists =
              typeof existsResp?.body === "boolean"
                ? existsResp.body
                : Boolean(existsResp);
            if (exists) return;
            try {
              await native.indices.create({
                index,
                body: {
                  mappings: {
                    properties: {
                      tenant_id: { type: "keyword" },
                      classification: { type: "text" },
                      subclass: { type: "text" },
                      severity: { type: "keyword" },
                      source: { type: "text" },
                      snippet: { type: "text" },
                    },
                  },
                },
              });
            } catch (err) {
              // A concurrent boot may have created it between exists+create.
              // Re-check; only rethrow if it still doesn't exist.
              const recheck = await native.indices.exists({ index });
              const ok =
                typeof recheck?.body === "boolean"
                  ? recheck.body
                  : Boolean(recheck);
              if (!ok) throw err;
            }
          },
          async indexDoc(
            index: string,
            id: string,
            body: Record<string, unknown>,
          ): Promise<void> {
            await native.index({ index, id, body, refresh: false });
          },
          async bulkIndex(
            index: string,
            docs: ReadonlyArray<{ id: string; body: Record<string, unknown> }>,
          ): Promise<void> {
            if (docs.length === 0) return;
            // `_bulk` takes an action/source NDJSON pair per doc.
            const operations = docs.flatMap((d) => [
              { index: { _index: index, _id: d.id } },
              d.body,
            ]);
            const resp = await native.bulk({ body: operations, refresh: false });
            const payload = resp?.body ?? resp;
            if (payload?.errors) {
              const firstErr = (payload.items as ReadonlyArray<
                Record<string, { error?: { reason?: string } }>
              >)
                .map((it) => Object.values(it)[0]?.error?.reason)
                .find((r): r is string => Boolean(r));
              throw new Error(
                `OpenSearch _bulk reported item errors${
                  firstErr ? `: ${firstErr}` : ""
                }`,
              );
            }
          },
          async searchIds(
            index: string,
            body: Record<string, unknown>,
          ): Promise<string[]> {
            const resp = await native.search({ index, body });
            const hits =
              resp?.body?.hits?.hits ?? resp?.hits?.hits ?? [];
            return (hits as ReadonlyArray<{ _id: string }>).map((h) => h._id);
          },
        } satisfies OpenSearchClient;
      })();
    }
    return this.clientPromise;
  }

  private async ensureIndexOnce(
    client: OpenSearchClient,
    index: string,
  ): Promise<void> {
    if (this.ensured.has(index)) return;
    await client.ensureIndex(index);
    this.ensured.add(index);
  }

  async search(
    tenantId: string,
    query: string,
    limit: number,
  ): Promise<RetrievalHit[]> {
    if (!query.trim()) return [];
    const client = await this.getClient();
    const index = this.indexName(tenantId);
    await this.ensureIndexOnce(client, index);
    const ids = await client.searchIds(index, {
      size: limit,
      _source: false,
      query: {
        bool: {
          // Mandatory tenant isolation — defense in depth ahead of the
          // RLS-checked hydrate in search.ts.
          filter: [{ term: { tenant_id: tenantId } }],
          must: [
            {
              multi_match: {
                query,
                fields: [
                  "snippet^2",
                  "classification",
                  "subclass",
                  "source",
                  "severity",
                ],
              },
            },
          ],
        },
      },
    });
    return ids.map((id, i) => ({ finding_id: id, rank: i + 1 }));
  }

  async indexFindingBulk(docs: ReadonlyArray<LexicalSearchDoc>): Promise<void> {
    if (docs.length === 0) return;
    const client = await this.getClient();
    // Caller contract: all docs share a tenant, so they all route to one index.
    const index = this.indexName(docs[0]!.tenantId);
    await this.ensureIndexOnce(client, index);
    const payloads = docs.map((doc) => ({
      id: doc.findingId,
      body: {
        tenant_id: doc.tenantId,
        classification: doc.classification,
        subclass: doc.subclass,
        severity: doc.severity,
        source: doc.source,
        snippet: doc.snippet,
      } as Record<string, unknown>,
    }));
    if (client.bulkIndex) {
      await client.bulkIndex(index, payloads);
      return;
    }
    // Fallback for a client without _bulk support: per-doc index.
    for (const p of payloads) {
      await client.indexDoc(index, p.id, p.body);
    }
  }

  async indexFinding(doc: LexicalSearchDoc): Promise<void> {
    const client = await this.getClient();
    const index = this.indexName(doc.tenantId);
    await this.ensureIndexOnce(client, index);
    await client.indexDoc(index, doc.findingId, {
      tenant_id: doc.tenantId,
      classification: doc.classification,
      subclass: doc.subclass,
      severity: doc.severity,
      source: doc.source,
      snippet: doc.snippet,
    });
  }
}

// ----- Env-driven builder -----------------------------------------------

/** Build an OpenSearch provider from env. Throws (does not silently fall
 *  back) when SEARCH_PROVIDER=opensearch but the endpoint is missing, so a
 *  misconfiguration fails loudly at boot. */
export function createOpenSearchProvider(
  env: NodeJS.ProcessEnv = process.env,
): OpenSearchLexicalProvider {
  const endpoint = env["OPENSEARCH_ENDPOINT"]?.trim();
  if (!endpoint) {
    throw new Error(
      "SEARCH_PROVIDER=opensearch requires OPENSEARCH_ENDPOINT",
    );
  }
  const indexPrefix =
    env["OPENSEARCH_INDEX_PREFIX"]?.trim() || DEFAULT_INDEX_PREFIX;
  const username = env["OPENSEARCH_USERNAME"]?.trim();
  const password = env["OPENSEARCH_PASSWORD"]?.trim();
  if ((username && !password) || (!username && password)) {
    logger.warn(
      "OpenSearch: only one of OPENSEARCH_USERNAME / OPENSEARCH_PASSWORD is set; " +
        "basic auth is disabled (both are required). Connecting unauthenticated.",
    );
  }
  const perTenantIndex = isTruthyEnv(env["OPENSEARCH_PER_TENANT_INDEX"]);
  return new OpenSearchLexicalProvider({
    endpoint,
    indexPrefix,
    perTenantIndex,
    ...(username ? { username } : {}),
    ...(password ? { password } : {}),
  });
}

/** A small, permissive truthy-env reader (`1`/`true`/`yes`/`on`,
 *  case-insensitive). Unset / blank / anything else ⇒ false, so the per-tenant
 *  index switch stays off by default and dev/eval are byte-identical. */
function isTruthyEnv(raw: string | undefined): boolean {
  const v = raw?.trim().toLowerCase();
  return v === "1" || v === "true" || v === "yes" || v === "on";
}
