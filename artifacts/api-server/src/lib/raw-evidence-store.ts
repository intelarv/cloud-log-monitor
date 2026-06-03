import { logger } from "./logger";
import {
  createS3RawEvidenceStore,
  createGcsRawEvidenceStore,
  createAzureBlobRawEvidenceStore,
} from "./cloud-raw-evidence-stores";

// ---------------------------------------------------------------------------
// Pluggable raw-evidence store (M10.2 / M10.3)
// ---------------------------------------------------------------------------
//
// Raw evidence is the single highest-value asset in the system (unredacted PHI
// / secrets). The threat model requires it to live ONLY in a WORM (write-once,
// read-many) tier — S3 Object Lock / GCS retention / Azure Blob immutability —
// never in the searchable hot tier, and to be reachable through exactly one
// code path (break-glass) that ledgers every read.
//
// Through M10.1 the dev placeholder for that tier was the `findings.raw_evidence`
// jsonb column. This module is the seam that lets the raw payload be retargeted
// to a real WORM object store in production WITHOUT changing the ingest pipeline
// or the break-glass endpoint — exactly mirroring the embedder registry
// (embedder-config.ts) and the lexical-search provider registry
// (search-config.ts).
//
// Configuration precedence (highest to lowest):
//   1. RAW_EVIDENCE_PROVIDER — explicit ("database" | "s3" | "gcs" | "azure-blob")
//   2. (default)             — database
//
// NOTE: as with SEARCH_PROVIDER (search-config.ts), there is intentionally NO
// DEPLOYMENT_TARGET shortcut. Every object store needs an explicit bucket /
// container name (there is no sensible default), and — more importantly — the
// raw-PHI storage location is far too consequential to flip implicitly: an
// existing cloud deployment that set DEPLOYMENT_TARGET only for the embedder /
// LLM must never silently start trying to write unredacted PHI to an
// unprovisioned (or wrong) bucket. Selection is therefore always explicit.
// ---------------------------------------------------------------------------

export type RawEvidenceProvider = "database" | "s3" | "gcs" | "azure-blob";

export const ALL_RAW_EVIDENCE_PROVIDERS: readonly RawEvidenceProvider[] = [
  "database",
  "s3",
  "gcs",
  "azure-blob",
];

export function isRawEvidenceProvider(s: string): s is RawEvidenceProvider {
  return (ALL_RAW_EVIDENCE_PROVIDERS as readonly string[]).includes(s);
}

export interface RawEvidenceStoreConfig {
  provider: RawEvidenceProvider;
}

/** A structured reference persisted on `findings.raw_evidence_ref` (jsonb)
 *  when an EXTERNAL store is active. Holds the URIs of the first + latest
 *  occurrence objects so break-glass reconstruction preserves both the
 *  forensic anchor (first) and the currently-arriving leak (latest), matching
 *  the `{first, latest}` shape the DB store keeps inline. */
export interface RawEvidenceRef {
  first: string;
  latest: string;
}

export function isRawEvidenceRef(v: unknown): v is RawEvidenceRef {
  return (
    typeof v === "object" &&
    v !== null &&
    typeof (v as { first?: unknown }).first === "string" &&
    typeof (v as { latest?: unknown }).latest === "string"
  );
}

/** The raw-evidence store seam.
 *
 *  - `external = false` (database): raw stays inline in the `raw_evidence`
 *    jsonb column. `put`/`get` are never invoked — ingest writes inline in its
 *    dedup transaction and break-glass reads the column directly. They throw if
 *    called so a wiring bug surfaces loudly rather than silently no-op'ing.
 *
 *  - `external = true` (s3/gcs/azure-blob): each occurrence's raw payload is
 *    written as a NEW immutable object (WORM forbids overwrite), and the
 *    finding's `raw_evidence_ref` records {first, latest} object URIs. */
export interface RawEvidenceStore {
  readonly name: string;
  readonly external: boolean;
  /** Persist one occurrence's raw payload as an immutable object; return its
   *  URI. The object key embeds the tenant + finding so `get` can re-validate
   *  tenancy. */
  put(args: {
    findingId: string;
    tenantId: string;
    evidence: unknown;
  }): Promise<string>;
  /** Resolve a stored object's payload by URI. Implementations MUST verify the
   *  URI belongs to `tenantId` (defense in depth behind the break-glass grant,
   *  which is already tenant- + finding-scoped). */
  get(args: { tenantId: string; uri: string }): Promise<unknown>;
}

// ---------------------------------------------------------------------------
// Database store (dev default)
// ---------------------------------------------------------------------------

/** Default store: raw evidence lives inline in `findings.raw_evidence` jsonb.
 *  This is the M3 behavior. `put`/`get` are intentionally unreachable — the
 *  ingest inline-write path and the break-glass inline-read path handle the DB
 *  case directly, gated on `external === false`. */
export class DatabaseRawEvidenceStore implements RawEvidenceStore {
  readonly name = "database";
  readonly external = false;

  put(): Promise<string> {
    return Promise.reject(
      new Error(
        "DatabaseRawEvidenceStore.put must not be called; the database store " +
          "writes raw evidence inline in the ingest transaction (external === false).",
      ),
    );
  }

  get(): Promise<unknown> {
    return Promise.reject(
      new Error(
        "DatabaseRawEvidenceStore.get must not be called; the database store " +
          "reads raw evidence inline from the raw_evidence column (external === false).",
      ),
    );
  }
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/** Parse env into a RawEvidenceStoreConfig. Pure: no I/O, no SDK loading.
 *  Throws on an unknown provider rather than silently falling back. */
export function loadRawEvidenceStoreConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): RawEvidenceStoreConfig {
  const explicit = env["RAW_EVIDENCE_PROVIDER"]?.trim().toLowerCase();
  let provider: RawEvidenceProvider = "database";
  if (explicit) {
    if (!isRawEvidenceProvider(explicit)) {
      throw new Error(
        `RAW_EVIDENCE_PROVIDER=${explicit} is not a known provider. ` +
          `Valid: ${ALL_RAW_EVIDENCE_PROVIDERS.join(", ")}`,
      );
    }
    provider = explicit;
  }
  return { provider };
}

/** Construct the store for a config. Cloud impls are lazy — their SDK is only
 *  imported when a put/get actually runs (see cloud-raw-evidence-stores.ts), so
 *  a dev install never pulls the AWS / GCP / Azure storage SDKs. */
export function createRawEvidenceStore(
  cfg: RawEvidenceStoreConfig,
  env: NodeJS.ProcessEnv = process.env,
): RawEvidenceStore {
  switch (cfg.provider) {
    case "database":
      return new DatabaseRawEvidenceStore();
    case "s3":
      return createS3RawEvidenceStore(env);
    case "gcs":
      return createGcsRawEvidenceStore(env);
    case "azure-blob":
      return createAzureBlobRawEvidenceStore(env);
  }
}

// ---------------------------------------------------------------------------
// Module-level registry
// ---------------------------------------------------------------------------
//
// Set once at boot by initRawEvidenceStoreFromEnv(). Consumed by ingest.ts
// (write path) and routes/admin.ts (break-glass read path). Tests inject
// explicitly via setRawEvidenceStore() or pass deps directly.

let currentStore: RawEvidenceStore | null = null;

export function setRawEvidenceStore(s: RawEvidenceStore): void {
  currentStore = s;
}

export function getRawEvidenceStore(): RawEvidenceStore {
  if (!currentStore) {
    throw new Error(
      "Raw-evidence store not initialized. Call initRawEvidenceStoreFromEnv() at boot.",
    );
  }
  return currentStore;
}

/** Like getRawEvidenceStore() but returns null instead of throwing when no
 *  store is registered (test / unconfigured environments). */
export function getRawEvidenceStoreOrNull(): RawEvidenceStore | null {
  return currentStore;
}

/** For tests that need to reset module state between cases. */
export function resetRawEvidenceStoreForTests(): void {
  currentStore = null;
}

export function initRawEvidenceStoreFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { config: RawEvidenceStoreConfig; store: RawEvidenceStore } {
  const config = loadRawEvidenceStoreConfigFromEnv(env);
  const store = createRawEvidenceStore(config, env);
  setRawEvidenceStore(store);
  logger.info(
    { provider: config.provider, external: store.external },
    "Raw-evidence store initialized",
  );
  return { config, store };
}

// ---------------------------------------------------------------------------
// Break-glass read resolution (shared, testable)
// ---------------------------------------------------------------------------

export interface ResolveRawEvidenceInput {
  /** `findings.raw_evidence` (legacy inline jsonb; null when raw lives in an
   *  external store or the finding has no raw). */
  rawEvidence: unknown;
  /** `findings.raw_evidence_ref` ({first,latest} URIs; null for the DB store or
   *  when an external write failed at ingest). */
  rawEvidenceRef: unknown;
  tenantId: string;
  /** The active store (getRawEvidenceStoreOrNull()); null in unconfigured envs. */
  store: RawEvidenceStore | null;
}

export interface ResolveRawEvidenceResult {
  /** The resolved raw payload, or null when unresolved/absent. */
  rawEvidence: unknown;
  /** True if EITHER the inline column or an external ref carried raw — i.e. raw
   *  was expected to exist for this finding (used for ledger `raw_present`). */
  rawPresent: boolean;
  /** Where the returned payload actually came from. `database` covers both the
   *  legacy inline column and an inline fallback after an external miss. */
  rawSource: "database" | "external_store";
  /** Set ONLY when raw was expected but could not be produced. Absent when raw
   *  resolved (including via inline fallback) or is genuinely absent. */
  rawUnresolved?: string;
  /** True when the external ref could not be resolved but the legacy inline
   *  column was served instead (mixed-state row during a provider transition). */
  fallbackUsed: boolean;
  /** Set ONLY when `fallbackUsed === true`: the reason the external resolution
   *  failed (same vocabulary as `rawUnresolved`). Carries no PHI — it names the
   *  failure mode (outage / malformed ref / missing store), not the payload. Lets
   *  the caller alert on-call that durable reads are degraded. */
  fallbackReason?: string;
}

/** Resolve a finding's raw evidence for the break-glass read path.
 *
 *  Order: external `raw_evidence_ref` FIRST, then the legacy inline
 *  `raw_evidence` column as a read-fallback (non-destructive migration keeps the
 *  inline column for at least one release cycle). Concretely, when an external
 *  ref is present but cannot be resolved — malformed ref, no/ wrong store
 *  configured, or `store.get()` throws — and the legacy inline column still
 *  carries raw (a mixed-state row written before/around the provider switch), we
 *  serve the inline copy rather than failing closed to null.
 *
 *  Pure w.r.t. logging/ledger (callers inspect the result and log/ledger). */
export async function resolveRawEvidence(
  input: ResolveRawEvidenceInput,
): Promise<ResolveRawEvidenceResult> {
  const { rawEvidence: inline, rawEvidenceRef: ref, tenantId, store } = input;
  const hasExternalRef = ref !== null && ref !== undefined;
  const hasInline = inline !== null && inline !== undefined;
  const rawPresent = hasInline || hasExternalRef;

  if (hasExternalRef) {
    let extErr: string | undefined;
    let resolved: unknown;
    if (!isRawEvidenceRef(ref)) {
      extErr = "malformed raw_evidence_ref";
    } else if (!store || !store.external) {
      extErr =
        "raw evidence is in an external store but no external store is configured to resolve it";
    } else {
      try {
        const first = await store.get({ tenantId, uri: ref.first });
        const latest =
          ref.latest === ref.first
            ? first
            : await store.get({ tenantId, uri: ref.latest });
        resolved = { first, latest };
      } catch {
        extErr = "failed to resolve raw evidence from external store";
      }
    }

    if (extErr === undefined) {
      return {
        rawEvidence: resolved,
        rawPresent,
        rawSource: "external_store",
        fallbackUsed: false,
      };
    }
    // External resolution failed. Fall back to the legacy inline column when it
    // still carries raw (mixed-state row), otherwise report unresolved.
    if (hasInline) {
      return {
        rawEvidence: inline,
        rawPresent,
        rawSource: "database",
        fallbackUsed: true,
        fallbackReason: extErr,
      };
    }
    return {
      rawEvidence: null,
      rawPresent,
      rawSource: "external_store",
      rawUnresolved: extErr,
      fallbackUsed: false,
    };
  }

  // No external ref. Inline column is authoritative.
  if (hasInline) {
    return {
      rawEvidence: inline,
      rawPresent,
      rawSource: "database",
      fallbackUsed: false,
    };
  }

  // No inline raw and no ref. Under an EXTERNAL store every ingested finding
  // gets a ref on a successful object write, so this means the external write
  // failed at ingest (finding committed, ref left NULL by design) — surface it
  // honestly. Under the database store a null here is genuinely absent.
  let rawUnresolved: string | undefined;
  if (store && store.external) {
    rawUnresolved =
      "external store is configured but no raw evidence reference was recorded (external write likely failed at ingest)";
  }
  return {
    rawEvidence: null,
    rawPresent,
    rawSource: store && store.external ? "external_store" : "database",
    rawUnresolved,
    fallbackUsed: false,
  };
}
