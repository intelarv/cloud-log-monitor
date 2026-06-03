// M10.2 / M10.3: Cloud WORM raw-evidence stores (S3 Object Lock / GCS retention
// / Azure Blob immutability).
//
// Mirrors the lazy-load pattern in cloud-embedders.ts / cloud-search.ts: each
// SDK import is hidden from the TS static analyzer via a variable-aliased
// dynamic import, so the AWS / GCP / Azure storage SDKs are OPTIONAL
// dependencies — a dev install never pulls them. Operators install only the SDK
// for the store they actually enable.
//
// Per threat_model "Assets" + §Tampering: raw PHI lives ONLY in a WORM tier and
// the writer role MUST NOT be able to disable the lock or shorten retention.
// Each occurrence's payload is written as a NEW immutable object (WORM forbids
// overwrite); the finding's `raw_evidence_ref` (first/latest URIs) is the only
// pointer, and the break-glass endpoint is the only reader. Object keys embed
// the tenant so `get` re-validates tenancy as defense in depth behind the
// (already tenant-scoped) break-glass grant.

import { randomUUID } from "node:crypto";
import { logger } from "./logger";
import type { RawEvidenceStore } from "./raw-evidence-store";

// ----- SDK lazy loader -------------------------------------------------

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

const DEFAULT_PREFIX = "raw-evidence";
// HIPAA retention is commonly 6 years; we default to 7 (2555 days) so the WORM
// retain-until window outlives the typical audit horizon. Operators override
// via RAW_EVIDENCE_RETENTION_DAYS.
const DEFAULT_RETENTION_DAYS = 2555;

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

/** `<prefix>/<tenantId>/<findingId>/<uuid>.json`. tenantId + findingId are
 *  already charset-constrained upstream (ingest validates tenantId; finding ids
 *  are `F-…`), so they are safe key segments. The uuid guarantees a fresh,
 *  never-overwritten key per occurrence (WORM-safe). */
function buildObjectKey(
  prefix: string,
  tenantId: string,
  findingId: string,
): string {
  return `${prefix}/${tenantId}/${findingId}/${randomUUID()}.json`;
}

/** Tenant isolation backstop: every object key starts with
 *  `<prefix>/<tenantId>/`. A URI whose key does not is refused before any
 *  fetch, so a confused/forged ref can never read another tenant's object. */
function assertKeyBelongsToTenant(
  key: string,
  prefix: string,
  tenantId: string,
): void {
  const expected = `${prefix}/${tenantId}/`;
  if (!key.startsWith(expected)) {
    throw new Error(
      "raw-evidence get refused: object key is not within the requesting tenant's namespace",
    );
  }
}

function retainUntil(retentionDays: number): Date {
  return new Date(Date.now() + retentionDays * 24 * 60 * 60 * 1000);
}

// =====================================================================
// S3 (AWS) — Object Lock
// =====================================================================

/** Minimal S3 surface used by the store; the lazy loader adapts the real
 *  `@aws-sdk/client-s3` to this shape so the store is SDK-agnostic + mockable. */
export interface S3RawClient {
  putObject(args: {
    bucket: string;
    key: string;
    body: string;
    objectLockMode: string;
    objectLockRetainUntilDate: Date;
  }): Promise<void>;
  getObject(args: { bucket: string; key: string }): Promise<string>;
}

export interface S3RawEvidenceStoreOpts {
  readonly bucket: string;
  readonly region: string;
  readonly prefix?: string;
  readonly retentionDays?: number;
  /** "COMPLIANCE" (default — not even root can shorten) or "GOVERNANCE". */
  readonly objectLockMode?: string;
  /** Test injection: bypass the real SDK loader. */
  readonly clientFactory?: () => Promise<S3RawClient>;
}

export class S3RawEvidenceStore implements RawEvidenceStore {
  readonly name = "s3";
  readonly external = true;
  private clientPromise: Promise<S3RawClient> | null = null;
  private readonly prefix: string;
  private readonly retentionDays: number;
  private readonly objectLockMode: string;

  constructor(private readonly opts: S3RawEvidenceStoreOpts) {
    this.prefix = opts.prefix ?? DEFAULT_PREFIX;
    this.retentionDays = opts.retentionDays ?? DEFAULT_RETENTION_DAYS;
    this.objectLockMode = opts.objectLockMode ?? "COMPLIANCE";
  }

  private async getClient(): Promise<S3RawClient> {
    if (this.opts.clientFactory) return this.opts.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          mod = await loadOptional("@aws-sdk/client-s3");
        } catch {
          throw new Error(
            "RAW_EVIDENCE_PROVIDER=s3 selected but @aws-sdk/client-s3 is not " +
              "installed. Run: pnpm --filter @workspace/api-server add @aws-sdk/client-s3",
          );
        }
        const native = new mod.S3Client({ region: this.opts.region });
        return {
          async putObject(args): Promise<void> {
            await native.send(
              new mod.PutObjectCommand({
                Bucket: args.bucket,
                Key: args.key,
                Body: args.body,
                ContentType: "application/json",
                ObjectLockMode: args.objectLockMode,
                ObjectLockRetainUntilDate: args.objectLockRetainUntilDate,
              }),
            );
          },
          async getObject(args): Promise<string> {
            const resp = await native.send(
              new mod.GetObjectCommand({ Bucket: args.bucket, Key: args.key }),
            );
            // aws-sdk v3 body is a stream with a transformToString() helper.
            const body = resp.Body as {
              transformToString?: () => Promise<string>;
            };
            if (typeof body?.transformToString === "function") {
              return body.transformToString();
            }
            throw new Error("S3 GetObject returned an unreadable body");
          },
        } satisfies S3RawClient;
      })();
    }
    return this.clientPromise;
  }

  async put(args: {
    findingId: string;
    tenantId: string;
    evidence: unknown;
  }): Promise<string> {
    const client = await this.getClient();
    const key = buildObjectKey(this.prefix, args.tenantId, args.findingId);
    await client.putObject({
      bucket: this.opts.bucket,
      key,
      body: JSON.stringify(args.evidence),
      objectLockMode: this.objectLockMode,
      objectLockRetainUntilDate: retainUntil(this.retentionDays),
    });
    return `s3://${this.opts.bucket}/${key}`;
  }

  async get(args: { tenantId: string; uri: string }): Promise<unknown> {
    const { bucket, key } = parseSchemeUri("s3", args.uri);
    if (bucket !== this.opts.bucket) {
      throw new Error(
        "raw-evidence get refused: URI bucket does not match the configured S3 bucket",
      );
    }
    assertKeyBelongsToTenant(key, this.prefix, args.tenantId);
    const client = await this.getClient();
    const body = await client.getObject({ bucket, key });
    return JSON.parse(body);
  }
}

export function createS3RawEvidenceStore(
  env: NodeJS.ProcessEnv = process.env,
): S3RawEvidenceStore {
  const bucket = env["RAW_EVIDENCE_S3_BUCKET"]?.trim();
  if (!bucket) {
    throw new Error("RAW_EVIDENCE_PROVIDER=s3 requires RAW_EVIDENCE_S3_BUCKET");
  }
  const region = env["AWS_REGION"]?.trim();
  if (!region) {
    throw new Error("RAW_EVIDENCE_PROVIDER=s3 requires AWS_REGION");
  }
  const prefix = env["RAW_EVIDENCE_S3_PREFIX"]?.trim() || DEFAULT_PREFIX;
  const retentionDays = parsePositiveInt(
    env["RAW_EVIDENCE_RETENTION_DAYS"],
    DEFAULT_RETENTION_DAYS,
  );
  const objectLockMode =
    env["RAW_EVIDENCE_OBJECT_LOCK_MODE"]?.trim().toUpperCase() || "COMPLIANCE";
  if (objectLockMode !== "COMPLIANCE" && objectLockMode !== "GOVERNANCE") {
    throw new Error(
      `RAW_EVIDENCE_OBJECT_LOCK_MODE=${objectLockMode} invalid (COMPLIANCE | GOVERNANCE)`,
    );
  }
  if (objectLockMode === "GOVERNANCE") {
    // GOVERNANCE-mode Object Lock can be bypassed/shortened by a principal
    // holding s3:BypassGovernanceRetention, so it does NOT give true WORM
    // immutability for raw PHI. COMPLIANCE is the required production default;
    // GOVERNANCE is only acceptable as an explicit, time-bounded security
    // exception. Surface it loudly at boot so it can't pass review silently.
    logger.warn(
      { bucket, objectLockMode },
      "RAW_EVIDENCE_OBJECT_LOCK_MODE=GOVERNANCE weakens WORM immutability for " +
        "raw PHI (bypassable via s3:BypassGovernanceRetention). Use COMPLIANCE " +
        "in production unless this is an approved, time-bounded exception.",
    );
  }
  return new S3RawEvidenceStore({
    bucket,
    region,
    prefix,
    retentionDays,
    objectLockMode,
  });
}

// =====================================================================
// GCS (GCP) — bucket retention / object hold
// =====================================================================
//
// WORM on GCS is enforced by a LOCKED bucket retention policy (operator-
// configured + locked so it cannot be shortened) plus, optionally, a per-object
// temporary hold. The application writes objects normally; it deliberately does
// NOT manage the retention policy (writer must not be able to weaken it).

export interface GcsRawClient {
  putObject(args: { bucket: string; key: string; body: string }): Promise<void>;
  getObject(args: { bucket: string; key: string }): Promise<string>;
}

export interface GcsRawEvidenceStoreOpts {
  readonly bucket: string;
  readonly prefix?: string;
  readonly clientFactory?: () => Promise<GcsRawClient>;
}

export class GcsRawEvidenceStore implements RawEvidenceStore {
  readonly name = "gcs";
  readonly external = true;
  private clientPromise: Promise<GcsRawClient> | null = null;
  private readonly prefix: string;

  constructor(private readonly opts: GcsRawEvidenceStoreOpts) {
    this.prefix = opts.prefix ?? DEFAULT_PREFIX;
  }

  private async getClient(): Promise<GcsRawClient> {
    if (this.opts.clientFactory) return this.opts.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          mod = await loadOptional("@google-cloud/storage");
        } catch {
          throw new Error(
            "RAW_EVIDENCE_PROVIDER=gcs selected but @google-cloud/storage is " +
              "not installed. Run: pnpm --filter @workspace/api-server add @google-cloud/storage",
          );
        }
        const storage = new mod.Storage();
        return {
          async putObject(args): Promise<void> {
            await storage
              .bucket(args.bucket)
              .file(args.key)
              .save(args.body, {
                resumable: false,
                contentType: "application/json",
              });
          },
          async getObject(args): Promise<string> {
            const [buf] = await storage
              .bucket(args.bucket)
              .file(args.key)
              .download();
            return buf.toString("utf8");
          },
        } satisfies GcsRawClient;
      })();
    }
    return this.clientPromise;
  }

  async put(args: {
    findingId: string;
    tenantId: string;
    evidence: unknown;
  }): Promise<string> {
    const client = await this.getClient();
    const key = buildObjectKey(this.prefix, args.tenantId, args.findingId);
    await client.putObject({
      bucket: this.opts.bucket,
      key,
      body: JSON.stringify(args.evidence),
    });
    return `gs://${this.opts.bucket}/${key}`;
  }

  async get(args: { tenantId: string; uri: string }): Promise<unknown> {
    const { bucket, key } = parseSchemeUri("gs", args.uri);
    if (bucket !== this.opts.bucket) {
      throw new Error(
        "raw-evidence get refused: URI bucket does not match the configured GCS bucket",
      );
    }
    assertKeyBelongsToTenant(key, this.prefix, args.tenantId);
    const client = await this.getClient();
    const body = await client.getObject({ bucket, key });
    return JSON.parse(body);
  }
}

export function createGcsRawEvidenceStore(
  env: NodeJS.ProcessEnv = process.env,
): GcsRawEvidenceStore {
  const bucket = env["RAW_EVIDENCE_GCS_BUCKET"]?.trim();
  if (!bucket) {
    throw new Error("RAW_EVIDENCE_PROVIDER=gcs requires RAW_EVIDENCE_GCS_BUCKET");
  }
  const prefix = env["RAW_EVIDENCE_GCS_PREFIX"]?.trim() || DEFAULT_PREFIX;
  return new GcsRawEvidenceStore({ bucket, prefix });
}

// =====================================================================
// Azure Blob — container immutability policy
// =====================================================================
//
// WORM on Azure is enforced by a LOCKED container-level immutability policy
// (operator-configured). The application writes blobs normally. Auth is via a
// connection string (simplest; covers account key + SAS) so we avoid pulling
// @azure/identity as a second optional dep.

export interface AzureRawClient {
  putObject(args: {
    container: string;
    key: string;
    body: string;
  }): Promise<void>;
  getObject(args: { container: string; key: string }): Promise<string>;
}

export interface AzureBlobRawEvidenceStoreOpts {
  readonly container: string;
  readonly connectionString: string;
  readonly prefix?: string;
  readonly clientFactory?: () => Promise<AzureRawClient>;
}

export class AzureBlobRawEvidenceStore implements RawEvidenceStore {
  readonly name = "azure-blob";
  readonly external = true;
  private clientPromise: Promise<AzureRawClient> | null = null;
  private readonly prefix: string;

  constructor(private readonly opts: AzureBlobRawEvidenceStoreOpts) {
    this.prefix = opts.prefix ?? DEFAULT_PREFIX;
  }

  private async getClient(): Promise<AzureRawClient> {
    if (this.opts.clientFactory) return this.opts.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          mod = await loadOptional("@azure/storage-blob");
        } catch {
          throw new Error(
            "RAW_EVIDENCE_PROVIDER=azure-blob selected but @azure/storage-blob " +
              "is not installed. Run: pnpm --filter @workspace/api-server add @azure/storage-blob",
          );
        }
        const service = mod.BlobServiceClient.fromConnectionString(
          this.opts.connectionString,
        );
        return {
          async putObject(args): Promise<void> {
            const blob = service
              .getContainerClient(args.container)
              .getBlockBlobClient(args.key);
            const body = Buffer.from(args.body, "utf8");
            await blob.upload(body, body.length, {
              blobHTTPHeaders: { blobContentType: "application/json" },
            });
          },
          async getObject(args): Promise<string> {
            const blob = service
              .getContainerClient(args.container)
              .getBlockBlobClient(args.key);
            const buf = (await blob.downloadToBuffer()) as Buffer;
            return buf.toString("utf8");
          },
        } satisfies AzureRawClient;
      })();
    }
    return this.clientPromise;
  }

  async put(args: {
    findingId: string;
    tenantId: string;
    evidence: unknown;
  }): Promise<string> {
    const client = await this.getClient();
    const key = buildObjectKey(this.prefix, args.tenantId, args.findingId);
    await client.putObject({
      container: this.opts.container,
      key,
      body: JSON.stringify(args.evidence),
    });
    return `azblob://${this.opts.container}/${key}`;
  }

  async get(args: { tenantId: string; uri: string }): Promise<unknown> {
    const { bucket: container, key } = parseSchemeUri("azblob", args.uri);
    if (container !== this.opts.container) {
      throw new Error(
        "raw-evidence get refused: URI container does not match the configured Azure container",
      );
    }
    assertKeyBelongsToTenant(key, this.prefix, args.tenantId);
    const client = await this.getClient();
    const body = await client.getObject({ container, key });
    return JSON.parse(body);
  }
}

export function createAzureBlobRawEvidenceStore(
  env: NodeJS.ProcessEnv = process.env,
): AzureBlobRawEvidenceStore {
  const container = env["RAW_EVIDENCE_AZURE_CONTAINER"]?.trim();
  if (!container) {
    throw new Error(
      "RAW_EVIDENCE_PROVIDER=azure-blob requires RAW_EVIDENCE_AZURE_CONTAINER",
    );
  }
  const connectionString =
    env["RAW_EVIDENCE_AZURE_CONNECTION_STRING"]?.trim();
  if (!connectionString) {
    throw new Error(
      "RAW_EVIDENCE_PROVIDER=azure-blob requires RAW_EVIDENCE_AZURE_CONNECTION_STRING",
    );
  }
  const prefix = env["RAW_EVIDENCE_AZURE_PREFIX"]?.trim() || DEFAULT_PREFIX;
  return new AzureBlobRawEvidenceStore({ container, connectionString, prefix });
}

// ----- shared URI parsing ------------------------------------------------

/** Parse `<scheme>://<bucketOrContainer>/<key>` into its parts. Throws on a
 *  malformed or wrong-scheme URI. `key` keeps every segment after the first
 *  slash (so nested prefixes survive). */
function parseSchemeUri(
  scheme: "s3" | "gs" | "azblob",
  uri: string,
): { bucket: string; key: string } {
  const p = `${scheme}://`;
  if (!uri.startsWith(p)) {
    throw new Error(`raw-evidence get refused: expected ${p} URI, got "${uri}"`);
  }
  const rest = uri.slice(p.length);
  const slash = rest.indexOf("/");
  if (slash <= 0 || slash === rest.length - 1) {
    throw new Error(`raw-evidence get refused: malformed URI "${uri}"`);
  }
  return { bucket: rest.slice(0, slash), key: rest.slice(slash + 1) };
}
