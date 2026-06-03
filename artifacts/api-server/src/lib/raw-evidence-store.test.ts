import { afterEach, describe, expect, it, vi } from "vitest";
import { logger } from "./logger";
import {
  DatabaseRawEvidenceStore,
  createRawEvidenceStore,
  getRawEvidenceStore,
  getRawEvidenceStoreOrNull,
  initRawEvidenceStoreFromEnv,
  isRawEvidenceRef,
  loadRawEvidenceStoreConfigFromEnv,
  resetRawEvidenceStoreForTests,
  resolveRawEvidence,
  setRawEvidenceStore,
  type RawEvidenceStore,
} from "./raw-evidence-store";
import {
  AzureBlobRawEvidenceStore,
  GcsRawEvidenceStore,
  S3RawEvidenceStore,
  type AzureRawClient,
  type GcsRawClient,
  type S3RawClient,
} from "./cloud-raw-evidence-stores";

afterEach(() => resetRawEvidenceStoreForTests());

describe("loadRawEvidenceStoreConfigFromEnv", () => {
  it("defaults to database when unset", () => {
    expect(loadRawEvidenceStoreConfigFromEnv({}).provider).toBe("database");
  });

  it("honors an explicit RAW_EVIDENCE_PROVIDER (case-insensitive)", () => {
    expect(
      loadRawEvidenceStoreConfigFromEnv({ RAW_EVIDENCE_PROVIDER: "S3" })
        .provider,
    ).toBe("s3");
    expect(
      loadRawEvidenceStoreConfigFromEnv({ RAW_EVIDENCE_PROVIDER: "azure-blob" })
        .provider,
    ).toBe("azure-blob");
  });

  it("does NOT auto-select from DEPLOYMENT_TARGET (no cloud shortcut)", () => {
    // Moving raw PHI is too consequential to flip implicitly: a cloud target set
    // only for the embedder/LLM must never start writing PHI to an unprovisioned
    // bucket. Selection is always explicit.
    expect(
      loadRawEvidenceStoreConfigFromEnv({ DEPLOYMENT_TARGET: "aws" }).provider,
    ).toBe("database");
  });

  it("throws on an unknown provider rather than falling back", () => {
    expect(() =>
      loadRawEvidenceStoreConfigFromEnv({ RAW_EVIDENCE_PROVIDER: "minio" }),
    ).toThrow(/not a known provider/);
  });
});

describe("createRawEvidenceStore", () => {
  it("builds the database store (not external)", () => {
    const s = createRawEvidenceStore({ provider: "database" });
    expect(s).toBeInstanceOf(DatabaseRawEvidenceStore);
    expect(s.name).toBe("database");
    expect(s.external).toBe(false);
  });

  it("throws when s3 is selected without a bucket", () => {
    expect(() => createRawEvidenceStore({ provider: "s3" }, {})).toThrow(
      /RAW_EVIDENCE_S3_BUCKET/,
    );
  });

  it("throws when s3 has a bucket but no region", () => {
    expect(() =>
      createRawEvidenceStore(
        { provider: "s3" },
        { RAW_EVIDENCE_S3_BUCKET: "b" },
      ),
    ).toThrow(/AWS_REGION/);
  });

  it("builds the s3 store when bucket+region present", () => {
    const s = createRawEvidenceStore(
      { provider: "s3" },
      { RAW_EVIDENCE_S3_BUCKET: "phi-bucket", AWS_REGION: "us-east-1" },
    );
    expect(s).toBeInstanceOf(S3RawEvidenceStore);
    expect(s.external).toBe(true);
  });

  it("rejects an invalid object-lock mode", () => {
    expect(() =>
      createRawEvidenceStore(
        { provider: "s3" },
        {
          RAW_EVIDENCE_S3_BUCKET: "b",
          AWS_REGION: "us-east-1",
          RAW_EVIDENCE_OBJECT_LOCK_MODE: "loose",
        },
      ),
    ).toThrow(/COMPLIANCE \| GOVERNANCE/);
  });

  it("warns when S3 object-lock mode is GOVERNANCE (weaker than COMPLIANCE)", () => {
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => logger);
    try {
      createRawEvidenceStore(
        { provider: "s3" },
        {
          RAW_EVIDENCE_S3_BUCKET: "b",
          AWS_REGION: "us-east-1",
          RAW_EVIDENCE_OBJECT_LOCK_MODE: "governance",
        },
      );
      expect(warn).toHaveBeenCalledTimes(1);
      const [meta, msg] = warn.mock.calls[0]!;
      expect(meta).toMatchObject({ objectLockMode: "GOVERNANCE" });
      expect(String(msg)).toMatch(/GOVERNANCE/);
    } finally {
      warn.mockRestore();
    }
  });

  it("does NOT warn when S3 object-lock mode is COMPLIANCE (default or explicit)", () => {
    const warn = vi.spyOn(logger, "warn").mockImplementation(() => logger);
    try {
      createRawEvidenceStore(
        { provider: "s3" },
        { RAW_EVIDENCE_S3_BUCKET: "b", AWS_REGION: "us-east-1" },
      );
      createRawEvidenceStore(
        { provider: "s3" },
        {
          RAW_EVIDENCE_S3_BUCKET: "b",
          AWS_REGION: "us-east-1",
          RAW_EVIDENCE_OBJECT_LOCK_MODE: "compliance",
        },
      );
      expect(warn).not.toHaveBeenCalled();
    } finally {
      warn.mockRestore();
    }
  });

  it("throws when gcs is selected without a bucket", () => {
    expect(() => createRawEvidenceStore({ provider: "gcs" }, {})).toThrow(
      /RAW_EVIDENCE_GCS_BUCKET/,
    );
  });

  it("throws when azure-blob is missing container or connection string", () => {
    expect(() =>
      createRawEvidenceStore({ provider: "azure-blob" }, {}),
    ).toThrow(/RAW_EVIDENCE_AZURE_CONTAINER/);
    expect(() =>
      createRawEvidenceStore(
        { provider: "azure-blob" },
        { RAW_EVIDENCE_AZURE_CONTAINER: "c" },
      ),
    ).toThrow(/RAW_EVIDENCE_AZURE_CONNECTION_STRING/);
  });
});

describe("DatabaseRawEvidenceStore", () => {
  it("rejects put/get (inline paths handle the DB case directly)", async () => {
    const s: RawEvidenceStore = new DatabaseRawEvidenceStore();
    await expect(
      s.put({ findingId: "F-1", tenantId: "t1", evidence: {} }),
    ).rejects.toThrow(/must not be called/);
    await expect(
      s.get({ tenantId: "t1", uri: "x" }),
    ).rejects.toThrow(/must not be called/);
  });
});

describe("isRawEvidenceRef", () => {
  it("accepts a {first,latest} string pair only", () => {
    expect(isRawEvidenceRef({ first: "a", latest: "b" })).toBe(true);
    expect(isRawEvidenceRef({ first: "a" })).toBe(false);
    expect(isRawEvidenceRef({ first: 1, latest: 2 })).toBe(false);
    expect(isRawEvidenceRef(null)).toBe(false);
    expect(isRawEvidenceRef("a")).toBe(false);
  });
});

describe("registry", () => {
  it("getRawEvidenceStore throws before init; getOrNull returns null", () => {
    resetRawEvidenceStoreForTests();
    expect(getRawEvidenceStoreOrNull()).toBeNull();
    expect(() => getRawEvidenceStore()).toThrow(/not initialized/);
  });

  it("set/get round-trips and reset clears", () => {
    const s = new DatabaseRawEvidenceStore();
    setRawEvidenceStore(s);
    expect(getRawEvidenceStore()).toBe(s);
    expect(getRawEvidenceStoreOrNull()).toBe(s);
    resetRawEvidenceStoreForTests();
    expect(getRawEvidenceStoreOrNull()).toBeNull();
  });

  it("initRawEvidenceStoreFromEnv registers the configured store", () => {
    const { config, store } = initRawEvidenceStoreFromEnv({});
    expect(config.provider).toBe("database");
    expect(getRawEvidenceStore()).toBe(store);
  });
});

// ---------------------------------------------------------------------------
// S3 store against an in-memory fake client — deterministic, no real bucket
// and no SDK install required.
// ---------------------------------------------------------------------------

function makeFakeS3(): {
  client: S3RawClient;
  puts: Array<{
    bucket: string;
    key: string;
    body: string;
    objectLockMode: string;
    objectLockRetainUntilDate: Date;
  }>;
  store: Map<string, string>;
} {
  const puts: Array<{
    bucket: string;
    key: string;
    body: string;
    objectLockMode: string;
    objectLockRetainUntilDate: Date;
  }> = [];
  const blob = new Map<string, string>();
  const client: S3RawClient = {
    async putObject(args) {
      puts.push(args);
      blob.set(`${args.bucket}/${args.key}`, args.body);
    },
    async getObject(args) {
      const v = blob.get(`${args.bucket}/${args.key}`);
      if (v === undefined) throw new Error("not found");
      return v;
    },
  };
  return { client, puts, store: blob };
}

describe("S3RawEvidenceStore (fake client)", () => {
  it("put writes an immutable object under Object Lock and returns an s3:// URI", async () => {
    const fake = makeFakeS3();
    const before = Date.now();
    const s = new S3RawEvidenceStore({
      bucket: "phi-bucket",
      region: "us-east-1",
      retentionDays: 10,
      clientFactory: async () => fake.client,
    });
    const uri = await s.put({
      findingId: "F-7",
      tenantId: "tenant-a",
      evidence: { ssn: "123-45-6789" },
    });
    expect(uri).toMatch(/^s3:\/\/phi-bucket\/raw-evidence\/tenant-a\/F-7\/.+\.json$/);
    expect(fake.puts).toHaveLength(1);
    const put = fake.puts[0]!;
    expect(put.objectLockMode).toBe("COMPLIANCE");
    // retain-until is ~10 days out (well in the future).
    expect(put.objectLockRetainUntilDate.getTime()).toBeGreaterThan(
      before + 9 * 24 * 60 * 60 * 1000,
    );
  });

  it("round-trips put → get for the same tenant", async () => {
    const fake = makeFakeS3();
    const s = new S3RawEvidenceStore({
      bucket: "phi-bucket",
      region: "us-east-1",
      clientFactory: async () => fake.client,
    });
    const uri = await s.put({
      findingId: "F-7",
      tenantId: "tenant-a",
      evidence: { ssn: "123-45-6789" },
    });
    expect(await s.get({ tenantId: "tenant-a", uri })).toEqual({
      ssn: "123-45-6789",
    });
  });

  it("get refuses a URI whose key is not in the requesting tenant's namespace", async () => {
    const fake = makeFakeS3();
    const s = new S3RawEvidenceStore({
      bucket: "phi-bucket",
      region: "us-east-1",
      clientFactory: async () => fake.client,
    });
    const uri = await s.put({
      findingId: "F-7",
      tenantId: "tenant-a",
      evidence: { x: 1 },
    });
    await expect(
      s.get({ tenantId: "tenant-b", uri }),
    ).rejects.toThrow(/not within the requesting tenant/);
  });

  it("get refuses a URI for a different bucket", async () => {
    const fake = makeFakeS3();
    const s = new S3RawEvidenceStore({
      bucket: "phi-bucket",
      region: "us-east-1",
      clientFactory: async () => fake.client,
    });
    await expect(
      s.get({
        tenantId: "tenant-a",
        uri: "s3://other-bucket/raw-evidence/tenant-a/F-7/abc.json",
      }),
    ).rejects.toThrow(/bucket does not match/);
  });

  it("get rejects a malformed / wrong-scheme URI", async () => {
    const fake = makeFakeS3();
    const s = new S3RawEvidenceStore({
      bucket: "phi-bucket",
      region: "us-east-1",
      clientFactory: async () => fake.client,
    });
    await expect(
      s.get({ tenantId: "tenant-a", uri: "gs://phi-bucket/k" }),
    ).rejects.toThrow(/expected s3:\/\//);
  });
});

// ---------------------------------------------------------------------------
// GCS + Azure round-trips (same tenant-isolation contract, different scheme).
// ---------------------------------------------------------------------------

function makeFakeKv(): { put: (k: string, v: string) => void; get: (k: string) => string } {
  const m = new Map<string, string>();
  return {
    put: (k, v) => void m.set(k, v),
    get: (k) => {
      const v = m.get(k);
      if (v === undefined) throw new Error("not found");
      return v;
    },
  };
}

describe("GcsRawEvidenceStore (fake client)", () => {
  it("round-trips and uses a gs:// URI, refusing cross-tenant reads", async () => {
    const kv = makeFakeKv();
    const client: GcsRawClient = {
      async putObject(a) {
        kv.put(`${a.bucket}/${a.key}`, a.body);
      },
      async getObject(a) {
        return kv.get(`${a.bucket}/${a.key}`);
      },
    };
    const s = new GcsRawEvidenceStore({
      bucket: "phi-gcs",
      clientFactory: async () => client,
    });
    const uri = await s.put({
      findingId: "F-9",
      tenantId: "tenant-a",
      evidence: { mrn: "X" },
    });
    expect(uri).toMatch(/^gs:\/\/phi-gcs\/raw-evidence\/tenant-a\/F-9\/.+\.json$/);
    expect(await s.get({ tenantId: "tenant-a", uri })).toEqual({ mrn: "X" });
    await expect(
      s.get({ tenantId: "tenant-b", uri }),
    ).rejects.toThrow(/not within the requesting tenant/);
  });
});

describe("AzureBlobRawEvidenceStore (fake client)", () => {
  it("round-trips and uses an azblob:// URI, refusing a wrong container", async () => {
    const kv = makeFakeKv();
    const client: AzureRawClient = {
      async putObject(a) {
        kv.put(`${a.container}/${a.key}`, a.body);
      },
      async getObject(a) {
        return kv.get(`${a.container}/${a.key}`);
      },
    };
    const s = new AzureBlobRawEvidenceStore({
      container: "phi-az",
      connectionString: "fake",
      clientFactory: async () => client,
    });
    const uri = await s.put({
      findingId: "F-9",
      tenantId: "tenant-a",
      evidence: { mrn: "Y" },
    });
    expect(uri).toMatch(
      /^azblob:\/\/phi-az\/raw-evidence\/tenant-a\/F-9\/.+\.json$/,
    );
    expect(await s.get({ tenantId: "tenant-a", uri })).toEqual({ mrn: "Y" });
    await expect(
      s.get({
        tenantId: "tenant-a",
        uri: "azblob://other/raw-evidence/tenant-a/F-9/abc.json",
      }),
    ).rejects.toThrow(/container does not match/);
  });
});

// ---------------------------------------------------------------------------
// resolveRawEvidence — the break-glass read resolution matrix, including the
// non-destructive read-fallback from an external ref to the legacy inline
// `raw_evidence` column (mixed-state rows during a provider transition).
// ---------------------------------------------------------------------------

/** Minimal external store whose get() is fully controlled by the test. */
function fakeExternalStore(
  get: (args: { tenantId: string; uri: string }) => Promise<unknown>,
): RawEvidenceStore {
  return {
    name: "fake-external",
    external: true,
    put: () => Promise.reject(new Error("put not used in resolve tests")),
    get,
  };
}

const okRef = { first: "s3://b/t/F/1.json", latest: "s3://b/t/F/2.json" };

describe("resolveRawEvidence", () => {
  it("database store, raw inline present → serves inline, source database", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: { mrn: "X" },
      rawEvidenceRef: null,
      tenantId: "t1",
      store: new DatabaseRawEvidenceStore(),
    });
    expect(r.rawEvidence).toEqual({ mrn: "X" });
    expect(r.rawPresent).toBe(true);
    expect(r.rawSource).toBe("database");
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(false);
  });

  it("database store, raw genuinely absent → bare null, NO unresolved", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: null,
      tenantId: "t1",
      store: new DatabaseRawEvidenceStore(),
    });
    expect(r.rawEvidence).toBeNull();
    expect(r.rawPresent).toBe(false);
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(false);
  });

  it("external store configured, no inline + no ref → unresolved (failed ingest write)", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: null,
      tenantId: "t1",
      store: fakeExternalStore(() => Promise.resolve({})),
    });
    expect(r.rawEvidence).toBeNull();
    expect(r.rawPresent).toBe(false);
    expect(r.rawUnresolved).toMatch(/external write likely failed/);
    expect(r.fallbackUsed).toBe(false);
  });

  it("external ref resolves → serves {first,latest}, source external", async () => {
    const seen: string[] = [];
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: okRef,
      tenantId: "t1",
      store: fakeExternalStore(async ({ uri }) => {
        seen.push(uri);
        return uri === okRef.first ? { occ: 1 } : { occ: 2 };
      }),
    });
    expect(r.rawEvidence).toEqual({ first: { occ: 1 }, latest: { occ: 2 } });
    expect(r.rawSource).toBe("external_store");
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(false);
    expect(seen).toEqual([okRef.first, okRef.latest]);
  });

  it("malformed ref + inline present → inline fallback (no unresolved)", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: { mrn: "legacy" },
      rawEvidenceRef: { first: 1 },
      tenantId: "t1",
      store: fakeExternalStore(() => Promise.resolve({})),
    });
    expect(r.rawEvidence).toEqual({ mrn: "legacy" });
    expect(r.rawSource).toBe("database");
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(true);
  });

  it("malformed ref + no inline → unresolved malformed", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: { first: 1 },
      tenantId: "t1",
      store: fakeExternalStore(() => Promise.resolve({})),
    });
    expect(r.rawEvidence).toBeNull();
    expect(r.rawUnresolved).toMatch(/malformed/);
    expect(r.fallbackUsed).toBe(false);
  });

  it("ref present but no external store configured + inline present → inline fallback", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: { mrn: "legacy" },
      rawEvidenceRef: okRef,
      tenantId: "t1",
      store: new DatabaseRawEvidenceStore(), // external === false
    });
    expect(r.rawEvidence).toEqual({ mrn: "legacy" });
    expect(r.rawSource).toBe("database");
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(true);
  });

  it("ref present but no store at all + no inline → unresolved", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: okRef,
      tenantId: "t1",
      store: null,
    });
    expect(r.rawEvidence).toBeNull();
    expect(r.rawUnresolved).toMatch(/no external store is configured/);
    expect(r.fallbackUsed).toBe(false);
  });

  it("store.get throws + inline present → inline fallback", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: { mrn: "legacy" },
      rawEvidenceRef: okRef,
      tenantId: "t1",
      store: fakeExternalStore(() => Promise.reject(new Error("s3 down"))),
    });
    expect(r.rawEvidence).toEqual({ mrn: "legacy" });
    expect(r.rawSource).toBe("database");
    expect(r.rawUnresolved).toBeUndefined();
    expect(r.fallbackUsed).toBe(true);
  });

  it("store.get throws + no inline → unresolved + null", async () => {
    const r = await resolveRawEvidence({
      rawEvidence: null,
      rawEvidenceRef: okRef,
      tenantId: "t1",
      store: fakeExternalStore(() => Promise.reject(new Error("s3 down"))),
    });
    expect(r.rawEvidence).toBeNull();
    expect(r.rawUnresolved).toMatch(/failed to resolve/);
    expect(r.fallbackUsed).toBe(false);
  });
});
