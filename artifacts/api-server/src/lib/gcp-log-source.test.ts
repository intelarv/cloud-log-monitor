import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import { db, ledgerEntriesTable, bootstrap } from "@workspace/db";
import { InMemoryCheckpointStore } from "./cloud-log-sources";
import {
  GcpCloudLoggingSource,
  type CloudLoggingClient,
  type CloudLoggingEntry,
} from "./gcp-log-source";
import { buildCloudLoggingSourceFromEnv } from "./log-source-config";
import type { LogRecord } from "./log-source";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";

type FakeResp = Awaited<ReturnType<CloudLoggingClient["listEntries"]>>;
function fakeClient(queue: Array<FakeResp | Error>): {
  client: CloudLoggingClient;
  calls: Array<Parameters<CloudLoggingClient["listEntries"]>[0]>;
} {
  const calls: Array<Parameters<CloudLoggingClient["listEntries"]>[0]> = [];
  const client: CloudLoggingClient = {
    async listEntries(params) {
      calls.push(params);
      const next = queue.shift();
      if (!next) return { entries: [] };
      if (next instanceof Error) throw next;
      return next;
    },
  };
  return { client, calls };
}

function recordingPublisher(): {
  publish: (r: LogRecord) => Promise<void>;
  records: LogRecord[];
} {
  const records: LogRecord[] = [];
  return {
    publish: async (r) => {
      records.push(r);
    },
    records,
  };
}

function entry(
  ts: string,
  opts: Partial<CloudLoggingEntry> = {},
): CloudLoggingEntry {
  return { timestamp: ts, textPayload: "msg", ...opts };
}

describe("GcpCloudLoggingSource.pollOnce", () => {
  it("publishes entries from a single page and advances the cursor", async () => {
    const { client, calls } = fakeClient([
      {
        entries: [
          entry("2024-01-01T00:00:01.000Z", {
            insertId: "i1",
            textPayload: "hello",
          }),
          entry("2024-01-01T00:00:02.000Z", {
            insertId: "i2",
            textPayload: "world",
          }),
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const store = new InMemoryCheckpointStore();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "proj-x",
      groups: ["my-log"],
      publish,
      clientFactory: async () => client,
      checkpointStore: store,
    });

    const r = await src.pollOnce();
    expect(r.published).toBe(2);
    expect(records).toHaveLength(2);
    expect(records[0]?.sourceType).toBe("cloud_logging");
    expect(records[0]?.sourceName).toBe("my-log");
    expect(records[0]?.tenantId).toBe(TENANT);
    expect(records[0]?.sourceRecordId).toBe("i1");
    expect(records[0]?.payload).toBe("hello");
    // Filter is fully-qualified + URL-encoded logName, strictly-after cursor.
    expect(calls[0]?.filter).toContain(
      'logName="projects/proj-x/logs/my-log"',
    );
    expect(calls[0]?.filter).toContain("timestamp>");
    expect(calls[0]?.orderBy).toBe("timestamp asc");
    expect(await store.load("cloud_logging:default:my-log")).toBe(
      Date.parse("2024-01-01T00:00:02.000Z"),
    );
  });

  it("URL-encodes log ids that contain a slash", async () => {
    const { client, calls } = fakeClient([{ entries: [] }]);
    const { publish } = recordingPublisher();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "proj-x",
      groups: ["cloudaudit.googleapis.com/activity"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await src.pollOnce();
    expect(calls[0]?.filter).toContain(
      'logName="projects/proj-x/logs/cloudaudit.googleapis.com%2Factivity"',
    );
  });

  it("serializes jsonPayload and skips entries with neither payload", async () => {
    const { client } = fakeClient([
      {
        entries: [
          entry("2024-01-01T00:00:01.000Z", {
            textPayload: undefined,
            jsonPayload: { a: 1 },
          }),
          { timestamp: "2024-01-01T00:00:02.000Z" },
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "p",
      groups: ["g"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(1);
    expect(records[0]?.payload).toBe('{"a":1}');
  });

  it("synthesizes a sourceRecordId when insertId is absent", async () => {
    const { client } = fakeClient([
      { entries: [entry("2024-01-01T00:00:01.000Z", { textPayload: "x" })] },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "p",
      groups: ["g"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await src.pollOnce();
    const ts = Date.parse("2024-01-01T00:00:01.000Z");
    expect(records[0]?.sourceRecordId).toMatch(
      new RegExp(`^${ts}:[0-9a-f]+$`),
    );
  });

  it("paginates within a tick and caps pages per tick", async () => {
    const queue: FakeResp[] = Array.from({ length: 10 }, (_, i) => ({
      entries: [
        entry(new Date(1_000 + i).toISOString(), { insertId: `i${i}` }),
      ],
      nextPageToken: `p${i + 1}`,
    }));
    const { client } = fakeClient(queue);
    const { publish, records } = recordingPublisher();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "p",
      groups: ["g"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      maxPagesPerTick: 2,
    });
    await src.pollOnce();
    // Capped at 2 pages → 2 records.
    expect(records).toHaveLength(2);
  });

  it("freezes the cursor at the contiguous success prefix on a mid-batch failure", async () => {
    const { client } = fakeClient([
      {
        entries: [
          entry("2024-01-01T00:00:01.000Z", {
            insertId: "ok",
            textPayload: "ok",
          }),
          entry("2024-01-01T00:00:02.000Z", {
            insertId: "bad",
            textPayload: "boom",
          }),
          entry("2024-01-01T00:00:03.000Z", {
            insertId: "later",
            textPayload: "after",
          }),
        ],
      },
    ]);
    const store = new InMemoryCheckpointStore();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "p",
      groups: ["g"],
      publish: async (r) => {
        if (r.payload === "boom") throw new Error("downstream said no");
      },
      clientFactory: async () => client,
      checkpointStore: store,
    });
    await src.pollOnce();
    expect(await store.load("cloud_logging:default:g")).toBe(
      Date.parse("2024-01-01T00:00:01.000Z"),
    );
  });
});

describe("GcpCloudLoggingSource lifecycle", () => {
  it("emits ingest.source_started and ingest.source_stopped to the ledger", async () => {
    const { client } = fakeClient([{ entries: [] }]);
    const { publish } = recordingPublisher();
    const src = new GcpCloudLoggingSource({
      tenantId: TENANT,
      projectId: "p",
      groups: ["/lifecycle-gcp"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      pollIntervalMs: 10_000,
    });
    const sinceRows = await db
      .select({ seq: sql<number>`MAX(seq)`.as("max_seq") })
      .from(ledgerEntriesTable);
    const sinceSeq = sinceRows[0]?.seq ?? 0;

    await src.start();
    await new Promise((r) => setTimeout(r, 20));
    await src.stop();

    const rows = await db
      .select({ eventType: ledgerEntriesTable.eventType })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, sinceSeq),
          eq(ledgerEntriesTable.subjectType, "log_source"),
          eq(ledgerEntriesTable.subjectId, src.name),
        ),
      )
      .orderBy(ledgerEntriesTable.seq);
    const types = rows.map((r) => r.eventType);
    expect(types).toContain("ingest.source_started");
    expect(types).toContain("ingest.source_stopped");
  });
});

describe("buildCloudLoggingSourceFromEnv", () => {
  const ENV_KEYS = [
    "LOG_SOURCE",
    "CLOUD_LOGGING_TENANT_ID",
    "GCP_PROJECT_ID",
    "GCP_LOG_IDS",
  ] as const;
  const original: Record<string, string | undefined> = {};
  beforeAll(() => {
    for (const k of ENV_KEYS) original[k] = process.env[k];
  });
  beforeEach(() => {
    for (const k of ENV_KEYS) delete process.env[k];
  });
  afterAll(() => {
    for (const k of ENV_KEYS) {
      if (original[k] !== undefined) process.env[k] = original[k];
      else delete process.env[k];
    }
  });

  it("returns null when LOG_SOURCE is unset (inert by default)", () => {
    expect(buildCloudLoggingSourceFromEnv(async () => {})).toBeNull();
  });

  it("throws when selected without required vars", () => {
    process.env["LOG_SOURCE"] = "cloud_logging";
    expect(() => buildCloudLoggingSourceFromEnv(async () => {})).toThrow(
      /CLOUD_LOGGING_TENANT_ID/,
    );
  });

  it("constructs a source with parsed multi-id CSV", () => {
    process.env["LOG_SOURCE"] = "cloud_logging";
    process.env["CLOUD_LOGGING_TENANT_ID"] = "tenant-g";
    process.env["GCP_PROJECT_ID"] = "proj-x";
    process.env["GCP_LOG_IDS"] = "a, b ,c";
    const src = buildCloudLoggingSourceFromEnv(async () => {});
    expect(src).not.toBeNull();
    expect(src!.name).toBe("cloud_logging:tenant-g");
  });
});
