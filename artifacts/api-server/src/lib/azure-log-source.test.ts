import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import { db, ledgerEntriesTable, bootstrap } from "@workspace/db";
import { InMemoryCheckpointStore } from "./cloud-log-sources";
import {
  AzureMonitorSource,
  type AzureMonitorClient,
} from "./azure-log-source";
import { buildAzureMonitorSourceFromEnv } from "./log-source-config";
import type { LogRecord } from "./log-source";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";

type FakeResp = Awaited<ReturnType<AzureMonitorClient["queryWorkspace"]>>;
function fakeClient(queue: Array<FakeResp | Error>): {
  client: AzureMonitorClient;
  calls: Array<Parameters<AzureMonitorClient["queryWorkspace"]>[0]>;
} {
  const calls: Array<Parameters<AzureMonitorClient["queryWorkspace"]>[0]> = [];
  const client: AzureMonitorClient = {
    async queryWorkspace(params) {
      calls.push(params);
      const next = queue.shift();
      if (!next) return { columns: [], rows: [] };
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

describe("AzureMonitorSource.pollOnce", () => {
  it("publishes rows and advances the cursor over TimeGenerated", async () => {
    const t1 = new Date("2024-01-01T00:00:01.000Z");
    const t2 = new Date("2024-01-01T00:00:02.000Z");
    const { client, calls } = fakeClient([
      {
        columns: ["TimeGenerated", "Message"],
        rows: [
          [t1, "hello"],
          [t2, "world"],
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const store = new InMemoryCheckpointStore();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws-1",
      groups: ["AppTraces"],
      publish,
      clientFactory: async () => client,
      checkpointStore: store,
    });

    const r = await src.pollOnce();
    expect(r.published).toBe(2);
    expect(records).toHaveLength(2);
    expect(records[0]?.sourceType).toBe("azure_monitor");
    expect(records[0]?.sourceName).toBe("AppTraces");
    expect(records[0]?.tenantId).toBe(TENANT);
    expect(records[0]?.payload).toBe(
      JSON.stringify({ TimeGenerated: t1, Message: "hello" }),
    );
    // KQL query references the table, a strictly-after filter, asc order, take.
    expect(calls[0]?.query).toContain("AppTraces");
    expect(calls[0]?.query).toContain("TimeGenerated > datetime(");
    expect(calls[0]?.query).toContain("order by TimeGenerated asc");
    expect(calls[0]?.query).toContain("take 1000");
    expect(await store.load("azure_monitor:default:AppTraces")).toBe(
      t2.getTime(),
    );
  });

  it("synthesizes a stable sourceRecordId from ts + row hash", async () => {
    const ts = new Date("2024-01-01T00:00:01.000Z");
    const { client } = fakeClient([
      { columns: ["TimeGenerated", "Message"], rows: [[ts, "x"]] },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws",
      groups: ["T"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await src.pollOnce();
    expect(records[0]?.sourceRecordId).toMatch(
      new RegExp(`^${ts.getTime()}:[0-9a-f]+$`),
    );
  });

  it("accepts string TimeGenerated values and skips unparseable rows", async () => {
    const { client } = fakeClient([
      {
        columns: ["TimeGenerated", "Message"],
        rows: [
          ["2024-01-01T00:00:01.000Z", "ok"],
          ["not-a-date", "skip"],
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws",
      groups: ["T"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(1);
    expect(records[0]?.payload).toContain("ok");
  });

  it("respects maxRowsPerTick in the KQL take clause", async () => {
    const { client, calls } = fakeClient([{ columns: [], rows: [] }]);
    const { publish } = recordingPublisher();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws",
      groups: ["T"],
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      maxRowsPerTick: 50,
    });
    await src.pollOnce();
    expect(calls[0]?.query).toContain("take 50");
  });

  it("freezes the cursor at the contiguous success prefix on a mid-batch failure", async () => {
    const t1 = new Date("2024-01-01T00:00:01.000Z");
    const t2 = new Date("2024-01-01T00:00:02.000Z");
    const t3 = new Date("2024-01-01T00:00:03.000Z");
    const { client } = fakeClient([
      {
        columns: ["TimeGenerated", "Message"],
        rows: [
          [t1, "ok"],
          [t2, "boom"],
          [t3, "after"],
        ],
      },
    ]);
    const store = new InMemoryCheckpointStore();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws",
      groups: ["T"],
      publish: async (r) => {
        if (r.payload.includes("boom")) throw new Error("downstream said no");
      },
      clientFactory: async () => client,
      checkpointStore: store,
    });
    await src.pollOnce();
    expect(await store.load("azure_monitor:default:T")).toBe(t1.getTime());
  });
});

describe("AzureMonitorSource lifecycle", () => {
  it("emits ingest.source_started and ingest.source_stopped to the ledger", async () => {
    const { client } = fakeClient([{ columns: [], rows: [] }]);
    const { publish } = recordingPublisher();
    const src = new AzureMonitorSource({
      tenantId: TENANT,
      workspaceId: "ws",
      groups: ["LifecycleAzure"],
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
      );
    const types = rows.map((r) => r.eventType);
    expect(types).toContain("ingest.source_started");
    expect(types).toContain("ingest.source_stopped");
  });
});

describe("buildAzureMonitorSourceFromEnv", () => {
  const ENV_KEYS = [
    "LOG_SOURCE",
    "AZURE_MONITOR_TENANT_ID",
    "AZURE_MONITOR_WORKSPACE_ID",
    "AZURE_MONITOR_TABLES",
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
    expect(buildAzureMonitorSourceFromEnv(async () => {})).toBeNull();
  });

  it("throws when selected without required vars", () => {
    process.env["LOG_SOURCE"] = "azure_monitor";
    expect(() => buildAzureMonitorSourceFromEnv(async () => {})).toThrow(
      /AZURE_MONITOR_TENANT_ID/,
    );
  });

  it("rejects an invalid (KQL-injection) table name", () => {
    process.env["LOG_SOURCE"] = "azure_monitor";
    process.env["AZURE_MONITOR_TENANT_ID"] = "t";
    process.env["AZURE_MONITOR_WORKSPACE_ID"] = "ws";
    process.env["AZURE_MONITOR_TABLES"] = "AppTraces | where 1==1";
    expect(() => buildAzureMonitorSourceFromEnv(async () => {})).toThrow(
      /invalid table name/,
    );
  });

  it("constructs a source with parsed multi-table CSV", () => {
    process.env["LOG_SOURCE"] = "azure_monitor";
    process.env["AZURE_MONITOR_TENANT_ID"] = "tenant-z";
    process.env["AZURE_MONITOR_WORKSPACE_ID"] = "ws-1";
    process.env["AZURE_MONITOR_TABLES"] = "AppTraces, AzureActivity";
    const src = buildAzureMonitorSourceFromEnv(async () => {});
    expect(src).not.toBeNull();
    expect(src!.name).toBe("azure_monitor:tenant-z");
  });
});
