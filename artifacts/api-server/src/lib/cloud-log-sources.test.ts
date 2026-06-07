import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { and, eq, gt, sql } from "drizzle-orm";
import { db, ledgerEntriesTable, bootstrap } from "@workspace/db";
import {
  CloudwatchLogSource,
  InMemoryCheckpointStore,
  buildCloudwatchSourceFromEnv,
  type CloudwatchClient,
} from "./cloud-log-sources";
import type { LogRecord } from "./log-source";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";
import { uniq } from "../test-support/ledger-harness";

// Tiny in-memory fake client. Per-call response queue so tests can script
// pagination, empty pages, and explicit failures.
type FakeResp = NonNullable<Awaited<ReturnType<CloudwatchClient["filterLogEvents"]>>>;
function fakeClient(queue: Array<FakeResp | Error>): {
  client: CloudwatchClient;
  calls: Array<Parameters<CloudwatchClient["filterLogEvents"]>[0]>;
} {
  const calls: Array<Parameters<CloudwatchClient["filterLogEvents"]>[0]> = [];
  const client: CloudwatchClient = {
    async filterLogEvents(params) {
      calls.push(params);
      const next = queue.shift();
      if (!next) return {};
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

describe("CloudwatchLogSource.pollOnce", () => {
  beforeEach(() => {
    // Tests do not mutate cross-test state — each constructs its own source +
    // store, no resets needed.
  });

  it("publishes events from a single page and advances the cursor", async () => {
    const { client, calls } = fakeClient([
      {
        events: [
          { eventId: "e1", timestamp: 1000, message: "hello" },
          { eventId: "e2", timestamp: 2000, message: "world" },
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const store = new InMemoryCheckpointStore();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/aws/lambda/foo"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: store,
    });

    const r = await src.pollOnce();
    expect(r.published).toBe(2);
    expect(r.pages).toBe(1);
    expect(records).toHaveLength(2);
    expect(records[0]?.sourceType).toBe("cloudwatch");
    expect(records[0]?.sourceName).toBe("/aws/lambda/foo");
    expect(records[0]?.tenantId).toBe(TENANT);
    expect(records[0]?.sourceRecordId).toBe("e1");
    expect(records[0]?.payload).toBe("hello");
    expect(records[0]?.observedAt.getTime()).toBe(1000);
    // First poll: used the lookback window, no checkpoint yet.
    expect(calls[0]?.nextToken).toBeUndefined();
    expect(typeof calls[0]?.startTime).toBe("number");
    // Cursor advanced to the max event ts.
    expect(await store.load("cloudwatch:default:/aws/lambda/foo")).toBe(2000);
  });

  it("paginates via nextToken within a single tick", async () => {
    const { client, calls } = fakeClient([
      {
        events: [{ eventId: "e1", timestamp: 1000, message: "a" }],
        nextToken: "page2",
      },
      {
        events: [{ eventId: "e2", timestamp: 2000, message: "b" }],
        nextToken: "page3",
      },
      {
        events: [{ eventId: "e3", timestamp: 3000, message: "c" }],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(3);
    expect(r.pages).toBe(3);
    expect(records.map((x) => x.payload)).toEqual(["a", "b", "c"]);
    expect(calls[1]?.nextToken).toBe("page2");
    expect(calls[2]?.nextToken).toBe("page3");
  });

  it("caps pages per tick to bound API spend on a burst", async () => {
    // 10 pages queued but maxPagesPerTick=2 should stop after 2.
    const queue: FakeResp[] = Array.from({ length: 10 }, (_, i) => ({
      events: [{ eventId: `e${i}`, timestamp: 1000 + i, message: `m${i}` }],
      nextToken: `t${i + 1}`,
    }));
    const { client } = fakeClient(queue);
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      maxPagesPerTick: 2,
    });
    const r = await src.pollOnce();
    expect(r.pages).toBe(2);
    expect(records).toHaveLength(2);
  });

  it("resumes from the saved cursor + 1ms on the second poll", async () => {
    const { client, calls } = fakeClient([
      { events: [{ eventId: "e1", timestamp: 5000, message: "first" }] },
      { events: [{ eventId: "e2", timestamp: 6000, message: "second" }] },
    ]);
    const { publish } = recordingPublisher();
    const store = new InMemoryCheckpointStore();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: store,
    });
    await src.pollOnce();
    await src.pollOnce();
    expect(calls[0]?.startTime).not.toBe(5001);
    expect(calls[1]?.startTime).toBe(5001);
    expect(await store.load("cloudwatch:default:/g")).toBe(6000);
  });

  it("skips events missing timestamp or message", async () => {
    const { client } = fakeClient([
      {
        events: [
          { eventId: "ok", timestamp: 1000, message: "ok" },
          { eventId: "no-ts", message: "x" },
          { eventId: "no-msg", timestamp: 2000 },
        ],
      },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(1);
    expect(records[0]?.payload).toBe("ok");
  });

  it("synthesizes a sourceRecordId when eventId is absent", async () => {
    const { client } = fakeClient([
      { events: [{ timestamp: 1000, message: "no-id" }] },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await src.pollOnce();
    expect(records[0]?.sourceRecordId).toMatch(/^1000:[0-9a-f]+$/);
  });

  it("freezes the cursor at the contiguous success prefix on a mid-batch failure (re-fetches lost record)", async () => {
    // Architect-flagged M8 fix: cursor MUST track the contiguous success
    // prefix, not the max successful timestamp. Otherwise a failure at
    // ts=2000 followed by a success at ts=3000 would advance the cursor
    // past 2000 and the failed record would never be retried (next poll
    // starts at 3001).
    const { client } = fakeClient([
      {
        events: [
          { eventId: "ok", timestamp: 1000, message: "ok" },
          { eventId: "bad", timestamp: 2000, message: "boom" },
          { eventId: "later", timestamp: 3000, message: "after" },
        ],
      },
    ]);
    const store = new InMemoryCheckpointStore();
    let n = 0;
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish: async (r) => {
        n++;
        if (r.payload === "boom") throw new Error("downstream said no");
      },
      clientFactory: async () => client,
      checkpointStore: store,
    });
    const r = await src.pollOnce();
    expect(n).toBe(3);
    // The two non-throwing publishes still ran (no early-abort), but only
    // the prefix-success counts toward forward progress.
    expect(r.published).toBe(2);
    // Cursor is FROZEN at 1000 — the last contiguously-successful event.
    // Next poll starts at 1001 and re-fetches the failed record at 2000.
    // The later success at 3000 will be re-delivered too; the ingest
    // pipeline already dedupes by fingerprint, so this is a cheap no-op.
    expect(await store.load("cloudwatch:default:/g")).toBe(1000);
  });

  it("advances cursor normally when all events succeed (regression guard for the contiguous-prefix path)", async () => {
    // Same fix as above — make sure the all-success happy path still
    // advances all the way to the max timestamp.
    const { client } = fakeClient([
      {
        events: [
          { eventId: "a", timestamp: 1000, message: "a" },
          { eventId: "b", timestamp: 2000, message: "b" },
          { eventId: "c", timestamp: 3000, message: "c" },
        ],
      },
    ]);
    const store = new InMemoryCheckpointStore();
    const { publish } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: store,
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(3);
    expect(await store.load("cloudwatch:default:/g")).toBe(3000);
  });

  it("sorts out-of-order events by timestamp before applying the contiguous-prefix rule", async () => {
    // FilterLogEvents normally returns events in time order, but the
    // implementation defensively sorts. Confirm that a failure at the
    // *temporally* earliest event freezes the cursor below it even if it
    // arrives last in the API response.
    const { client } = fakeClient([
      {
        events: [
          { eventId: "later", timestamp: 3000, message: "after" },
          { eventId: "bad", timestamp: 1500, message: "boom" },
          { eventId: "early", timestamp: 1000, message: "ok" },
        ],
      },
    ]);
    const store = new InMemoryCheckpointStore();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish: async (r) => {
        if (r.payload === "boom") throw new Error("downstream said no");
      },
      clientFactory: async () => client,
      checkpointStore: store,
    });
    await src.pollOnce();
    // After ascending sort: 1000(ok), 1500(boom), 3000(after).
    // Contiguous success prefix ends at 1000.
    expect(await store.load("cloudwatch:default:/g")).toBe(1000);
  });

  it("polls multiple log groups in a single tick", async () => {
    const { client, calls } = fakeClient([
      { events: [{ eventId: "a1", timestamp: 100, message: "a" }] },
      { events: [{ eventId: "b1", timestamp: 200, message: "b" }] },
    ]);
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g1", "/g2"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(2);
    expect(calls.map((c) => c.logGroupName)).toEqual(["/g1", "/g2"]);
    expect(records.map((x) => x.sourceName)).toEqual(["/g1", "/g2"]);
  });

  it("propagates a filterLogEvents error so runLoop can backoff/alert", async () => {
    const { client } = fakeClient([new Error("AccessDenied")]);
    const { publish } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await expect(src.pollOnce()).rejects.toThrow(/AccessDenied/);
  });
});

describe("CloudwatchLogSource.start/stop lifecycle", () => {
  it("emits ingest.source_started and ingest.source_stopped to the ledger", async () => {
    const { client } = fakeClient([{ events: [] }]);
    const { publish } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/lifecycle-test"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      pollIntervalMs: 10_000, // long — we stop before it ticks again
    });
    const sinceRows = await db
      .select({ seq: sql<number>`MAX(seq)`.as("max_seq") })
      .from(ledgerEntriesTable);
    const sinceSeq = sinceRows[0]?.seq ?? 0;

    await src.start();
    // Give the first tick a moment to fire (pollOnce → no events → done).
    await new Promise((r) => setTimeout(r, 20));
    await src.stop();

    const lifecycleRows = await db
      .select({
        eventType: ledgerEntriesTable.eventType,
        subjectId: ledgerEntriesTable.subjectId,
      })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, sinceSeq),
          eq(ledgerEntriesTable.subjectType, "log_source"),
          eq(ledgerEntriesTable.subjectId, src.name),
        ),
      )
      .orderBy(ledgerEntriesTable.seq);
    const types = lifecycleRows.map((r) => r.eventType);
    expect(types).toContain("ingest.source_started");
    expect(types).toContain("ingest.source_stopped");
    // Started precedes stopped.
    expect(types.indexOf("ingest.source_started")).toBeLessThan(
      types.indexOf("ingest.source_stopped"),
    );
  });

  it("emits ingest.source_error on poll failure and continues (does not throw out of loop)", async () => {
    // First call throws, then on retry returns empty so the loop exits cleanly when we stop.
    const { client } = fakeClient([
      new Error("Throttling"),
      { events: [] },
      { events: [] },
    ]);
    const { publish } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/error-test"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      pollIntervalMs: 10_000,
      initialBackoffMs: 5,
      maxBackoffMs: 5,
    });
    const sinceRows = await db
      .select({ seq: sql<number>`MAX(seq)`.as("max_seq") })
      .from(ledgerEntriesTable);
    const sinceSeq = sinceRows[0]?.seq ?? 0;

    await src.start();
    // Wait for the first tick to throw and the backoff to elapse + one more tick.
    await new Promise((r) => setTimeout(r, 80));
    await src.stop();

    const errorRows = await db
      .select({ eventType: ledgerEntriesTable.eventType })
      .from(ledgerEntriesTable)
      .where(
        and(
          gt(ledgerEntriesTable.seq, sinceSeq),
          eq(ledgerEntriesTable.eventType, "ingest.source_error"),
          eq(ledgerEntriesTable.subjectId, src.name),
        ),
      );
    expect(errorRows.length).toBeGreaterThanOrEqual(1);
  });
});

describe("buildCloudwatchSourceFromEnv", () => {
  const ENV_KEYS = [
    "LOG_SOURCE",
    "CLOUDWATCH_TENANT_ID",
    "CLOUDWATCH_LOG_GROUPS",
    "AWS_REGION",
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
    const src = buildCloudwatchSourceFromEnv(async () => {});
    expect(src).toBeNull();
  });

  it("throws when LOG_SOURCE=cloudwatch is set without required vars", () => {
    process.env["LOG_SOURCE"] = "cloudwatch";
    expect(() => buildCloudwatchSourceFromEnv(async () => {})).toThrow(
      /CLOUDWATCH_TENANT_ID/,
    );
  });

  it("constructs a source with parsed multi-group CSV", () => {
    process.env["LOG_SOURCE"] = "cloudwatch";
    process.env["CLOUDWATCH_TENANT_ID"] = "tenant-a";
    process.env["CLOUDWATCH_LOG_GROUPS"] = "/g1, /g2 ,/g3";
    process.env["AWS_REGION"] = "us-east-1";
    const src = buildCloudwatchSourceFromEnv(async () => {});
    expect(src).not.toBeNull();
    expect(src!.name).toBe("cloudwatch:tenant-a");
  });

  it("rejects empty CLOUDWATCH_LOG_GROUPS after parsing", () => {
    process.env["LOG_SOURCE"] = "cloudwatch";
    process.env["CLOUDWATCH_TENANT_ID"] = "tenant-a";
    process.env["CLOUDWATCH_LOG_GROUPS"] = ", , ,";
    process.env["AWS_REGION"] = "us-east-1";
    expect(() => buildCloudwatchSourceFromEnv(async () => {})).toThrow(
      /empty list/,
    );
  });
});

