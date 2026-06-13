import { describe, it, expect, beforeAll, beforeEach, afterAll } from "vitest";
import { bootstrap } from "@workspace/db";
import {
  CloudwatchLogSource,
  InMemoryCheckpointStore,
  type CloudwatchClient,
} from "./cloud-log-sources";
import { GcpCloudLoggingSource } from "./gcp-log-source";
import { AzureMonitorSource } from "./azure-log-source";
import { buildLogSourceFromEnv } from "./log-source-config";
import type { LogRecord } from "./log-source";

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

const TENANT = "default";

describe("buildLogSourceFromEnv dispatcher", () => {
  const ENV_KEYS = [
    "LOG_SOURCE",
    "CLOUDWATCH_TENANT_ID",
    "CLOUDWATCH_LOG_GROUPS",
    "AWS_REGION",
    "CLOUD_LOGGING_TENANT_ID",
    "GCP_PROJECT_ID",
    "GCP_LOG_IDS",
    "AZURE_MONITOR_TENANT_ID",
    "AZURE_MONITOR_WORKSPACE_ID",
    "AZURE_MONITOR_TABLES",
    "LOG_SOURCE_MAX_CONCURRENT_GROUPS",
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
    expect(buildLogSourceFromEnv(async () => {})).toBeNull();
  });

  it("throws on an unrecognized LOG_SOURCE value", () => {
    process.env["LOG_SOURCE"] = "splunk";
    expect(() => buildLogSourceFromEnv(async () => {})).toThrow(
      /not recognized/,
    );
  });

  it("dispatches to CloudwatchLogSource", () => {
    process.env["LOG_SOURCE"] = "cloudwatch";
    process.env["CLOUDWATCH_TENANT_ID"] = "t";
    process.env["CLOUDWATCH_LOG_GROUPS"] = "/g";
    process.env["AWS_REGION"] = "us-east-1";
    expect(buildLogSourceFromEnv(async () => {})).toBeInstanceOf(
      CloudwatchLogSource,
    );
  });

  it("dispatches to GcpCloudLoggingSource", () => {
    process.env["LOG_SOURCE"] = "cloud_logging";
    process.env["CLOUD_LOGGING_TENANT_ID"] = "t";
    process.env["GCP_PROJECT_ID"] = "p";
    process.env["GCP_LOG_IDS"] = "g";
    expect(buildLogSourceFromEnv(async () => {})).toBeInstanceOf(
      GcpCloudLoggingSource,
    );
  });

  it("dispatches to AzureMonitorSource", () => {
    process.env["LOG_SOURCE"] = "azure_monitor";
    process.env["AZURE_MONITOR_TENANT_ID"] = "t";
    process.env["AZURE_MONITOR_WORKSPACE_ID"] = "ws";
    process.env["AZURE_MONITOR_TABLES"] = "AppTraces";
    expect(buildLogSourceFromEnv(async () => {})).toBeInstanceOf(
      AzureMonitorSource,
    );
  });
});

// Tiny fake CloudWatch client whose per-group calls observe concurrency.
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

describe("PollingLogSource bounded concurrency", () => {
  it("polls groups sequentially by default (maxConcurrentGroups=1)", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const client: CloudwatchClient = {
      async filterLogEvents(params) {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        return {
          events: [
            { eventId: `${params.logGroupName}-1`, timestamp: 1000, message: "m" },
          ],
        };
      },
    };
    const { publish } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g1", "/g2", "/g3"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
    });
    await src.pollOnce();
    expect(maxInFlight).toBe(1);
  });

  it("polls groups concurrently up to maxConcurrentGroups", async () => {
    let inFlight = 0;
    let maxInFlight = 0;
    const client: CloudwatchClient = {
      async filterLogEvents(params) {
        inFlight++;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 5));
        inFlight--;
        return {
          events: [
            { eventId: `${params.logGroupName}-1`, timestamp: 1000, message: "m" },
          ],
        };
      },
    };
    const { publish, records } = recordingPublisher();
    const src = new CloudwatchLogSource({
      tenantId: TENANT,
      logGroups: ["/g1", "/g2", "/g3", "/g4"],
      region: "us-east-1",
      publish,
      clientFactory: async () => client,
      checkpointStore: new InMemoryCheckpointStore(),
      maxConcurrentGroups: 2,
    });
    const r = await src.pollOnce();
    expect(r.published).toBe(4);
    expect(records).toHaveLength(4);
    // Concurrency observed but bounded at 2.
    expect(maxInFlight).toBeGreaterThan(1);
    expect(maxInFlight).toBeLessThanOrEqual(2);
  });
});
