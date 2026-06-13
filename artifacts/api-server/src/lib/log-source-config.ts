// M8: Unified env-driven LogSource selection.
//
// One dispatcher over `LOG_SOURCE` so `index.ts` wires a single seam instead
// of one builder per cloud. Default-INERT: `LOG_SOURCE` unset → returns null
// → dev keeps the fixture-replay-only behavior, and the credential-free eval
// gate is byte-identical. An unknown value throws loudly at boot (operator
// typo) rather than silently ingesting nothing.
//
// Mirrors `buildCloudwatchSourceFromEnv` (which stays the canonical builder for
// the AWS branch and is reused here). GCP/Azure builders live here next to the
// dispatcher because they share the same concurrency/poll env conventions.

import {
  buildCloudwatchSourceFromEnv,
  type CloudwatchClient,
} from "./cloud-log-sources";
import { parsePositiveIntEnv } from "./polling-log-source";
import { GcpCloudLoggingSource } from "./gcp-log-source";
import { AzureMonitorSource } from "./azure-log-source";
import type { LogRecord, LogSource } from "./log-source";

// Shared concurrency knob across every pull-based source: max log groups
// polled concurrently per tick. Default 1 (sequential — byte-identical to the
// original CloudWatch behavior). Bounded so a wide group fan-out can't open an
// unbounded number of in-flight SDK calls.
function maxConcurrentGroupsFromEnv(): number {
  return parsePositiveIntEnv(process.env["LOG_SOURCE_MAX_CONCURRENT_GROUPS"], 1);
}

function csv(raw: string | undefined): string[] {
  return (raw ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Build a GCP Cloud Logging source from env, or null if not selected. */
export function buildCloudLoggingSourceFromEnv(
  publish: (record: LogRecord) => Promise<unknown>,
): GcpCloudLoggingSource | null {
  if (process.env["LOG_SOURCE"] !== "cloud_logging") return null;
  const tenantId = process.env["CLOUD_LOGGING_TENANT_ID"];
  const projectId = process.env["GCP_PROJECT_ID"];
  const groups = csv(process.env["GCP_LOG_IDS"]);
  if (!tenantId)
    throw new Error("LOG_SOURCE=cloud_logging requires CLOUD_LOGGING_TENANT_ID");
  if (!projectId)
    throw new Error("LOG_SOURCE=cloud_logging requires GCP_PROJECT_ID");
  if (groups.length === 0)
    throw new Error("LOG_SOURCE=cloud_logging requires GCP_LOG_IDS (CSV of log ids)");
  return new GcpCloudLoggingSource({
    tenantId,
    projectId,
    groups,
    publish,
    pollIntervalMs: parsePositiveIntEnv(
      process.env["CLOUD_LOGGING_POLL_INTERVAL_MS"],
      5000,
    ),
    lookbackMsOnFirstPoll: parsePositiveIntEnv(
      process.env["CLOUD_LOGGING_LOOKBACK_MS"],
      5 * 60 * 1000,
    ),
    maxConcurrentGroups: maxConcurrentGroupsFromEnv(),
  });
}

// Log Analytics table names are KQL identifiers interpolated into the query;
// constrain to the documented charset (letters, digits, underscore) so a
// misconfigured env can't smuggle KQL operators into the query string.
const AZURE_TABLE_RE = /^[A-Za-z0-9_]+$/;

/** Build an Azure Monitor source from env, or null if not selected. */
export function buildAzureMonitorSourceFromEnv(
  publish: (record: LogRecord) => Promise<unknown>,
): AzureMonitorSource | null {
  if (process.env["LOG_SOURCE"] !== "azure_monitor") return null;
  const tenantId = process.env["AZURE_MONITOR_TENANT_ID"];
  const workspaceId = process.env["AZURE_MONITOR_WORKSPACE_ID"];
  const tables = csv(process.env["AZURE_MONITOR_TABLES"]);
  if (!tenantId)
    throw new Error("LOG_SOURCE=azure_monitor requires AZURE_MONITOR_TENANT_ID");
  if (!workspaceId)
    throw new Error(
      "LOG_SOURCE=azure_monitor requires AZURE_MONITOR_WORKSPACE_ID",
    );
  if (tables.length === 0)
    throw new Error(
      "LOG_SOURCE=azure_monitor requires AZURE_MONITOR_TABLES (CSV of table names)",
    );
  for (const t of tables) {
    if (!AZURE_TABLE_RE.test(t))
      throw new Error(
        `LOG_SOURCE=azure_monitor: invalid table name "${t}" (letters/digits/underscore only)`,
      );
  }
  return new AzureMonitorSource({
    tenantId,
    workspaceId,
    groups: tables,
    publish,
    pollIntervalMs: parsePositiveIntEnv(
      process.env["AZURE_MONITOR_POLL_INTERVAL_MS"],
      5000,
    ),
    lookbackMsOnFirstPoll: parsePositiveIntEnv(
      process.env["AZURE_MONITOR_LOOKBACK_MS"],
      5 * 60 * 1000,
    ),
    maxConcurrentGroups: maxConcurrentGroupsFromEnv(),
  });
}

/** Single dispatcher over `LOG_SOURCE`. Returns the configured source, or null
 *  when `LOG_SOURCE` is unset (dev default). Throws on an unknown value. */
export function buildLogSourceFromEnv(
  publish: (record: LogRecord) => Promise<unknown>,
): LogSource | null {
  const sel = process.env["LOG_SOURCE"];
  if (!sel) return null;
  switch (sel) {
    case "cloudwatch":
      return buildCloudwatchSourceFromEnv(publish, {
        maxConcurrentGroups: maxConcurrentGroupsFromEnv(),
      });
    case "cloud_logging":
      return buildCloudLoggingSourceFromEnv(publish);
    case "azure_monitor":
      return buildAzureMonitorSourceFromEnv(publish);
    default:
      throw new Error(
        `LOG_SOURCE="${sel}" is not recognized (expected cloudwatch | cloud_logging | azure_monitor)`,
      );
  }
}

// Re-export the concrete client interfaces so test files / operators have a
// single import surface for the source layer.
export type { CloudwatchClient };
