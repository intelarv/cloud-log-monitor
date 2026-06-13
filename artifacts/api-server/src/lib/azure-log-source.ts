// M8: Azure Monitor (Log Analytics) source adapter.
//
// Pull-based, behind the same `LogSource` seam as CloudWatch/GCP, built on the
// shared `PollingLogSource` base. Only the cloud-specific KQL query lives here.
//
// SDKs (`@azure/monitor-query` + `@azure/identity`) are lazy-loaded via the
// variable-aliased dynamic import in the base, so they are OPTIONAL
// dependencies — a dev install never pulls them. An operator on Azure opts in
// with `LOG_SOURCE=azure_monitor` + the required vars and installs the SDKs.
//
// Per threat_model "System ↔ Log Sources": row data is attacker-controlled;
// this module only serializes it into a LogRecord payload for the ingest
// pipeline to detect+redact.

import {
  PollingLogSource,
  loadOptionalSdk,
  shortHash,
  type CollectedRecord,
  type PollingLogSourceOpts,
} from "./polling-log-source";
import type { LogSourceType } from "./log-source";

/** Minimal query result shape. The real `LogsQueryClient.queryWorkspace`
 *  returns a richer object (status, tables[]); the lazy loader flattens the
 *  primary table into this. */
export interface AzureMonitorClient {
  queryWorkspace(params: {
    query: string;
    startTimeMs: number;
    endTimeMs: number;
  }): Promise<{ columns: string[]; rows: unknown[][] }>;
}

export interface AzureMonitorSourceOpts extends PollingLogSourceOpts {
  /** Log Analytics workspace id (GUID). */
  readonly workspaceId: string;
  /** Max rows fetched per tick per table (KQL `take`). Default 1000. */
  readonly maxRowsPerTick?: number;
  /** Test injection: bypass the real SDK loader. */
  readonly clientFactory?: () => Promise<AzureMonitorClient>;
}

/** Serialize a result row to a stable string payload: a JSON object keyed by
 *  column name, skipping null/undefined cells. Deterministic given column
 *  order so the synthesized record id is stable across re-fetches. */
function rowToPayload(columns: string[], row: unknown[]): string {
  const obj: Record<string, unknown> = {};
  for (let i = 0; i < columns.length; i++) {
    const v = row[i];
    if (v !== null && v !== undefined) obj[columns[i]!] = v;
  }
  return JSON.stringify(obj);
}

export class AzureMonitorSource extends PollingLogSource {
  readonly name: string;
  protected readonly sourceType: LogSourceType = "azure_monitor";
  protected readonly provider = "azure_monitor";
  private readonly workspaceId: string;
  private readonly maxRowsPerTick: number;
  private readonly clientFactory?: () => Promise<AzureMonitorClient>;
  private clientPromise: Promise<AzureMonitorClient> | null = null;

  constructor(opts: AzureMonitorSourceOpts) {
    super(opts);
    this.workspaceId = opts.workspaceId;
    this.name = `azure_monitor:${opts.tenantId}`;
    this.maxRowsPerTick = opts.maxRowsPerTick ?? 1000;
    if (opts.clientFactory) this.clientFactory = opts.clientFactory;
  }

  private async getClient(): Promise<AzureMonitorClient> {
    if (this.clientFactory) return this.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let monitor: any;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let identity: any;
        try {
          monitor = await loadOptionalSdk("@azure/monitor-query");
          identity = await loadOptionalSdk("@azure/identity");
        } catch {
          throw new Error(
            "AzureMonitorSource selected but @azure/monitor-query / " +
              "@azure/identity are not installed. Run: pnpm --filter " +
              "@workspace/api-server add @azure/monitor-query @azure/identity",
          );
        }
        const credential = new identity.DefaultAzureCredential();
        const client = new monitor.LogsQueryClient(credential);
        const workspaceId = this.workspaceId;
        return {
          async queryWorkspace(params) {
            const resp = (await client.queryWorkspace(
              workspaceId,
              params.query,
              {
                startTime: new Date(params.startTimeMs),
                endTime: new Date(params.endTimeMs),
              },
            )) as {
              status?: string;
              tables?: Array<{
                columnDescriptors?: Array<{ name?: string }>;
                columns?: Array<{ name?: string }>;
                rows?: unknown[][];
              }>;
            };
            const table = resp.tables?.[0];
            const cols = (table?.columnDescriptors ?? table?.columns ?? [])
              .map((c) => c?.name ?? "")
              .filter((n) => n.length > 0);
            return { columns: cols, rows: table?.rows ?? [] };
          },
        };
      })();
    }
    return this.clientPromise;
  }

  protected async fetchGroup(
    table: string,
    startTimeMs: number,
  ): Promise<CollectedRecord[]> {
    const client = await this.getClient();
    const startRfc = new Date(startTimeMs).toISOString();
    // KQL: events strictly newer than the cursor, oldest-first, capped. Table
    // name is validated in the env builder (alnum/underscore only), so it is
    // safe to interpolate. `TimeGenerated` is the standard Log Analytics
    // ingestion-time column present on every table.
    const query =
      `${table} | where TimeGenerated > datetime(${startRfc}) | ` +
      `order by TimeGenerated asc | take ${this.maxRowsPerTick}`;
    const resp = await client.queryWorkspace({
      query,
      startTimeMs,
      endTimeMs: Date.now(),
    });
    const tgIdx = resp.columns.indexOf("TimeGenerated");
    const out: CollectedRecord[] = [];
    for (const row of resp.rows) {
      const tgVal = tgIdx >= 0 ? row[tgIdx] : undefined;
      const ts =
        tgVal instanceof Date
          ? tgVal.getTime()
          : tgVal !== undefined
            ? Date.parse(String(tgVal))
            : NaN;
      if (!Number.isFinite(ts)) continue;
      const payload = rowToPayload(resp.columns, row);
      // Log Analytics rows carry no globally-unique id; synthesize a stable one
      // from the event ts + a short hash of the serialized row.
      const sourceRecordId = `${ts}:${shortHash(payload)}`;
      out.push({
        ts,
        sourceRecordId,
        record: {
          tenantId: this.baseOpts.tenantId,
          sourceType: this.sourceType,
          sourceName: table,
          sourceRecordId,
          observedAt: new Date(ts),
          ingestedAt: new Date(),
          payload,
        },
      });
    }
    return out;
  }
}
