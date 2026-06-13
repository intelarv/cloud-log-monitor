// M8: GCP Cloud Logging source adapter.
//
// Pull-based, behind the same `LogSource` seam as CloudWatch, built on the
// shared `PollingLogSource` base (poll loop, backoff, contiguous-watermark
// cursor, lifecycle ledger). Only the cloud-specific fetch lives here.
//
// SDK (`@google-cloud/logging`) is lazy-loaded via the variable-aliased
// dynamic import in the base, so it is an OPTIONAL dependency — a dev install
// never pulls it. An operator running on GCP opts in with
// `LOG_SOURCE=cloud_logging` + the required vars and installs the SDK.
//
// Per threat_model "System ↔ Log Sources": entry payloads are
// attacker-controlled; this module only wraps them in a LogRecord for the
// ingest pipeline to detect+redact. Provenance fields land verbatim; the
// ingest trust-boundary validation runs downstream.

import {
  PollingLogSource,
  loadOptionalSdk,
  shortHash,
  type CollectedRecord,
  type PollingLogSourceOpts,
} from "./polling-log-source";
import type { LogSourceType } from "./log-source";

/** Minimal Cloud Logging entry shape we actually use. The real SDK returns
 *  rich `Entry` objects; the lazy loader adapts them to this. */
export interface CloudLoggingEntry {
  insertId?: string;
  /** RFC3339 timestamp string (event time). */
  timestamp?: string;
  logName?: string;
  textPayload?: string;
  jsonPayload?: unknown;
}

/** Minimal client shape. The real `@google-cloud/logging` `Logging#getEntries`
 *  returns `[entries, nextQuery, apiResponse]`; the lazy loader adapts that to
 *  this single-page-at-a-time interface so the rest of the module is
 *  SDK-agnostic and trivial to mock. */
export interface CloudLoggingClient {
  listEntries(params: {
    filter: string;
    orderBy?: string;
    pageSize?: number;
    pageToken?: string;
  }): Promise<{ entries: CloudLoggingEntry[]; nextPageToken?: string }>;
}

export interface GcpCloudLoggingSourceOpts extends PollingLogSourceOpts {
  /** GCP project id (used to build the fully-qualified logName filter). */
  readonly projectId: string;
  /** Max pages per tick per group. Default 5. */
  readonly maxPagesPerTick?: number;
  /** Test injection: bypass the real SDK loader. */
  readonly clientFactory?: () => Promise<CloudLoggingClient>;
}

/** textPayload wins; otherwise serialize jsonPayload; null if neither is
 *  present (skip — nothing to scan). */
function entryPayloadToString(e: CloudLoggingEntry): string | null {
  if (typeof e.textPayload === "string") return e.textPayload;
  if (e.jsonPayload !== undefined && e.jsonPayload !== null) {
    try {
      return JSON.stringify(e.jsonPayload);
    } catch {
      return null;
    }
  }
  return null;
}

export class GcpCloudLoggingSource extends PollingLogSource {
  readonly name: string;
  protected readonly sourceType: LogSourceType = "cloud_logging";
  protected readonly provider = "cloud_logging";
  private readonly projectId: string;
  private readonly maxPagesPerTick: number;
  private readonly clientFactory?: () => Promise<CloudLoggingClient>;
  private clientPromise: Promise<CloudLoggingClient> | null = null;

  constructor(opts: GcpCloudLoggingSourceOpts) {
    super(opts);
    this.projectId = opts.projectId;
    this.name = `cloud_logging:${opts.tenantId}`;
    this.maxPagesPerTick = opts.maxPagesPerTick ?? 5;
    if (opts.clientFactory) this.clientFactory = opts.clientFactory;
  }

  private async getClient(): Promise<CloudLoggingClient> {
    if (this.clientFactory) return this.clientFactory();
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let mod: any;
        try {
          mod = await loadOptionalSdk("@google-cloud/logging");
        } catch {
          throw new Error(
            "GcpCloudLoggingSource selected but @google-cloud/logging is not " +
              "installed. Run: pnpm --filter @workspace/api-server add @google-cloud/logging",
          );
        }
        const logging = new mod.Logging({ projectId: this.projectId });
        return {
          async listEntries(params) {
            // autoPaginate:false → single page; nextQuery carries the page
            // token for the following page.
            const [entries, nextQuery] = (await logging.getEntries({
              filter: params.filter,
              ...(params.orderBy ? { orderBy: params.orderBy } : {}),
              ...(params.pageSize ? { pageSize: params.pageSize } : {}),
              ...(params.pageToken ? { pageToken: params.pageToken } : {}),
              autoPaginate: false,
              // eslint-disable-next-line @typescript-eslint/no-explicit-any
            })) as [Array<{ metadata?: any; data?: unknown }>, { pageToken?: string } | undefined, unknown];
            const mapped: CloudLoggingEntry[] = entries.map((entry) => {
              const md = entry.metadata ?? {};
              const out: CloudLoggingEntry = {};
              if (md.insertId) out.insertId = String(md.insertId);
              if (md.timestamp)
                out.timestamp =
                  md.timestamp instanceof Date
                    ? md.timestamp.toISOString()
                    : String(md.timestamp);
              if (md.logName) out.logName = String(md.logName);
              if (typeof entry.data === "string") out.textPayload = entry.data;
              else if (entry.data !== undefined) out.jsonPayload = entry.data;
              return out;
            });
            const result: { entries: CloudLoggingEntry[]; nextPageToken?: string } =
              { entries: mapped };
            if (nextQuery?.pageToken) result.nextPageToken = nextQuery.pageToken;
            return result;
          },
        };
      })();
    }
    return this.clientPromise;
  }

  protected async fetchGroup(
    logId: string,
    startTimeMs: number,
  ): Promise<CollectedRecord[]> {
    const client = await this.getClient();
    const startRfc = new Date(startTimeMs).toISOString();
    // Fully-qualified logName per the Cloud Logging filter grammar. The log id
    // is URL-encoded (a logName segment can legally contain "/"). timestamp is
    // strictly greater-than (we already advanced the cursor by 1ms).
    const fullLogName = `projects/${this.projectId}/logs/${encodeURIComponent(logId)}`;
    const filter = `logName="${fullLogName}" AND timestamp>"${startRfc}"`;

    const out: CollectedRecord[] = [];
    let pageToken: string | undefined;
    let pages = 0;
    do {
      const resp = await client.listEntries({
        filter,
        orderBy: "timestamp asc",
        pageSize: 1000,
        ...(pageToken ? { pageToken } : {}),
      });
      pages++;
      for (const e of resp.entries) {
        const ts = e.timestamp ? Date.parse(e.timestamp) : NaN;
        if (!Number.isFinite(ts)) continue;
        const payload = entryPayloadToString(e);
        if (payload === null) continue;
        const sourceRecordId = e.insertId ?? `${ts}:${shortHash(payload)}`;
        out.push({
          ts,
          sourceRecordId,
          record: {
            tenantId: this.baseOpts.tenantId,
            sourceType: this.sourceType,
            sourceName: logId,
            sourceRecordId,
            observedAt: new Date(ts),
            ingestedAt: new Date(),
            payload,
          },
        });
      }
      pageToken = resp.nextPageToken;
      if (pages >= this.maxPagesPerTick) break;
    } while (pageToken);
    return out;
  }
}
