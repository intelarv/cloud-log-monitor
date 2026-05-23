// M3: Log ingestion source adapters. Cloud-agnostic by interface — the same
// `LogSource` shape covers CloudWatch Logs, GCP Cloud Logging, Azure Monitor,
// on-prem syslog, and dev fixtures. The system never depends on a specific
// cloud's SDK at the type level; concrete adapters are lazy-imported (same
// pattern as cloud-embedders.ts) so a dev install never pulls AWS/GCP/Azure
// SDKs.
//
// Per ARCHITECTURE.md §3:
//   Log Sources (any cloud) -> pulled via LogSource adapters
//   -> Kafka / Redpanda / NATS (topic: raw.logs)
//   -> Detector Pipeline -> findings
//
// Per threat_model "System ↔ Log Sources": log content is attacker-controlled
// wherever any logged input is influenced by an external user. Source-tagged
// provenance is the basis of every downstream trust decision.

export type LogSourceType =
  | "cloudwatch"
  | "cloud_logging"
  | "azure_monitor"
  | "onprem"
  | "fixture";

export interface LogRecord {
  /** Tenant the source belongs to. RLS-scoped at every downstream read. */
  tenantId: string;
  /** Which cloud/system this came from. */
  sourceType: LogSourceType;
  /** Logical source name (log group, project/log name, workspace/log name). */
  sourceName: string;
  /** Source-side record id (CloudWatch event id, GCP insertId, syslog seq). */
  sourceRecordId: string;
  /** Wall-clock time on the source side (untrusted but provenance-relevant). */
  observedAt: Date;
  /** Wall-clock time the API server received it. */
  ingestedAt: Date;
  /** Raw log line / message body. Attacker-controlled — treat as untrusted. */
  payload: string;
}

/** Source adapter contract. `start()` is non-blocking — implementations spin
 *  up timers / brokered consumers and return. `stop()` MUST cancel everything
 *  so tests and graceful shutdown don't leak handles. */
export interface LogSource {
  readonly name: string;
  start(): Promise<void>;
  stop(): Promise<void>;
}

/** Dev fixture source. Does NOT auto-start a timer — explicit `replayOnce()`
 *  injects all fixture records once. Keeping replay explicit avoids polluting
 *  the dev DB on every boot and keeps tests deterministic. */
export class StaticFixtureLogSource implements LogSource {
  readonly name = "fixture";
  constructor(
    private readonly publish: (record: LogRecord) => Promise<void>,
    private readonly records: readonly LogRecord[] = FIXTURE_RECORDS,
  ) {}
  async start(): Promise<void> {
    /* no-op — call replayOnce() to inject. */
  }
  async stop(): Promise<void> {
    /* no-op. */
  }
  /** Publish every fixture record exactly once. Ingest time is stamped fresh
   *  per call so `last_seen_at` advances on each replay. */
  async replayOnce(): Promise<{ published: number }> {
    let n = 0;
    for (const r of this.records) {
      await this.publish({ ...r, ingestedAt: new Date() });
      n++;
    }
    return { published: n };
  }
}

/** Interface stub for real CloudWatch Logs. M3 ships the contract only —
 *  the concrete implementation against `@aws-sdk/client-cloudwatch-logs`
 *  FilterLogEvents (paginated + checkpointed) lands post-M3 along with the
 *  Kafka-backed bus. Construction throws so accidental wiring in dev fails
 *  loudly instead of silently no-op'ing. Mirrors the lazy-load pattern in
 *  cloud-embedders.ts. */
export class CloudwatchLogSourceStub implements LogSource {
  readonly name: string;
  constructor(opts: { tenantId: string; logGroup: string }) {
    this.name = `cloudwatch:${opts.logGroup}`;
    void opts.tenantId;
    throw new Error(
      "CloudwatchLogSourceStub is interface-only in M3. Implement against " +
        "@aws-sdk/client-cloudwatch-logs FilterLogEvents (paginated, " +
        "checkpointed) in a follow-up milestone.",
    );
  }
  async start(): Promise<void> {
    throw new Error("not implemented");
  }
  async stop(): Promise<void> {
    /* no-op. */
  }
}

const TENANT = "default";

/** Synthetic fixture records. Mix of clean / PHI / secrets / multi-class /
 *  duplicate-source-and-class so the ingest path exercises every branch:
 *  classification routing, severity mapping, fingerprint dedupe + occurrence
 *  increment, multi-class fan-out, and the no-hit short-circuit. */
export const FIXTURE_RECORDS: readonly LogRecord[] = Object.freeze([
  {
    tenantId: TENANT,
    sourceType: "cloudwatch",
    sourceName: "app-billing",
    sourceRecordId: "evt-0001",
    observedAt: new Date("2026-05-23T12:00:00Z"),
    ingestedAt: new Date("2026-05-23T12:00:00Z"),
    payload:
      "2026-05-23T12:00:00Z app-billing level=info msg=request_processed tenant=acme order_id=1234",
  },
  {
    tenantId: TENANT,
    sourceType: "cloudwatch",
    sourceName: "app-billing",
    sourceRecordId: "evt-0002",
    observedAt: new Date("2026-05-23T12:01:00Z"),
    ingestedAt: new Date("2026-05-23T12:01:00Z"),
    payload:
      "2026-05-23T12:01:00Z app-billing level=warn msg=lookup_failed applicant_ssn=123-45-6789 status=retry",
  },
  {
    tenantId: TENANT,
    sourceType: "cloudwatch",
    sourceName: "app-billing",
    sourceRecordId: "evt-0003",
    observedAt: new Date("2026-05-23T12:02:00Z"),
    ingestedAt: new Date("2026-05-23T12:02:00Z"),
    payload:
      "2026-05-23T12:02:00Z app-billing level=warn msg=lookup_failed applicant_ssn=987-65-4321 status=retry",
  },
  {
    tenantId: TENANT,
    sourceType: "cloudwatch",
    sourceName: "app-auth",
    sourceRecordId: "evt-0010",
    observedAt: new Date("2026-05-23T12:03:00Z"),
    ingestedAt: new Date("2026-05-23T12:03:00Z"),
    payload:
      "2026-05-23T12:03:00Z app-auth level=error msg=deploy_misconfig AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
  },
  {
    tenantId: TENANT,
    sourceType: "cloud_logging",
    sourceName: "notify-svc",
    sourceRecordId: "ins-0042",
    observedAt: new Date("2026-05-23T12:04:00Z"),
    ingestedAt: new Date("2026-05-23T12:04:00Z"),
    payload:
      "ts=2026-05-23T12:04:00Z notify-svc recipient=jane.doe@example.com template=welcome status=sent",
  },
]);
