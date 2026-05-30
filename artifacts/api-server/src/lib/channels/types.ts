// M6 — channel adapter contracts.
//
// `ChannelEnvelope` is the ONLY shape that may cross the application →
// third-party-channel trust boundary (threat_model §"Application ↔ Channel
// Adapters"). It is intentionally an allow-list of metadata fields: no
// payload bodies, no actor identifiers beyond a stable pseudonymous id,
// no detector strings. Anything more sensitive lives in the ledger row
// pointed to by `ledgerSeq` and stays inside the BAA boundary.
//
// Adapters MUST treat the envelope as their entire universe — they may
// not reach out to fetch finding content, raw payloads, or anything else
// over this seam. The `dispatch.ts` module enforces this by being the
// only constructor of envelopes.

import type { AlertSeverity } from "../alerts";

export interface ChannelEnvelope {
  /** Mirrors `AlertSeverity` from `alerts.ts`. */
  readonly severity: AlertSeverity;
  /** Stable, allow-listed ledger event-type literal — used by receivers
   *  for routing. Value is one of the keys of `ALERT_RULES`. */
  readonly eventType: string;
  /** Tenant scope. `null` only for tenant-less control-plane events
   *  (e.g. some boot-time integrity events). */
  readonly tenantId: string | null;
  /** Append-only ledger row pointer — lets a receiver fetch full
   *  context out-of-band via the dashboard if they have access. */
  readonly ledgerSeq: number;
  /** Short hash for correlation in cross-system traces. */
  readonly ledgerHashShort: string;
  /** Subject TYPE only (small enum: ledger / ingest / finding / etc),
   *  never a content string. */
  readonly subjectType: string | null;
  /** Subject ID only (opaque identifier), never a content string. */
  readonly subjectId: string | null;
  /** ISO-8601 timestamp at which the ledger row was committed. */
  readonly occurredAt: string;
}

export interface DispatchResult {
  readonly channel: string;
  readonly ok: boolean;
  readonly statusCode?: number;
  readonly err?: string;
  readonly durationMs: number;
}

export interface ChannelAdapter {
  /** Stable channel name used in config + ledger payloads + log lines. */
  readonly name: string;
  /** Adapter sends the envelope to its destination. MUST NOT throw —
   *  network errors / non-2xx responses are returned in `DispatchResult`
   *  so the `dispatch.ts` orchestrator can ledger them uniformly. MUST
   *  enforce a hard timeout. */
  send(env: ChannelEnvelope): Promise<DispatchResult>;
}
