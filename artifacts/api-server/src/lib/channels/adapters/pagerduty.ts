// PagerDuty Events API v2 adapter.
//
// Pages the on-call rotation directly instead of relying on someone
// watching a Slack channel — threat_model §Tampering requires integrity
// failures to "page on-call within 5 minutes", and the alerting design
// references PagerDuty. The Events API v2 `enqueue` surface takes a
// `routing_key` (the integration key) which is itself the secret, so no
// host allow-list or HMAC is needed here (cf. the Slack adapter, whose
// webhook URL is the secret). `redirect: "error"` still blocks
// redirect-based SSRF on the (operator-configured, official-by-default)
// events endpoint.
//
// PHI: the envelope (types.ts) is an allow-list of metadata only — no
// payload bodies, no detector strings — so nothing PHI-bearing can cross
// this boundary. The same allow-list rule as every other channel adapter
// (threat_model §Information Disclosure) stands even though PagerDuty is
// not a BAA-covered destination.
//
// Dedup: PagerDuty collapses triggers sharing a `dedup_key` into one
// incident. We key on tenant + event type + subject so a flapping
// integrity check (e.g. chain-invalid re-firing every walk) raises ONE
// incident instead of one per occurrence — the per-channel rate limit in
// dispatch.ts is the first line of defense; dedup is the second.

import type { AlertSeverity } from "../../alerts";
import type { ChannelAdapter, ChannelEnvelope, DispatchResult } from "../types";

export const PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue";

/** Map our internal severity onto PagerDuty's Events API v2 severity
 *  enum (`critical | error | warning | info`). `high` has no direct
 *  PagerDuty equivalent, so it maps to `error`. */
export function toPagerDutySeverity(s: AlertSeverity): "critical" | "error" | "warning" {
  switch (s) {
    case "critical":
      return "critical";
    case "high":
      return "error";
    case "warning":
      return "warning";
  }
}

/** Stable dedup key for an envelope. PagerDuty groups triggers sharing
 *  this key into a single incident until it is resolved. */
export function pagerDutyDedupKey(env: ChannelEnvelope): string {
  const tenant = env.tenantId ?? "global";
  const subject = env.subjectId ?? `seq:${env.ledgerSeq}`;
  const subjectType = env.subjectType ?? "none";
  return `phi-audit/${tenant}/${env.eventType}/${subjectType}/${subject}`;
}

export interface PagerDutyAdapterOpts {
  readonly routingKey: string;
  readonly eventsUrl?: string;
  readonly timeoutMs?: number;
}

export function createPagerDutyAdapter(opts: PagerDutyAdapterOpts): ChannelAdapter {
  const timeoutMs = opts.timeoutMs ?? 5000;
  const eventsUrl = opts.eventsUrl ?? PAGERDUTY_EVENTS_URL;
  if (!opts.routingKey) {
    throw new Error("pagerduty adapter: routingKey is required");
  }
  // Resolve once at construction so a malformed override fails loudly at
  // boot, not at first page.
  new URL(eventsUrl);

  return {
    name: "pagerduty",
    async send(env: ChannelEnvelope): Promise<DispatchResult> {
      const started = Date.now();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const summary =
          `[${env.severity.toUpperCase()}] ${env.eventType}` +
          ` — ledger seq=${env.ledgerSeq}` +
          (env.subjectId ? ` subject=${env.subjectType ?? "?"}:${env.subjectId}` : "") +
          (env.tenantId ? ` tenant=${env.tenantId}` : "");
        const body = {
          routing_key: opts.routingKey,
          event_action: "trigger" as const,
          dedup_key: pagerDutyDedupKey(env),
          payload: {
            // PagerDuty caps `summary` at 1024 chars.
            summary: summary.slice(0, 1024),
            source: "phi-audit",
            severity: toPagerDutySeverity(env.severity),
            timestamp: env.occurredAt,
            component: "audit-ledger",
            group: env.tenantId ?? "global",
            class: env.eventType,
            // Allow-listed metadata only — no payload bodies, no detector
            // strings. Mirrors the envelope, which is the PHI hard gate.
            custom_details: {
              ledger_seq: env.ledgerSeq,
              ledger_hash_short: env.ledgerHashShort,
              subject_type: env.subjectType,
              subject_id: env.subjectId,
            },
          },
        };
        const res = await fetch(eventsUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: ctrl.signal,
          redirect: "error",
        });
        return {
          channel: "pagerduty",
          ok: res.ok,
          statusCode: res.status,
          durationMs: Date.now() - started,
          ...(res.ok ? {} : { err: `pagerduty returned status ${res.status}` }),
        };
      } catch (err) {
        return {
          channel: "pagerduty",
          ok: false,
          err: err instanceof Error ? err.message : String(err),
          durationMs: Date.now() - started,
        };
      } finally {
        clearTimeout(t);
      }
    },
  };
}
