// Slack incoming-webhook adapter.
//
// Uses the legacy "incoming webhook" surface intentionally — the URL is
// itself the secret (rotates per channel), the receiver is Slack-side,
// and there's no PHI in the body because envelopes are allow-listed
// metadata only (see types.ts and dispatch.ts PHI hard gate).
//
// Not Slack-app OAuth: we'd need a bot token, scopes, and storage of
// per-tenant credentials. For an alert pipeline this is over-scope; the
// webhook URL model is what every monitoring system uses for the same
// reason.
//
// Production BAA note: Slack offers a HIPAA-aligned tier (Enterprise
// Grid + signed BAA). Even with BAA, the allow-list rule on envelope
// fields stands — no PHI in any notification body per threat_model
// §Information Disclosure ("PHI MUST NOT appear in ... notification
// channel payloads").

import type { ChannelAdapter, ChannelEnvelope, DispatchResult } from "../types";

export interface SlackAdapterOpts {
  readonly webhookUrl: string;
  readonly timeoutMs?: number;
}

export function createSlackAdapter(opts: SlackAdapterOpts): ChannelAdapter {
  const timeoutMs = opts.timeoutMs ?? 5000;
  return {
    name: "slack",
    async send(env: ChannelEnvelope): Promise<DispatchResult> {
      const started = Date.now();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const body = {
          text:
            `[${env.severity.toUpperCase()}] ${env.eventType}` +
            ` — ledger seq=${env.ledgerSeq}` +
            (env.subjectId ? ` subject=${env.subjectType ?? "?"}:${env.subjectId}` : "") +
            (env.tenantId ? ` tenant=${env.tenantId}` : ""),
        };
        const res = await fetch(opts.webhookUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body),
          signal: ctrl.signal,
        });
        return {
          channel: "slack",
          ok: res.ok,
          statusCode: res.status,
          durationMs: Date.now() - started,
          ...(res.ok ? {} : { err: `slack returned status ${res.status}` }),
        };
      } catch (err) {
        return {
          channel: "slack",
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
