// Channel routing config + selection.
//
// Config is read at boot from env. Keep this simple — the hot-reloadable
// DB-driven version is a future-milestone scope item (see Open Questions
// in replit.md M6 entry). The shape here is deliberately the same one
// that a row in a `channel_routes` table would have, so the future move
// to DB-driven config is mechanical.
//
// Routing rule: each enabled adapter has a minimum severity threshold.
// An event is routed to an adapter iff `severityRank(event) >=
// severityRank(adapter.minSeverity)`. There is no per-event-type
// allow/deny inside the router — the alert/non-alert decision lives in
// `alerts.ALERT_RULES` / `NOT_ALERTABLE`, which is also the gate for
// `dispatchAlertFromLedger`. The router is just severity-based fan-out.

import { z } from "zod";
import type { AlertSeverity } from "../alerts";
import { logger } from "../logger";
import { createSlackAdapter } from "./adapters/slack";
import { createWebhookAdapter } from "./adapters/webhook";
import { createPagerDutyAdapter } from "./adapters/pagerduty";
import type { ChannelAdapter } from "./types";

const SEVERITY_RANK: Record<AlertSeverity, number> = {
  warning: 1,
  high: 2,
  critical: 3,
};

export function severityRank(s: AlertSeverity): number {
  return SEVERITY_RANK[s];
}

/** Per-channel config. */
export interface ChannelConfig {
  readonly adapter: ChannelAdapter;
  readonly minSeverity: AlertSeverity;
}

const SeveritySchema = z.enum(["warning", "high", "critical"]);

const SlackEnvSchema = z.object({
  CHANNEL_SLACK_WEBHOOK_URL: z.string().url().optional(),
  CHANNEL_SLACK_MIN_SEVERITY: SeveritySchema.optional(),
});

const WebhookEnvSchema = z.object({
  CHANNEL_WEBHOOK_URL: z.string().url().optional(),
  CHANNEL_WEBHOOK_SECRET: z.string().min(16).optional(),
  CHANNEL_WEBHOOK_ALLOWED_HOSTS: z.string().optional(),
  CHANNEL_WEBHOOK_MIN_SEVERITY: SeveritySchema.optional(),
});

const PagerDutyEnvSchema = z.object({
  CHANNEL_PAGERDUTY_ROUTING_KEY: z.string().min(1).optional(),
  CHANNEL_PAGERDUTY_EVENTS_URL: z.string().url().optional(),
  CHANNEL_PAGERDUTY_MIN_SEVERITY: SeveritySchema.optional(),
});

/** Build the channel configuration from `process.env`. Inert if no
 *  adapter env is set — returns an empty array, which the dispatcher
 *  treats as "log only", same as today's behavior pre-M6. Misconfigs
 *  (e.g. webhook URL without secret) log a warning at boot and skip the
 *  adapter; they DO NOT crash the server. */
export function buildChannelsFromEnv(env: NodeJS.ProcessEnv = process.env): ChannelConfig[] {
  const out: ChannelConfig[] = [];

  const slackParsed = SlackEnvSchema.safeParse(env);
  if (slackParsed.success) {
    const e = slackParsed.data;
    if (e.CHANNEL_SLACK_WEBHOOK_URL) {
      out.push({
        adapter: createSlackAdapter({ webhookUrl: e.CHANNEL_SLACK_WEBHOOK_URL }),
        minSeverity: e.CHANNEL_SLACK_MIN_SEVERITY ?? "warning",
      });
    }
  } else {
    logger.warn({ err: slackParsed.error.message }, "slack channel env invalid; skipping adapter");
  }

  const webhookParsed = WebhookEnvSchema.safeParse(env);
  if (webhookParsed.success) {
    const e = webhookParsed.data;
    if (e.CHANNEL_WEBHOOK_URL) {
      if (!e.CHANNEL_WEBHOOK_SECRET || !e.CHANNEL_WEBHOOK_ALLOWED_HOSTS) {
        logger.warn(
          "CHANNEL_WEBHOOK_URL set without CHANNEL_WEBHOOK_SECRET and CHANNEL_WEBHOOK_ALLOWED_HOSTS; webhook adapter not enabled",
        );
      } else {
        const allowed = e.CHANNEL_WEBHOOK_ALLOWED_HOSTS.split(",")
          .map((h) => h.trim())
          .filter(Boolean);
        try {
          out.push({
            adapter: createWebhookAdapter({
              url: e.CHANNEL_WEBHOOK_URL,
              secret: e.CHANNEL_WEBHOOK_SECRET,
              allowedHosts: allowed,
            }),
            minSeverity: e.CHANNEL_WEBHOOK_MIN_SEVERITY ?? "warning",
          });
        } catch (err) {
          logger.warn(
            { err: err instanceof Error ? err.message : String(err) },
            "webhook adapter construction failed; not enabled",
          );
        }
      }
    }
  } else {
    logger.warn(
      { err: webhookParsed.error.message },
      "webhook channel env invalid; skipping adapter",
    );
  }

  const pagerdutyParsed = PagerDutyEnvSchema.safeParse(env);
  if (pagerdutyParsed.success) {
    const e = pagerdutyParsed.data;
    if (e.CHANNEL_PAGERDUTY_ROUTING_KEY) {
      try {
        out.push({
          adapter: createPagerDutyAdapter({
            routingKey: e.CHANNEL_PAGERDUTY_ROUTING_KEY,
            ...(e.CHANNEL_PAGERDUTY_EVENTS_URL
              ? { eventsUrl: e.CHANNEL_PAGERDUTY_EVENTS_URL }
              : {}),
          }),
          minSeverity: e.CHANNEL_PAGERDUTY_MIN_SEVERITY ?? "warning",
        });
      } catch (err) {
        logger.warn(
          { err: err instanceof Error ? err.message : String(err) },
          "pagerduty adapter construction failed; not enabled",
        );
      }
    }
  } else {
    logger.warn(
      { err: pagerdutyParsed.error.message },
      "pagerduty channel env invalid; skipping adapter",
    );
  }

  return out;
}

/** Select channels that should receive an alert of the given severity. */
export function selectChannels(
  channels: ReadonlyArray<ChannelConfig>,
  sev: AlertSeverity,
): ChannelAdapter[] {
  const rank = severityRank(sev);
  return channels.filter((c) => severityRank(c.minSeverity) <= rank).map((c) => c.adapter);
}
