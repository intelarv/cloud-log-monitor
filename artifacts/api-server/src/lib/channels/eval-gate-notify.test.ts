import { describe, expect, it } from "vitest";
// The nightly eval-gate notifier is pure ESM (it must be runnable by `node`
// directly from the shell entrypoint, with no TS runner). We import it here to
// lock its webhook signing scheme to the app's adapter and to cover its config
// parsing / severity gating / inert-when-unconfigured behavior.
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildRecoverySlackMessage,
  buildRecoveryText,
  buildSlackMessage,
  buildSummaryText,
  classifyOutcome,
  computeTrends,
  countRecentRecoveries,
  defaultHeartbeatDedupKey,
  defaultPagerDutyDedupKey,
  detectRecovery,
  extractScores,
  failingStreakStart,
  failingSuites,
  fmtDuration,
  fmtTrend,
  historyLimit,
  isRecoveryFlapping,
  loadHistory,
  notifyEvalGate,
  parseChannels,
  parseNotifyOn,
  postToChannels,
  previousRun,
  previousScores,
  recordRunHistory,
  recoveryMuteConfig,
  recoveryNotifyEnabled,
  resolveHeartbeat,
  selectForSeverity,
  shouldNotify,
  signWebhookBody as notifySignWebhookBody,
} from "../../../evals/notify.mjs";
import { signWebhookBody as adapterSignWebhookBody } from "./adapters/webhook";
import { toPagerDutySeverity } from "./adapters/pagerduty";

const WEBHOOK_SECRET = "an-eval-gate-webhook-secret-key";

interface FetchCall {
  url: string;
  init: RequestInit;
}

function makeFetch(ok = true, status = 200) {
  const calls: FetchCall[] = [];
  const fetchImpl = async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return { ok, status } as Response;
  };
  return { fetchImpl, calls };
}

const FAIL_SUMMARY = {
  ok: false,
  failures: ["detector-phi: 70.0% (baseline 90.0%, -20.0pt) [FAIL]"],
  warnings: [],
  suites: {
    "detector-phi": { score: 0.7, baseline: 0.9, deltaPt: -20, status: "FAIL" },
    "agent-agreement": { score: 0.4, floor: 0.5, status: "BELOW_FLOOR" },
  },
  floor: { active: true, value: 0.5 },
};

describe("eval-gate notifier", () => {
  it("webhook signature scheme matches the app adapter byte-for-byte", () => {
    const ts = 1_717_000_000;
    const body = JSON.stringify({ kind: "eval_gate_failure", ok: false });
    expect(notifySignWebhookBody(WEBHOOK_SECRET, ts, body)).toBe(
      adapterSignWebhookBody(WEBHOOK_SECRET, ts, body),
    );
  });

  it("is inert when no channel is configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: {},
      summary: FAIL_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("posts a concise summary to Slack with scores + which check tripped", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      summary: FAIL_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
      exitCode: 1,
    });
    expect(res.skipped).toBe(false);
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0]!.init.body as string);
    // The plain-text fallback is retained (push notifications / clients without
    // Block Kit show this).
    expect(body.text).toContain("nightly AI eval gate FAILED");
    expect(body.text).toContain("detector-phi");
    expect(body.text).toContain("FAIL");
    expect(body.text).toContain("gate exit code: 1");
    // Rich Block Kit attachment with a severity-colored bar + one-word headline.
    expect(body.attachments).toHaveLength(1);
    expect(body.attachments[0].color).toBe("#d7263d");
    const headerBlock = body.attachments[0].blocks.find((b: any) => b.type === "header");
    expect(headerBlock.text.text).toContain("FAILED");
  });

  it("builds a Slack Block Kit message with a colored bar + scannable headline per outcome", () => {
    const findHeaderText = (msg: ReturnType<typeof buildSlackMessage>): string => {
      const header = (msg.attachments[0]!.blocks as any[]).find((b) => b.type === "header");
      return header.text.text as string;
    };

    const failMsg = buildSlackMessage(FAIL_SUMMARY, { exitCode: 1 });
    expect(failMsg.attachments[0]!.color).toBe("#d7263d");
    expect(findHeaderText(failMsg)).toContain("FAILED");
    // Dense detail is tucked into code blocks so it stays scannable.
    const failText = JSON.stringify(failMsg.attachments[0]!.blocks);
    expect(failText).toContain("suite scores");
    expect(failText).toContain("detector-phi");
    expect(failText).toContain("gate exit code: 1");

    const warnMsg = buildSlackMessage(WARN_SUMMARY, {});
    expect(warnMsg.attachments[0]!.color).toBe("#f5a623");
    expect(findHeaderText(warnMsg)).toContain("WARNINGS");

    const cleanMsg = buildSlackMessage(CLEAN_SUMMARY, {});
    expect(cleanMsg.attachments[0]!.color).toBe("#2eb886");
    expect(findHeaderText(cleanMsg)).toContain("PASSED");
    // Fallback text is always present for non-Block-Kit clients.
    expect(typeof cleanMsg.text).toBe("string");
    expect(cleanMsg.text.length).toBeGreaterThan(0);
  });

  it("posts an HMAC-signed body to the generic webhook that the adapter verifier accepts", async () => {
    const { fetchImpl, calls } = makeFetch();
    await notifyEvalGate({
      env: {
        CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
        CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
        CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
      },
      summary: FAIL_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    const { init } = calls[0]!;
    const headers = init.headers as Record<string, string>;
    const sigHeader = headers["x-phi-audit-signature"]!;
    const ts = Number(headers["x-phi-audit-timestamp"]);
    const body = init.body as string;
    const expected = `sha256=${adapterSignWebhookBody(WEBHOOK_SECRET, ts, body)}`;
    expect(sigHeader).toBe(expected);
    const payload = JSON.parse(body);
    expect(payload.kind).toBe("eval_gate_failure");
    expect(payload.severity).toBe("high");
  });

  it("posts a PagerDuty Events API v2 trigger with mapped severity + dedup key", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    const res = await notifyEvalGate({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      summary: FAIL_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(false);
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://events.pagerduty.com/v2/enqueue");
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.routing_key).toBe("R0UT1NGK3Y0000000000000000000000");
    expect(event.event_action).toBe("trigger");
    // EVAL_GATE_SEVERITY is "high" → PagerDuty "error".
    expect(event.payload.severity).toBe("error");
    expect(event.payload.severity).toBe(toPagerDutySeverity("high"));
    expect(event.payload.summary).toContain("nightly AI eval gate FAILED");
    // Default dedup key is a single STABLE key (no date) so re-runs fold into
    // one incident AND a later passing night can resolve this same incident.
    expect(event.dedup_key).toBe(defaultPagerDutyDedupKey());
    expect(event.dedup_key).toBe("eval-gate-nightly");
  });

  it("default dedup key is stable (date-independent) so cross-night recovery clears yesterday's page", () => {
    // The core of the cross-night-recovery fix: a fail on night N and the
    // resolve on a passing night N+1 MUST share one dedup_key, or the resolve
    // targets a different incident than the one the failure opened. A per-day
    // key (`eval-gate-nightly/<date>`) would change between nights; assert the
    // key carries no date component so it can never regress to that.
    const key = defaultPagerDutyDedupKey();
    expect(key).toBe("eval-gate-nightly");
    // No YYYY-MM-DD anywhere in the key.
    expect(key).not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  it("a fail then a pass on a later night share one dedup_key (trigger + resolve clear the same incident)", async () => {
    // Night N: failing run opens the incident.
    const failFetch = makeFetch(true, 202);
    await notifyEvalGate({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      summary: FAIL_SUMMARY,
      fetchImpl: failFetch.fetchImpl as unknown as typeof fetch,
    });
    const triggerEvent = JSON.parse(failFetch.calls[0]!.init.body as string);
    expect(triggerEvent.event_action).toBe("trigger");

    // Night N+1: passing run sends a resolve. With a stable default key it
    // targets the exact dedup_key the prior failure opened.
    const passFetch = makeFetch(true, 202);
    await notifyEvalGate({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      summary: CLEAN_SUMMARY,
      fetchImpl: passFetch.fetchImpl as unknown as typeof fetch,
    });
    const resolveEvent = JSON.parse(passFetch.calls[0]!.init.body as string);
    expect(resolveEvent.event_action).toBe("resolve");
    expect(resolveEvent.dedup_key).toBe(triggerEvent.dedup_key);
  });

  it("sends a PagerDuty resolve on a passing run even under the default fail-only trigger", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    const res = await notifyEvalGate({
      // No EVAL_NOTIFY_ON → fail-only: a clean run posts nothing, but the
      // resolve must still fire to clear any incident a prior fail opened.
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(false);
    expect(calls).toHaveLength(1);
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("resolve");
    expect(event.routing_key).toBe("R0UT1NGK3Y0000000000000000000000");
    // Resolve uses the SAME dedup_key the failing run would have used.
    expect(event.dedup_key).toBe(defaultPagerDutyDedupKey());
    // A resolve carries no payload (routing key + dedup key + action only).
    expect(event.payload).toBeUndefined();
    const resolveResult = res.sent.find((s) => s.channel === "pagerduty");
    expect(resolveResult?.action).toBe("resolve");
  });

  it("resolves with the explicit CHANNEL_PAGERDUTY_DEDUP_KEY so the right incident clears", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    await notifyEvalGate({
      env: {
        CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
        CHANNEL_PAGERDUTY_DEDUP_KEY: "run-2026-05-31-abc",
        CHANNEL_PAGERDUTY_EVENTS_URL: "https://events.eu.pagerduty.com/v2/enqueue",
      },
      summary: WARN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://events.eu.pagerduty.com/v2/enqueue");
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("resolve");
    expect(event.dedup_key).toBe("run-2026-05-31-abc");
  });

  it("does not send a PagerDuty trigger for a passing run under EVAL_NOTIFY_ON=always", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    await notifyEvalGate({
      // 'always' would post a warning-severity confirmation to Slack/webhook,
      // but PagerDuty must only ever see a resolve for a green run — never a
      // trigger that re-opens the incident we just cleared.
      env: {
        EVAL_NOTIFY_ON: "always",
        CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
      },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("resolve");
  });

  it("on a passing run, resolves PagerDuty but leaves Slack untouched under the default trigger", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    await notifyEvalGate({
      // fail-only default: Slack posts nothing on a clean run, but PagerDuty
      // still gets its recovery resolve. Slack has no resolve concept.
      env: {
        CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
      },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://events.pagerduty.com/v2/enqueue");
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("resolve");
  });

  it("is inert (no resolve) on a passing run when PagerDuty is not configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    // fail-only default + no PagerDuty → nothing sent at all.
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("honors an explicit CHANNEL_PAGERDUTY_DEDUP_KEY and custom events URL", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    await notifyEvalGate({
      env: {
        CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
        CHANNEL_PAGERDUTY_DEDUP_KEY: "run-2026-05-31-abc",
        CHANNEL_PAGERDUTY_EVENTS_URL: "https://events.eu.pagerduty.com/v2/enqueue",
      },
      summary: FAIL_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://events.eu.pagerduty.com/v2/enqueue");
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.dedup_key).toBe("run-2026-05-31-abc");
  });

  it("heartbeat default dedup key is stable (date-independent) and distinct from the run key", () => {
    // The core of the heartbeat cross-night recovery fix: the staleness trigger
    // and the recovery resolve MUST share one dedup_key, so the key must carry
    // no date component (a per-day key would change if an outage straddled UTC
    // midnight, orphaning the open page). It is also distinct from the run key
    // so a quiet job and a failing suite are separate incidents.
    const key = defaultHeartbeatDedupKey();
    expect(key).toBe("eval-gate-heartbeat");
    expect(key).not.toMatch(/\d{4}-\d{2}-\d{2}/);
    expect(key).not.toBe(defaultPagerDutyDedupKey());
  });

  it("heartbeat staleness trigger uses the stable dedup key (no per-day component)", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    const res = await postToChannels({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      severity: "high",
      text: "[ALERT high] eval-gate.heartbeat_missing — gate went quiet",
      payload: { kind: "eval_gate_heartbeat_missing", severity: "high" },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(false);
    expect(calls).toHaveLength(1);
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("trigger");
    expect(event.dedup_key).toBe(defaultHeartbeatDedupKey());
    expect(event.dedup_key).not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  it("a heartbeat stale trigger then a healthy resolve clear the same incident", async () => {
    // Outage: a stale check opens the "went quiet" page.
    const staleFetch = makeFetch(true, 202);
    await postToChannels({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      severity: "high",
      text: "[ALERT high] eval-gate.heartbeat_missing",
      payload: { kind: "eval_gate_heartbeat_missing" },
      fetchImpl: staleFetch.fetchImpl as unknown as typeof fetch,
    });
    const triggerEvent = JSON.parse(staleFetch.calls[0]!.init.body as string);
    expect(triggerEvent.event_action).toBe("trigger");

    // Recovery: a healthy check resolves the exact same dedup_key.
    const healthyFetch = makeFetch(true, 202);
    const res = await resolveHeartbeat({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      fetchImpl: healthyFetch.fetchImpl as unknown as typeof fetch,
    });
    expect(healthyFetch.calls).toHaveLength(1);
    const resolveEvent = JSON.parse(healthyFetch.calls[0]!.init.body as string);
    expect(resolveEvent.event_action).toBe("resolve");
    expect(resolveEvent.dedup_key).toBe(triggerEvent.dedup_key);
    // A resolve carries no payload (routing key + dedup key + action only).
    expect(resolveEvent.payload).toBeUndefined();
    expect(res.sent.find((s) => s.channel === "pagerduty")?.action).toBe("resolve");
  });

  it("heartbeat resolve honors an explicit CHANNEL_PAGERDUTY_DEDUP_KEY", async () => {
    const { fetchImpl, calls } = makeFetch(true, 202);
    await resolveHeartbeat({
      env: {
        CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
        CHANNEL_PAGERDUTY_DEDUP_KEY: "heartbeat-prod-01",
        CHANNEL_PAGERDUTY_EVENTS_URL: "https://events.eu.pagerduty.com/v2/enqueue",
      },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://events.eu.pagerduty.com/v2/enqueue");
    const event = JSON.parse(calls[0]!.init.body as string);
    expect(event.event_action).toBe("resolve");
    expect(event.dedup_key).toBe("heartbeat-prod-01");
  });

  it("heartbeat resolve targets PagerDuty only and is inert without it", async () => {
    // Slack/webhook have no resolve concept, so a healthy check must not post to
    // them — and with no PagerDuty configured the resolve is a no-op.
    const slackOnly = makeFetch();
    const slackRes = await resolveHeartbeat({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      fetchImpl: slackOnly.fetchImpl as unknown as typeof fetch,
    });
    expect(slackOnly.calls).toHaveLength(0);
    expect(slackRes.sent).toHaveLength(0);

    const none = makeFetch();
    const noneRes = await resolveHeartbeat({
      env: {},
      fetchImpl: none.fetchImpl as unknown as typeof fetch,
    });
    expect(none.calls).toHaveLength(0);
    expect(noneRes.sent).toHaveLength(0);
  });

  it("applies severity gating to PagerDuty: a critical-only routing key skips the high alert", () => {
    const channels = parseChannels({
      CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
      CHANNEL_PAGERDUTY_MIN_SEVERITY: "critical",
    });
    expect(channels).toHaveLength(1);
    expect(selectForSeverity(channels)).toHaveLength(0);
  });

  it("does not enable PagerDuty when the events URL override is invalid", () => {
    const channels = parseChannels({
      CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
      CHANNEL_PAGERDUTY_EVENTS_URL: "not-a-url",
    });
    expect(channels).toHaveLength(0);
  });

  it("does not enable a webhook whose host is outside the allow-list", () => {
    const channels = parseChannels({
      CHANNEL_WEBHOOK_URL: "https://evil.example.net/hook",
      CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
      CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
    });
    expect(channels).toHaveLength(0);
  });

  it("does not enable a webhook configured without a secret", () => {
    const channels = parseChannels({
      CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
      CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
    });
    expect(channels).toHaveLength(0);
  });

  it("applies severity gating: a critical-only channel does not receive the high-severity gate alert", () => {
    const channels = parseChannels({
      CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
      CHANNEL_SLACK_MIN_SEVERITY: "critical",
    });
    expect(channels).toHaveLength(1);
    expect(selectForSeverity(channels)).toHaveLength(0);
  });

  it("includes an execution-failure cause line when the gate never ran", () => {
    const text = buildSummaryText({
      ok: false,
      executionFailure: true,
      failures: ["eval run failed before the regression gate (live-suite execution failure)"],
      suites: { "detector-phi": { score: 0.9, status: "ran" } },
      floor: { active: false, value: null },
    });
    expect(text).toContain("live-suite execution failure");
    expect(text).toContain("detector-phi");
  });

  const WARN_SUMMARY = {
    ok: true,
    failures: [],
    warnings: ["agent-agreement: 80.0% (no baseline — run --update to adopt)"],
    suites: { "agent-agreement": { score: 0.8, status: "no-baseline" } },
    floor: { active: false, value: null },
  };
  const CLEAN_SUMMARY = {
    ok: true,
    failures: [],
    warnings: [],
    suites: { "detector-phi": { score: 0.99, baseline: 0.99, deltaPt: 0, status: "ok" } },
    floor: { active: false, value: null },
  };

  it("classifies run outcomes from the gate verdict", () => {
    expect(classifyOutcome(FAIL_SUMMARY)).toBe("failed");
    expect(classifyOutcome(WARN_SUMMARY)).toBe("warned");
    expect(classifyOutcome(CLEAN_SUMMARY)).toBe("clean");
  });

  it("parses EVAL_NOTIFY_ON and falls back to fail on an unknown value", () => {
    expect(parseNotifyOn({})).toBe("fail");
    expect(parseNotifyOn({ EVAL_NOTIFY_ON: "WARN" })).toBe("warn");
    expect(parseNotifyOn({ EVAL_NOTIFY_ON: "always" })).toBe("always");
    expect(parseNotifyOn({ EVAL_NOTIFY_ON: "bogus" })).toBe("fail");
  });

  it("gates outcomes by trigger level", () => {
    expect(shouldNotify("fail", "failed")).toBe(true);
    expect(shouldNotify("fail", "warned")).toBe(false);
    expect(shouldNotify("fail", "clean")).toBe(false);
    expect(shouldNotify("warn", "warned")).toBe(true);
    expect(shouldNotify("warn", "clean")).toBe(false);
    expect(shouldNotify("always", "clean")).toBe(true);
  });

  it("does not post a passing run under the default fail-only trigger", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("posts a warning-severity heads-up for a passing-with-warnings run under EVAL_NOTIFY_ON=warn", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: {
        EVAL_NOTIFY_ON: "warn",
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
      },
      summary: WARN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(false);
    expect(res.severity).toBe("warning");
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.text).toContain("[ALERT warning]");
    expect(body.text).toContain("PASSED with warnings");
    expect(body.text).toContain("agent-agreement");
  });

  it("posts an all-green confirmation under EVAL_NOTIFY_ON=always", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: {
        EVAL_NOTIFY_ON: "always",
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
      },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(false);
    expect(res.severity).toBe("warning");
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.text).toContain("all suites green");
  });

  it("still gates a warning-severity confirmation by per-channel min-severity", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyEvalGate({
      env: {
        EVAL_NOTIFY_ON: "always",
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
        CHANNEL_SLACK_MIN_SEVERITY: "high",
      },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("tags the webhook payload kind + severity by outcome", async () => {
    const { fetchImpl, calls } = makeFetch();
    await notifyEvalGate({
      env: {
        EVAL_NOTIFY_ON: "always",
        CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
        CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
        CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
      },
      summary: CLEAN_SUMMARY,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const payload = JSON.parse(calls[0]!.init.body as string);
    expect(payload.kind).toBe("eval_gate_ok");
    expect(payload.severity).toBe("warning");
    expect(payload.outcome).toBe("clean");
    expect(payload.ok).toBe(true);
  });

  describe("score-history trend indicator", () => {
    const PREV = [
      { ts: "2026-05-29T00:00:00.000Z", ok: true, outcome: "clean", scores: { "detector-phi": 0.9, "agent-agreement": 0.6 } },
    ] as const;

    it("computes per-suite direction + delta vs. the previous run", () => {
      const trends = computeTrends(
        {
          "detector-phi": { score: 0.7, baseline: 0.9, status: "FAIL" },
          "agent-agreement": { score: 0.6, floor: 0.5, status: "floor-ok" },
          "new-suite": { score: 0.95, status: "no-baseline" },
        },
        previousScores(PREV as unknown as Parameters<typeof previousScores>[0]),
      );
      expect(trends["detector-phi"]).toEqual({ direction: "down", deltaPt: -20, prev: 0.9 });
      expect(trends["agent-agreement"]).toEqual({ direction: "flat", deltaPt: 0, prev: 0.6 });
      expect(trends["new-suite"]).toEqual({ direction: "new", deltaPt: 0, prev: null });
    });

    it("treats every suite as new when there is no history", () => {
      const trends = computeTrends({ "detector-phi": { score: 0.9, status: "ok" } }, previousScores([]));
      expect(trends["detector-phi"]!.direction).toBe("new");
    });

    it("renders compact trend suffixes", () => {
      expect(fmtTrend({ direction: "down", deltaPt: -1.2, prev: 1 })).toBe(" ▼ -1.2pt");
      expect(fmtTrend({ direction: "up", deltaPt: 0.5, prev: 1 })).toBe(" ▲ +0.5pt");
      expect(fmtTrend({ direction: "flat", deltaPt: 0, prev: 1 })).toBe(" ▬ ±0.0pt");
      expect(fmtTrend({ direction: "new", deltaPt: 0, prev: null })).toBe(" (new)");
      expect(fmtTrend(undefined)).toBe("");
    });

    it("shows the trend in the plain-text fallback and Slack score block", () => {
      const trends = computeTrends(
        FAIL_SUMMARY.suites,
        previousScores(PREV as unknown as Parameters<typeof previousScores>[0]),
      );
      const text = buildSummaryText(FAIL_SUMMARY, { trends });
      expect(text).toContain("vs previous run");
      expect(text).toContain("▼ -20.0pt");

      const slack = buildSlackMessage(FAIL_SUMMARY, { trends });
      const blockText = JSON.stringify(slack.attachments[0]!.blocks);
      expect(blockText).toContain("▲▼▬ vs previous run");
      expect(blockText).toContain("▼ -20.0pt");
    });

    it("posts the trend computed from injected history to the webhook payload", async () => {
      const { fetchImpl, calls } = makeFetch();
      await notifyEvalGate({
        env: {
          CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
          CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
          CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
        },
        summary: FAIL_SUMMARY,
        history: [...PREV] as Parameters<typeof previousScores>[0],
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      const payload = JSON.parse(calls[0]!.init.body as string);
      expect(payload.trends["detector-phi"]).toEqual({ direction: "down", deltaPt: -20, prev: 0.9 });
    });

    it("extractScores keeps only suites with a numeric score", () => {
      expect(
        extractScores({
          ok: false,
          suites: {
            scored: { score: 0.8, status: "ok" },
            missing: { baseline: 0.9, status: "missing" },
          },
        }),
      ).toEqual({ scored: 0.8 });
    });

    it("appends a run to history, caps at the limit, and round-trips via loadHistory", () => {
      const dir = mkdtempSync(join(tmpdir(), "eval-history-"));
      try {
        // Seed two runs, then append a third with a cap of 2 → oldest dropped.
        writeFileSync(
          join(dir, "score-history.json"),
          JSON.stringify({
            version: 1,
            runs: [
              { ts: "2026-05-28T00:00:00.000Z", ok: true, outcome: "clean", scores: { "detector-phi": 0.95 } },
              { ts: "2026-05-29T00:00:00.000Z", ok: true, outcome: "clean", scores: { "detector-phi": 0.9 } },
            ],
          }),
        );
        const now = new Date("2026-05-30T00:00:00.000Z");
        const result = recordRunHistory({
          evalsDir: dir,
          summary: { ok: true, suites: { "detector-phi": { score: 0.92, status: "ok" } } },
          maxEntries: 2,
          now,
        });
        expect(result).toHaveLength(2);
        expect(result[0]!.ts).toBe("2026-05-29T00:00:00.000Z");
        expect(result[1]!.scores["detector-phi"]).toBe(0.92);

        const reloaded = loadHistory(dir);
        expect(reloaded).toHaveLength(2);
        expect(previousScores(reloaded)).toEqual({ "detector-phi": 0.92 });

        const onDisk = JSON.parse(readFileSync(join(dir, "score-history.json"), "utf8"));
        expect(onDisk.version).toBe(1);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("does not record a run that produced no suite scores", () => {
      const dir = mkdtempSync(join(tmpdir(), "eval-history-"));
      try {
        const result = recordRunHistory({
          evalsDir: dir,
          summary: { ok: false, executionFailure: true, suites: {} },
        });
        expect(result).toEqual([]);
        expect(loadHistory(dir)).toEqual([]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    it("resolves EVAL_HISTORY_LIMIT with a safe default", () => {
      expect(historyLimit({})).toBe(30);
      expect(historyLimit({ EVAL_HISTORY_LIMIT: "10" })).toBe(10);
      expect(historyLimit({ EVAL_HISTORY_LIMIT: "0" })).toBe(30);
      expect(historyLimit({ EVAL_HISTORY_LIMIT: "nope" })).toBe(30);
    });
  });

  describe("recovery note (fail → pass)", () => {
    type Hist = Parameters<typeof previousRun>[0];
    type Run = Hist extends Array<infer T> ? T : never;
    const FAILED_RUN: Run = {
      ts: "2026-05-29T00:00:00.000Z",
      ok: false,
      outcome: "failed",
      failed: ["agent-agreement", "detector-phi"],
      scores: { "detector-phi": 0.7, "agent-agreement": 0.4 },
    };
    const PASSED_RUN: Run = {
      ts: "2026-05-29T00:00:00.000Z",
      ok: true,
      outcome: "clean",
      failed: [],
      scores: { "detector-phi": 0.99 },
    };

    it("records which suites were failing so the next run can name them", () => {
      expect(failingSuites(FAIL_SUMMARY)).toEqual(["agent-agreement", "detector-phi"]);
      expect(failingSuites(CLEAN_SUMMARY)).toEqual([]);
    });

    it("detects a recovery and names the suites that came back green", () => {
      const recovered = detectRecovery(
        "clean",
        { "detector-phi": { score: 0.99, status: "ok" }, "agent-agreement": { score: 0.6, status: "floor-ok" } },
        FAILED_RUN,
      );
      expect(recovered).toEqual(["agent-agreement", "detector-phi"]);
    });

    it("is not a recovery when the prior run also passed", () => {
      expect(detectRecovery("clean", CLEAN_SUMMARY.suites, PASSED_RUN)).toBeNull();
    });

    it("is not a recovery when there is no prior run or the current run failed", () => {
      expect(detectRecovery("clean", CLEAN_SUMMARY.suites, null)).toBeNull();
      expect(detectRecovery("failed", FAIL_SUMMARY.suites, FAILED_RUN)).toBeNull();
    });

    it("falls back to naming current green suites when the prior record lacks failure detail", () => {
      const legacy = { ts: "x", ok: false, outcome: "failed", scores: { "detector-phi": 0.7 } };
      const recovered = detectRecovery(
        "clean",
        { "detector-phi": { score: 0.99, status: "ok" } },
        legacy as unknown as Run,
      );
      expect(recovered).toEqual(["detector-phi"]);
    });

    it("parses the EVAL_NOTIFY_RECOVERY opt-out flag (default on)", () => {
      expect(recoveryNotifyEnabled({})).toBe(true);
      expect(recoveryNotifyEnabled({ EVAL_NOTIFY_RECOVERY: "on" })).toBe(true);
      expect(recoveryNotifyEnabled({ EVAL_NOTIFY_RECOVERY: "off" })).toBe(false);
      expect(recoveryNotifyEnabled({ EVAL_NOTIFY_RECOVERY: "false" })).toBe(false);
      expect(recoveryNotifyEnabled({ EVAL_NOTIFY_RECOVERY: "0" })).toBe(false);
      expect(recoveryNotifyEnabled({ EVAL_NOTIFY_RECOVERY: "no" })).toBe(false);
    });

    it("builds a concise recovery note naming the recovered suites", () => {
      const text = buildRecoveryText(CLEAN_SUMMARY, ["detector-phi", "agent-agreement"]);
      expect(text).toContain("RECOVERED");
      expect(text).toContain("GREEN again");
      expect(text).toContain("detector-phi");
      expect(text).toContain("agent-agreement");

      const slack = buildRecoverySlackMessage(CLEAN_SUMMARY, ["detector-phi"]);
      expect(slack.attachments[0]!.color).toBe("#2eb886");
      const header = (slack.attachments[0]!.blocks as any[]).find((b) => b.type === "header");
      expect(header.text.text).toContain("RECOVERED");
      expect(JSON.stringify(slack.attachments[0]!.blocks)).toContain("detector-phi");
    });

    it("posts a recovery note to Slack on a passing run after a prior fail (default trigger)", async () => {
      const { fetchImpl, calls } = makeFetch();
      const res = await notifyEvalGate({
        env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
        summary: CLEAN_SUMMARY,
        history: [FAILED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(res.skipped).toBe(false);
      expect(calls).toHaveLength(1);
      const recovery = res.sent.find((s) => s.action === "recovery");
      expect(recovery?.channel).toBe("slack");
      const body = JSON.parse(calls[0]!.init.body as string);
      expect(body.text).toContain("RECOVERED");
      expect(body.text).toContain("detector-phi");
    });

    it("posts an HMAC-signed recovery note to the webhook the adapter verifier accepts", async () => {
      const { fetchImpl, calls } = makeFetch();
      await notifyEvalGate({
        env: {
          CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
          CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
          CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
        },
        summary: CLEAN_SUMMARY,
        history: [FAILED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(calls).toHaveLength(1);
      const { init } = calls[0]!;
      const headers = init.headers as Record<string, string>;
      const ts = Number(headers["x-phi-audit-timestamp"]);
      const body = init.body as string;
      expect(headers["x-phi-audit-signature"]).toBe(`sha256=${adapterSignWebhookBody(WEBHOOK_SECRET, ts, body)}`);
      const payload = JSON.parse(body);
      expect(payload.kind).toBe("eval_gate_recovered");
      expect(payload.severity).toBe("warning");
      expect(payload.recovered).toContain("detector-phi");
    });

    it("does NOT post a recovery note on routine consecutive green nights", async () => {
      const { fetchImpl, calls } = makeFetch();
      const res = await notifyEvalGate({
        env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
        summary: CLEAN_SUMMARY,
        history: [PASSED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(res.skipped).toBe(true);
      expect(calls).toHaveLength(0);
    });

    it("honors the EVAL_NOTIFY_RECOVERY=off opt-out", async () => {
      const { fetchImpl, calls } = makeFetch();
      const res = await notifyEvalGate({
        env: {
          EVAL_NOTIFY_RECOVERY: "off",
          CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
        },
        summary: CLEAN_SUMMARY,
        history: [FAILED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(res.skipped).toBe(true);
      expect(calls).toHaveLength(0);
    });

    it("does not duplicate: under EVAL_NOTIFY_ON=always the normal confirmation posts, not a separate recovery note", async () => {
      const { fetchImpl, calls } = makeFetch();
      await notifyEvalGate({
        env: {
          EVAL_NOTIFY_ON: "always",
          CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
        },
        summary: CLEAN_SUMMARY,
        history: [FAILED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      // Exactly one Slack post — the normal all-green confirmation — with no
      // duplicate recovery note alongside it.
      expect(calls).toHaveLength(1);
      const body = JSON.parse(calls[0]!.init.body as string);
      expect(body.text).toContain("all suites green");
      expect(body.text).not.toContain("RECOVERED");
    });

    it("on a recovery run with PagerDuty + Slack, resolves PagerDuty AND posts the Slack recovery note", async () => {
      const { fetchImpl, calls } = makeFetch(true, 202);
      const res = await notifyEvalGate({
        env: {
          CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
          CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
        },
        summary: CLEAN_SUMMARY,
        history: [FAILED_RUN] as unknown as Hist,
        fetchImpl: fetchImpl as unknown as typeof fetch,
      });
      expect(calls).toHaveLength(2);
      expect(res.sent.find((s) => s.channel === "pagerduty")?.action).toBe("resolve");
      expect(res.sent.find((s) => s.action === "recovery")?.channel).toBe("slack");
    });

    it("records the failing-suite list in history for the next run", () => {
      const dir = mkdtempSync(join(tmpdir(), "eval-history-"));
      try {
        const result = recordRunHistory({
          evalsDir: dir,
          summary: FAIL_SUMMARY,
          now: new Date("2026-05-30T00:00:00.000Z"),
        });
        expect(result[result.length - 1]!.failed).toEqual(["agent-agreement", "detector-phi"]);
        const prev = previousRun(loadHistory(dir));
        expect(prev?.failed).toEqual(["agent-agreement", "detector-phi"]);
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
    });

    describe("recovery duration (was failing for ~X)", () => {
      it("finds the start of the trailing failing streak, or null when the last prior run passed", () => {
        const earlierFail: Run = { ...FAILED_RUN, ts: "2026-05-28T00:00:00.000Z" };
        const laterFail: Run = { ...FAILED_RUN, ts: "2026-05-29T06:00:00.000Z" };
        // Streak = the two consecutive trailing fails; start at the earlier one.
        expect(failingStreakStart([earlierFail, laterFail] as unknown as Hist)).toBe(
          "2026-05-28T00:00:00.000Z",
        );
        // A passing run between fails breaks the streak — only the trailing fail counts.
        expect(
          failingStreakStart([earlierFail, PASSED_RUN, laterFail] as unknown as Hist),
        ).toBe("2026-05-29T06:00:00.000Z");
        // No trailing fail → nothing to measure.
        expect(failingStreakStart([FAILED_RUN, PASSED_RUN] as unknown as Hist)).toBeNull();
        expect(failingStreakStart([] as unknown as Hist)).toBeNull();
      });

      it("formats a millisecond span compactly", () => {
        expect(fmtDuration(0)).toBe("0min");
        expect(fmtDuration(-5)).toBe("0min");
        expect(fmtDuration(45 * 60000)).toBe("45min");
        expect(fmtDuration(3 * 3600000)).toBe("3h");
        expect(fmtDuration(3 * 3600000 + 20 * 60000)).toBe("3h 20min");
        expect(fmtDuration(2 * 86400000)).toBe("2d");
        expect(fmtDuration(2 * 86400000 + 5 * 3600000)).toBe("2d 5h");
      });

      it("appends how long the gate had been failing to the recovery note", async () => {
        const { fetchImpl, calls } = makeFetch();
        await notifyEvalGate({
          env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
          summary: CLEAN_SUMMARY,
          history: [FAILED_RUN] as unknown as Hist,
          // FAILED_RUN.ts is 2026-05-29T00:00:00Z; 3h later → "~3h".
          now: Date.UTC(2026, 4, 29, 3, 0, 0),
          fetchImpl: fetchImpl as unknown as typeof fetch,
        });
        expect(calls).toHaveLength(1);
        const body = JSON.parse(calls[0]!.init.body as string);
        expect(body.text).toContain("was failing for ~3h");
      });
    });

    describe("flapping mute (repeated fail → pass)", () => {
      const FLAP_NOW = Date.UTC(2026, 4, 31, 12, 0, 0);
      const mkRun = (minsAgo: number, failing: boolean): Run =>
        ({
          ts: new Date(FLAP_NOW - minsAgo * 60000).toISOString(),
          ok: !failing,
          outcome: failing ? "failed" : "clean",
          failed: failing ? ["detector-phi"] : [],
          scores: { "detector-phi": failing ? 0.7 : 0.99 },
        }) as Run;
      // 3 fail→pass transitions within the 6h window, ending on a fail so the
      // current passing run reads as the 4th recovery.
      const FLAPPING: Run[] = [
        mkRun(300, true),
        mkRun(250, false),
        mkRun(200, true),
        mkRun(150, false),
        mkRun(100, true),
        mkRun(50, false),
        mkRun(10, true),
        mkRun(5, true),
      ];

      it("parses the flap-mute config with sane defaults", () => {
        expect(recoveryMuteConfig({})).toEqual({ threshold: 3, windowMinutes: 360 });
        expect(
          recoveryMuteConfig({
            EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD: "5",
            EVAL_NOTIFY_RECOVERY_FLAP_WINDOW_MINUTES: "120",
          }),
        ).toEqual({ threshold: 5, windowMinutes: 120 });
      });

      it("counts recent fail→pass transitions inside the window and flags flapping", () => {
        expect(countRecentRecoveries(FLAPPING as unknown as Hist, 360, FLAP_NOW)).toBe(3);
        // A tight window excludes the older transitions.
        expect(countRecentRecoveries(FLAPPING as unknown as Hist, 30, FLAP_NOW)).toBe(0);
        expect(isRecoveryFlapping(FLAPPING as unknown as Hist, {}, FLAP_NOW)).toBe(true);
        // threshold 0 disables muting entirely.
        expect(
          isRecoveryFlapping(
            FLAPPING as unknown as Hist,
            { EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD: "0" },
            FLAP_NOW,
          ),
        ).toBe(false);
      });

      it("mutes the recovery note when the gate is flapping (no Slack post)", async () => {
        const { fetchImpl, calls } = makeFetch();
        const res = await notifyEvalGate({
          env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
          summary: CLEAN_SUMMARY,
          history: FLAPPING as unknown as Hist,
          now: FLAP_NOW,
          fetchImpl: fetchImpl as unknown as typeof fetch,
        });
        expect(res.skipped).toBe(true);
        expect(calls).toHaveLength(0);
      });

      it("still resolves PagerDuty on a flapping recovery even though the Slack note is muted", async () => {
        const { fetchImpl, calls } = makeFetch(true, 202);
        const res = await notifyEvalGate({
          env: {
            CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000",
            CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
          },
          summary: CLEAN_SUMMARY,
          history: FLAPPING as unknown as Hist,
          now: FLAP_NOW,
          fetchImpl: fetchImpl as unknown as typeof fetch,
        });
        // PagerDuty resolve still fires; the Slack recovery note is suppressed.
        expect(calls).toHaveLength(1);
        expect(res.sent.find((s) => s.channel === "pagerduty")?.action).toBe("resolve");
        expect(res.sent.find((s) => s.action === "recovery")).toBeUndefined();
      });

      it("posts the recovery note when flap-muting is disabled (threshold 0)", async () => {
        const { fetchImpl, calls } = makeFetch();
        const res = await notifyEvalGate({
          env: {
            EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD: "0",
            CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
          },
          summary: CLEAN_SUMMARY,
          history: FLAPPING as unknown as Hist,
          now: FLAP_NOW,
          fetchImpl: fetchImpl as unknown as typeof fetch,
        });
        expect(res.skipped).toBe(false);
        expect(calls).toHaveLength(1);
        expect(res.sent.find((s) => s.action === "recovery")?.channel).toBe("slack");
      });
    });
  });
});
