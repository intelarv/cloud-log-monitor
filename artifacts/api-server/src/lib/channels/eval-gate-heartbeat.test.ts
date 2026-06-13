import { describe, expect, it } from "vitest";
// The heartbeat / dead-man's switch is pure ESM (run by `node` directly in a
// CronJob, no TS runner). We import its pure helpers here to cover staleness
// math, env parsing, and the channel posting path (severity gating + the
// no-PHI payload), reusing the same fake-fetch harness as the run notifier.
// Its webhook signing is the SAME postToChannels path the run notifier uses, so
// the byte-for-byte adapter cross-check in eval-gate-notify.test.ts covers both.
import {
  DEFAULT_MAX_AGE_MINUTES,
  DEFAULT_MAX_RUN_MINUTES,
  DEFAULT_PING_TIMEOUT_MS,
  ageMinutes,
  buildHeartbeatPayload,
  buildHeartbeatText,
  buildHungPayload,
  buildHungText,
  buildPingUrl,
  evaluateHeartbeat,
  evaluateHungRun,
  externalPingUrl,
  gateName,
  isHung,
  isStale,
  parseMaxAgeMinutes,
  parseMaxRunMinutes,
  parsePingTimeoutMs,
  pingExternalHeartbeat,
  pingStyle,
  validateExternalPing,
} from "../../../evals/heartbeat.mjs";
import { signWebhookBody as adapterSignWebhookBody } from "./adapters/webhook";

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

const NOW = Date.UTC(2026, 4, 31, 12, 0, 0); // fixed clock

describe("eval-gate heartbeat", () => {
  it("computes age and staleness, treating a missing stamp as stale", () => {
    const oneHourAgo = new Date(NOW - 60 * 60 * 1000).toISOString();
    expect(Math.round(ageMinutes(oneHourAgo, NOW)!)).toBe(60);
    expect(ageMinutes(null, NOW)).toBeNull();
    expect(ageMinutes("not-a-date", NOW)).toBeNull();

    expect(isStale(oneHourAgo, 1560, NOW)).toBe(false);
    expect(isStale(null, 1560, NOW)).toBe(true);
    const twoDaysAgo = new Date(NOW - 48 * 60 * 60 * 1000).toISOString();
    expect(isStale(twoDaysAgo, 1560, NOW)).toBe(true);
  });

  it("parses EVAL_HEARTBEAT_MAX_AGE_MINUTES and falls back on bad input", () => {
    expect(parseMaxAgeMinutes({})).toBe(DEFAULT_MAX_AGE_MINUTES);
    expect(parseMaxAgeMinutes({ EVAL_HEARTBEAT_MAX_AGE_MINUTES: "120" })).toBe(120);
    expect(parseMaxAgeMinutes({ EVAL_HEARTBEAT_MAX_AGE_MINUTES: "0" })).toBe(DEFAULT_MAX_AGE_MINUTES);
    expect(parseMaxAgeMinutes({ EVAL_HEARTBEAT_MAX_AGE_MINUTES: "nope" })).toBe(
      DEFAULT_MAX_AGE_MINUTES,
    );
    expect(gateName({})).toBe("nightly");
    expect(gateName({ EVAL_HEARTBEAT_NAME: "weekly" })).toBe("weekly");
  });

  it("builds a liveness-only alert body + payload with no scores/PHI fields", () => {
    const text = buildHeartbeatText({
      name: "nightly",
      lastSuccessAt: new Date(NOW - 48 * 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
    });
    expect(text).toContain("[ALERT high]");
    expect(text).toContain("heartbeat_missing");
    expect(text).toContain("nightly");
    expect(text).not.toMatch(/suite|score/i);

    const payload = buildHeartbeatPayload({
      name: "nightly",
      lastSuccessAt: null,
      maxAgeMinutes: 1560,
      now: NOW,
    });
    expect(payload.kind).toBe("eval_gate_heartbeat_missing");
    expect(payload.severity).toBe("high");
    expect(payload.lastSuccessAt).toBeNull();
    expect(payload).not.toHaveProperty("suites");
  });

  it("does not alert when the heartbeat is fresh", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHeartbeat({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      lastSuccessAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.stale).toBe(false);
    expect(res.skipped).toBe(true);
    // Slack/webhook have no resolve concept, so a healthy check posts nothing.
    expect(calls).toHaveLength(0);
  });

  it("clears the open page (PagerDuty resolve) when a healthy check follows a stale one", async () => {
    // Outage: the stale check opens the "went quiet" incident.
    const staleFetch = makeFetch(true, 202);
    const staleRes = await evaluateHeartbeat({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      lastSuccessAt: new Date(NOW - 48 * 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: staleFetch.fetchImpl as unknown as typeof fetch,
    });
    expect(staleRes.stale).toBe(true);
    expect(staleFetch.calls).toHaveLength(1);
    const triggerEvent = JSON.parse(staleFetch.calls[0]!.init.body as string);
    expect(triggerEvent.event_action).toBe("trigger");

    // Recovery: the nightly came back, the heartbeat is fresh again. The healthy
    // check must resolve the EXACT same dedup_key so the prior page self-clears.
    const healthyFetch = makeFetch(true, 202);
    const healthyRes = await evaluateHeartbeat({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      lastSuccessAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: healthyFetch.fetchImpl as unknown as typeof fetch,
    });
    expect(healthyRes.stale).toBe(false);
    expect(healthyRes.skipped).toBe(false);
    expect(healthyFetch.calls).toHaveLength(1);
    const resolveEvent = JSON.parse(healthyFetch.calls[0]!.init.body as string);
    expect(resolveEvent.event_action).toBe("resolve");
    expect(resolveEvent.dedup_key).toBe(triggerEvent.dedup_key);
    expect(healthyRes.sent.find((s) => s.channel === "pagerduty")?.action).toBe("resolve");
  });

  it("surfaces a failed resolve on a healthy check (the data the CLI exits non-zero on)", async () => {
    // The nightly recovered, so the check is healthy and tries to RESOLVE the
    // open "went quiet" page — but PagerDuty is unreachable, so the resolve
    // send fails. The healthy branch must still report skipped:false with a
    // failed `sent` entry, which is exactly what the CLI `--check` handler keys
    // on (`!skipped && sent.some(s => !s.ok)`) to exit non-zero so the lingering
    // page is not swallowed silently.
    const failingFetch = makeFetch(false, 502);
    const res = await evaluateHeartbeat({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      lastSuccessAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: failingFetch.fetchImpl as unknown as typeof fetch,
    });
    expect(res.stale).toBe(false);
    expect(res.skipped).toBe(false);
    expect(res.sent.some((s) => !s.ok)).toBe(true);
    expect(failingFetch.calls).toHaveLength(1);
    const resolveEvent = JSON.parse(failingFetch.calls[0]!.init.body as string);
    expect(resolveEvent.event_action).toBe("resolve");
  });

  it("pages Slack at high severity when the heartbeat is stale", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHeartbeat({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      lastSuccessAt: new Date(NOW - 48 * 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.stale).toBe(true);
    expect(res.skipped).toBe(false);
    expect(res.severity).toBe("high");
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.text).toContain("heartbeat_missing");
  });

  it("is inert (no page) when stale but no channel is configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHeartbeat({
      env: {},
      lastSuccessAt: null,
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.stale).toBe(true);
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("a warning-only channel does not receive the high-severity heartbeat page when pinned higher", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHeartbeat({
      env: {
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
        CHANNEL_SLACK_MIN_SEVERITY: "critical",
      },
      lastSuccessAt: null,
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.stale).toBe(true);
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("parses the external ping URL and timeout, treating blank/bad values as unset/default", () => {
    expect(externalPingUrl({})).toBeNull();
    expect(externalPingUrl({ HEARTBEAT_PING_URL: "   " })).toBeNull();
    expect(externalPingUrl({ HEARTBEAT_PING_URL: " https://hc-ping.com/uuid " })).toBe(
      "https://hc-ping.com/uuid",
    );
    expect(parsePingTimeoutMs({})).toBe(DEFAULT_PING_TIMEOUT_MS);
    expect(parsePingTimeoutMs({ HEARTBEAT_PING_TIMEOUT_MS: "2000" })).toBe(2000);
    expect(parsePingTimeoutMs({ HEARTBEAT_PING_TIMEOUT_MS: "0" })).toBe(DEFAULT_PING_TIMEOUT_MS);
    expect(parsePingTimeoutMs({ HEARTBEAT_PING_TIMEOUT_MS: "nope" })).toBe(DEFAULT_PING_TIMEOUT_MS);
  });

  it("validates the external outage-alert URL, flagging a misconfigured one", () => {
    expect(validateExternalPing({})).toEqual({
      configured: false,
      valid: false,
      url: null,
      reason: null,
    });
    expect(validateExternalPing({ HEARTBEAT_PING_URL: "https://hc-ping.com/uuid" })).toEqual({
      configured: true,
      valid: true,
      url: "https://hc-ping.com/uuid",
      reason: null,
    });
    // A bare typo'd value is not a valid absolute URL → misconfigured.
    const notUrl = validateExternalPing({ HEARTBEAT_PING_URL: "hc-ping.com/uuid" });
    expect(notUrl.configured).toBe(true);
    expect(notUrl.valid).toBe(false);
    expect(notUrl.reason).toContain("not a valid absolute URL");
    // A non-http(s) scheme cannot be GET-pinged → misconfigured.
    const badScheme = validateExternalPing({ HEARTBEAT_PING_URL: "ftp://hc-ping.com/uuid" });
    expect(badScheme.valid).toBe(false);
    expect(badScheme.reason).toContain("unsupported scheme");
  });

  it("refuses to silently ping a misconfigured outage-alert URL (no fetch, flagged)", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await pingExternalHeartbeat({
      env: { HEARTBEAT_PING_URL: "not-a-url" },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.pinged).toBe(false);
    expect(res.misconfigured).toBe(true);
    expect(res.skipped).toBeUndefined();
    expect(res.reason).toContain("not a valid absolute URL");
    // Crucially: no fetch attempt — a bad URL must NOT look like a transient blip.
    expect(calls).toHaveLength(0);
  });

  it("is inert (no external ping) when HEARTBEAT_PING_URL is unset", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await pingExternalHeartbeat({
      env: {},
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.pinged).toBe(false);
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("pings the external uptime monitor when HEARTBEAT_PING_URL is set", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await pingExternalHeartbeat({
      env: { HEARTBEAT_PING_URL: "https://hc-ping.com/uuid" },
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.pinged).toBe(true);
    expect(res.ok).toBe(true);
    expect(res.stage).toBe("success");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://hc-ping.com/uuid");
    expect(calls[0]!.init.method).toBe("GET");
  });

  it("resolves the ping style, defaulting to healthchecks and warning on junk", () => {
    expect(pingStyle({})).toBe("healthchecks");
    expect(pingStyle({ HEARTBEAT_PING_STYLE: "healthchecks" })).toBe("healthchecks");
    expect(pingStyle({ HEARTBEAT_PING_STYLE: " Cronitor " })).toBe("cronitor");
    expect(pingStyle({ HEARTBEAT_PING_STYLE: "nonsense" })).toBe("healthchecks");
  });

  it("shapes start/success/fail URLs per monitor convention", () => {
    // healthchecks.io: path suffixes, bare URL = success/OK check-in.
    expect(buildPingUrl("https://hc-ping.com/uuid", "start", "healthchecks")).toBe(
      "https://hc-ping.com/uuid/start",
    );
    expect(buildPingUrl("https://hc-ping.com/uuid", "success", "healthchecks")).toBe(
      "https://hc-ping.com/uuid",
    );
    expect(buildPingUrl("https://hc-ping.com/uuid", "fail", "healthchecks")).toBe(
      "https://hc-ping.com/uuid/fail",
    );
    // Trailing slash on the base must not produce a double slash.
    expect(buildPingUrl("https://hc-ping.com/uuid/", "fail", "healthchecks")).toBe(
      "https://hc-ping.com/uuid/fail",
    );
    // Cronitor: ?state= query, with & when the URL already has a query string.
    expect(buildPingUrl("https://cronitor.link/p/abc/job", "start", "cronitor")).toBe(
      "https://cronitor.link/p/abc/job?state=run",
    );
    expect(buildPingUrl("https://cronitor.link/p/abc/job", "success", "cronitor")).toBe(
      "https://cronitor.link/p/abc/job?state=complete",
    );
    expect(buildPingUrl("https://cronitor.link/p/abc/job", "fail", "cronitor")).toBe(
      "https://cronitor.link/p/abc/job?state=fail",
    );
    expect(buildPingUrl("https://cronitor.link/p/abc/job?env=prod", "fail", "cronitor")).toBe(
      "https://cronitor.link/p/abc/job?env=prod&state=fail",
    );
  });

  it("pings the start endpoint (healthchecks suffix) when stage=start", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await pingExternalHeartbeat({
      env: { HEARTBEAT_PING_URL: "https://hc-ping.com/uuid" },
      stage: "start",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.pinged).toBe(true);
    expect(res.stage).toBe("start");
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://hc-ping.com/uuid/start");
  });

  it("pings the fail endpoint when stage=fail, honoring the cronitor style", async () => {
    const { fetchImpl, calls } = makeFetch();
    await pingExternalHeartbeat({
      env: {
        HEARTBEAT_PING_URL: "https://cronitor.link/p/abc/job",
        HEARTBEAT_PING_STYLE: "cronitor",
      },
      stage: "fail",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    expect(calls[0]!.url).toBe("https://cronitor.link/p/abc/job?state=fail");
  });

  it("carries the stage through even when inert (no URL configured)", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await pingExternalHeartbeat({
      env: {},
      stage: "start",
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.pinged).toBe(false);
    expect(res.skipped).toBe(true);
    expect(res.stage).toBe("start");
    expect(calls).toHaveLength(0);
  });

  it("treats a failed external ping as non-fatal (swallowed, never throws)", async () => {
    const throwingFetch = (async () => {
      throw new Error("network down");
    }) as unknown as typeof fetch;
    const res = await pingExternalHeartbeat({
      env: { HEARTBEAT_PING_URL: "https://hc-ping.com/uuid" },
      fetchImpl: throwingFetch,
    });
    expect(res.pinged).toBe(true);
    expect(res.ok).toBe(false);
    expect(res.error).toContain("network down");

    const { fetchImpl: notOkFetch, calls } = makeFetch(false, 500);
    const res2 = await pingExternalHeartbeat({
      env: { HEARTBEAT_PING_URL: "https://hc-ping.com/uuid" },
      fetchImpl: notOkFetch as unknown as typeof fetch,
    });
    expect(res2.pinged).toBe(true);
    expect(res2.ok).toBe(false);
    expect(res2.status).toBe(500);
    expect(calls).toHaveLength(1);
  });

  it("signs the generic-webhook page with the app adapter's scheme", async () => {
    const { fetchImpl, calls } = makeFetch();
    await evaluateHeartbeat({
      env: {
        CHANNEL_WEBHOOK_URL: "https://alerts.example.com/hook",
        CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
        CHANNEL_WEBHOOK_ALLOWED_HOSTS: "alerts.example.com",
      },
      lastSuccessAt: null,
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(calls).toHaveLength(1);
    const { init } = calls[0]!;
    const headers = init.headers as Record<string, string>;
    const ts = Number(headers["x-phi-audit-timestamp"]);
    const body = init.body as string;
    expect(headers["x-phi-audit-signature"]).toBe(
      `sha256=${adapterSignWebhookBody(WEBHOOK_SECRET, ts, body)}`,
    );
    const payload = JSON.parse(body);
    expect(payload.kind).toBe("eval_gate_heartbeat_missing");
    expect(payload.severity).toBe("high");
  });

  // ---------------------------------------------------------------------------
  // Hung-run detection (--start stamps last_start_at; --check pages when a run
  // began but no completion arrived within the max-run window).
  // ---------------------------------------------------------------------------

  it("parses EVAL_HEARTBEAT_MAX_RUN_MINUTES and falls back on bad input", () => {
    expect(parseMaxRunMinutes({})).toBe(DEFAULT_MAX_RUN_MINUTES);
    expect(parseMaxRunMinutes({ EVAL_HEARTBEAT_MAX_RUN_MINUTES: "30" })).toBe(30);
    expect(parseMaxRunMinutes({ EVAL_HEARTBEAT_MAX_RUN_MINUTES: "0" })).toBe(DEFAULT_MAX_RUN_MINUTES);
    expect(parseMaxRunMinutes({ EVAL_HEARTBEAT_MAX_RUN_MINUTES: "nope" })).toBe(
      DEFAULT_MAX_RUN_MINUTES,
    );
  });

  it("flags a hung run: start present, no completion at/after it, older than max-run", () => {
    const threeHoursAgo = new Date(NOW - 3 * 60 * 60 * 1000).toISOString();
    const fourHoursAgo = new Date(NOW - 4 * 60 * 60 * 1000).toISOString();
    const tenMinAgo = new Date(NOW - 10 * 60 * 1000).toISOString();

    // No start stamp at all → never hung (pre-upgrade / never-started rows).
    expect(isHung(null, fourHoursAgo, 120, NOW)).toBe(false);
    // Started 3h ago, last completion 4h ago (before the start) → hung at 120min.
    expect(isHung(threeHoursAgo, fourHoursAgo, 120, NOW)).toBe(true);
    // Started 3h ago, never completed → hung.
    expect(isHung(threeHoursAgo, null, 120, NOW)).toBe(true);
    // A completion AT/AFTER the start means the run finished → not hung.
    expect(isHung(threeHoursAgo, tenMinAgo, 120, NOW)).toBe(false);
    // Start within the window → in-flight, not yet hung.
    expect(isHung(tenMinAgo, fourHoursAgo, 120, NOW)).toBe(false);
    // Unparseable start stamp → not hung (cannot prove a hang).
    expect(isHung("not-a-date", null, 120, NOW)).toBe(false);
  });

  it("builds a hung-run alert body + payload with no scores/PHI fields", () => {
    const startedAt = new Date(NOW - 3 * 60 * 60 * 1000).toISOString();
    const text = buildHungText({
      name: "nightly",
      lastStartAt: startedAt,
      lastSuccessAt: null,
      maxRunMinutes: 120,
      now: NOW,
    });
    expect(text).toContain("[ALERT high]");
    expect(text).toContain("run_hung");
    expect(text).toContain("nightly");

    const payload = buildHungPayload({
      name: "nightly",
      lastStartAt: startedAt,
      lastSuccessAt: null,
      maxRunMinutes: 120,
      now: NOW,
    });
    expect(payload.kind).toBe("eval_gate_run_hung");
    expect(payload.severity).toBe("high");
    expect(payload.lastStartAt).toBe(startedAt);
    expect(payload.lastSuccessAt).toBeNull();
    expect(Math.round(payload.runMinutes ?? NaN)).toBe(180);
    expect(payload).not.toHaveProperty("suites");
  });

  it("pages Slack at high severity when a run is hung", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHungRun({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      lastStartAt: new Date(NOW - 3 * 60 * 60 * 1000).toISOString(),
      lastSuccessAt: null,
      maxRunMinutes: 120,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.hung).toBe(true);
    expect(res.skipped).toBe(false);
    expect(res.severity).toBe("high");
    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0]!.init.body as string);
    expect(body.text).toContain("run_hung");
  });

  it("does not alert (inert) when the run is not hung", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHungRun({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X" },
      // Completion is after the start → finished, not hung.
      lastStartAt: new Date(NOW - 3 * 60 * 60 * 1000).toISOString(),
      lastSuccessAt: new Date(NOW - 10 * 60 * 1000).toISOString(),
      maxRunMinutes: 120,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.hung).toBe(false);
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("shares the PagerDuty liveness dedup_key so a later completion auto-resolves the hung page", async () => {
    // Hung run opens the liveness incident.
    const hungFetch = makeFetch(true, 202);
    const hungRes = await evaluateHungRun({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      lastStartAt: new Date(NOW - 3 * 60 * 60 * 1000).toISOString(),
      lastSuccessAt: null,
      maxRunMinutes: 120,
      now: NOW,
      fetchImpl: hungFetch.fetchImpl as unknown as typeof fetch,
    });
    expect(hungRes.hung).toBe(true);
    const triggerEvent = JSON.parse(hungFetch.calls[0]!.init.body as string);
    expect(triggerEvent.event_action).toBe("trigger");

    // A later healthy completion-staleness check resolves the SAME dedup_key.
    const healthyFetch = makeFetch(true, 202);
    const healthyRes = await evaluateHeartbeat({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      lastSuccessAt: new Date(NOW - 60 * 60 * 1000).toISOString(),
      maxAgeMinutes: 1560,
      now: NOW,
      fetchImpl: healthyFetch.fetchImpl as unknown as typeof fetch,
    });
    const resolveEvent = JSON.parse(healthyFetch.calls[0]!.init.body as string);
    expect(resolveEvent.event_action).toBe("resolve");
    expect(resolveEvent.dedup_key).toBe(triggerEvent.dedup_key);
    expect(healthyRes.stale).toBe(false);
  });

  it("is inert (no page) when hung but no channel is configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await evaluateHungRun({
      env: {},
      lastStartAt: new Date(NOW - 3 * 60 * 60 * 1000).toISOString(),
      lastSuccessAt: null,
      maxRunMinutes: 120,
      now: NOW,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(res.hung).toBe(true);
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });
});
