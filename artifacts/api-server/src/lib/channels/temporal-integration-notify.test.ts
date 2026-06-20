import { describe, expect, it } from "vitest";
// The nightly Temporal integration-gate notifier is pure ESM (it must be
// runnable by `node` directly from the GitHub Actions workflow, with no TS
// runner). We import it here to cover its config parsing, severity gating,
// inert-when-unconfigured posture, the distinct PagerDuty dedup key, and the
// no-PHI payload. Its channel send path is the SAME postToChannels primitive the
// heartbeat checker uses, so the byte-for-byte webhook-signing cross-check in
// eval-gate-notify.test.ts covers this notifier's signing too.
import {
  buildTemporalPayload,
  buildTemporalText,
  gateName,
  notifyTemporalGate,
  parseExitCode,
} from "../../../evals/temporal-notify.mjs";
import { defaultTemporalDedupKey } from "../../../evals/notify.mjs";

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

const NOW = Date.UTC(2026, 5, 11, 4, 0, 0); // fixed clock

describe("temporal integration-gate notifier", () => {
  it("resolves the gate name from env, defaulting to 'nightly'", () => {
    expect(gateName({})).toBe("nightly");
    expect(gateName({ TEMPORAL_GATE_NAME: "weekly" })).toBe("weekly");
    expect(gateName({ TEMPORAL_GATE_NAME: "  " })).toBe("nightly");
  });

  it("parses --exit-code and errs toward failure on missing/garbage", () => {
    expect(parseExitCode(["node", "x.mjs", "--exit-code=0"])).toBe(0);
    expect(parseExitCode(["node", "x.mjs", "--exit-code=7"])).toBe(7);
    expect(parseExitCode(["node", "x.mjs"])).toBe(1);
    expect(parseExitCode(["node", "x.mjs", "--exit-code=nope"])).toBe(1);
  });

  it("builds a high-severity, no-PHI alert body + payload", () => {
    const text = buildTemporalText({ name: "nightly", exitCode: 1, now: NOW });
    expect(text).toContain("[ALERT high]");
    expect(text).toContain("temporal-integration.nightly_failed");
    expect(text).toContain("nightly");
    expect(text).not.toMatch(/suite|score|patient|ssn/i);

    const payload = buildTemporalPayload({ name: "nightly", exitCode: 1, now: NOW });
    expect(payload.kind).toBe("temporal_integration_failure");
    expect(payload.severity).toBe("high");
    expect(payload.exitCode).toBe(1);
    expect(payload.occurredAt).toBe(new Date(NOW).toISOString());
    // No score/finding fields leak into the payload.
    expect(JSON.stringify(payload)).not.toMatch(/suite|score/i);
  });

  it("is a no-op on a passing run (exit 0)", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.test/abc" },
      exitCode: 0,
      fetchImpl,
      now: NOW,
    });
    expect(res.skipped).toBe(true);
    expect(res.sent).toHaveLength(0);
    // Slack/webhook have no resolve concept, so a green run posts nothing there.
    expect(calls).toHaveLength(0);
  });

  it("#90: a passing run (exit 0) auto-resolves the PagerDuty incident on the temporal dedup key", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y0000000000000000000000" },
      exitCode: 0,
      fetchImpl,
      now: NOW,
    });
    // One resolve was dispatched, so this run is not "skipped".
    expect(res.skipped).toBe(false);
    expect(res.sent).toHaveLength(1);
    expect(res.sent[0]).toMatchObject({ channel: "pagerduty", ok: true, action: "resolve" });
    expect(calls).toHaveLength(1);

    const event = JSON.parse(calls[0].init.body as string);
    expect(event.event_action).toBe("resolve");
    expect(event.routing_key).toBe("R0UT1NGK3Y0000000000000000000000");
    // The resolve MUST target the SAME stable key the failing run's trigger uses,
    // or a recovering run would fail to clear the page it raised. The Temporal
    // gate trigger keys on defaultTemporalDedupKey(), NOT a per-run/date key.
    expect(event.dedup_key).toBe(defaultTemporalDedupKey());
    expect(event.dedup_key).toBe("temporal-integration-nightly");
    // A stable key carries no date component (so it can't drift run-to-run).
    expect(event.dedup_key).not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  it("#90: a passing run stays inert (skipped) when no PagerDuty channel is configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({
      env: { CHANNEL_WEBHOOK_URL: "https://hook.test/ci" },
      exitCode: 0,
      fetchImpl,
      now: NOW,
    });
    expect(res.skipped).toBe(true);
    expect(res.sent).toHaveLength(0);
    expect(calls).toHaveLength(0);
  });

  it("is inert when no channel is configured", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({ env: {}, exitCode: 1, fetchImpl, now: NOW });
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("posts a failed run to Slack", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({
      env: { CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.test/abc" },
      exitCode: 1,
      fetchImpl,
      now: NOW,
    });
    expect(res.skipped).toBe(false);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://hooks.slack.test/abc");
    const body = JSON.parse(calls[0].init.body as string);
    expect(body.text).toContain("temporal-integration.nightly_failed");
  });

  it("honors per-channel min-severity gating (high alert; critical-only channel skipped)", async () => {
    const { fetchImpl, calls } = makeFetch();
    const res = await notifyTemporalGate({
      env: {
        CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.test/abc",
        CHANNEL_SLACK_MIN_SEVERITY: "critical",
      },
      exitCode: 1,
      fetchImpl,
      now: NOW,
    });
    expect(res.skipped).toBe(true);
    expect(calls).toHaveLength(0);
  });

  it("pages PagerDuty with the distinct temporal dedup key (own incident)", async () => {
    const { fetchImpl, calls } = makeFetch();
    await notifyTemporalGate({
      env: { CHANNEL_PAGERDUTY_ROUTING_KEY: "R0UT1NGK3Y" },
      exitCode: 1,
      fetchImpl,
      now: NOW,
    });
    expect(calls).toHaveLength(1);
    const event = JSON.parse(calls[0].init.body as string);
    expect(event.event_action).toBe("trigger");
    expect(event.dedup_key).toBe(defaultTemporalDedupKey());
    expect(event.dedup_key).toBe("temporal-integration-nightly");
    expect(event.payload.severity).toBe("error"); // high -> error
    expect(event.payload.source).toBe("phi-audit temporal-integration.nightly");
  });

  it("signs the generic webhook (same scheme as the eval gate) and carries no PHI", async () => {
    const { fetchImpl, calls } = makeFetch();
    await notifyTemporalGate({
      env: {
        CHANNEL_WEBHOOK_URL: "https://oncall.test/hook",
        CHANNEL_WEBHOOK_SECRET: WEBHOOK_SECRET,
        CHANNEL_WEBHOOK_ALLOWED_HOSTS: "oncall.test",
      },
      exitCode: 1,
      fetchImpl,
      now: NOW,
    });
    expect(calls).toHaveLength(1);
    const headers = calls[0].init.headers as Record<string, string>;
    expect(headers["x-phi-audit-signature"]).toMatch(/^sha256=/);
    expect(headers["x-phi-audit-timestamp"]).toBeTruthy();
    const payload = JSON.parse(calls[0].init.body as string);
    expect(payload.kind).toBe("temporal_integration_failure");
    expect(JSON.stringify(payload)).not.toMatch(/suite|score|patient/i);
  });
});
