import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { and, eq, gt } from "drizzle-orm";
import { bootstrap, CANARY_TOKEN, db, ledgerEntriesTable } from "@workspace/db";
import { appendLedger } from "../ledger";
import {
  __drainChannelsForTest,
  __resetChannelsForTest,
  __setChannelsForTest,
  buildChannelsFromEnv,
  selectChannels,
  severityRank,
  signWebhookBody,
  verifyWebhookSignature,
} from "./index";
import {
  buildSignatureBase,
  createWebhookAdapter,
} from "./adapters/webhook";
import { createSlackAdapter } from "./adapters/slack";
import {
  createPagerDutyAdapter,
  pagerDutyDedupKey,
  toPagerDutySeverity,
} from "./adapters/pagerduty";
import type { ChannelAdapter, ChannelEnvelope, DispatchResult } from "./types";

const TENANT = "00000000-0000-0000-0000-00000000c6a6";

function uniq(): string {
  return Math.random().toString(36).slice(2, 10);
}

interface FakeAdapter extends ChannelAdapter {
  readonly calls: ChannelEnvelope[];
  readonly result: DispatchResult;
}

function makeFakeAdapter(
  name: string,
  result: Partial<DispatchResult> = { ok: true, statusCode: 200 },
): FakeAdapter {
  const calls: ChannelEnvelope[] = [];
  const r: DispatchResult = {
    channel: name,
    ok: result.ok ?? true,
    ...(result.statusCode !== undefined ? { statusCode: result.statusCode } : {}),
    ...(result.err !== undefined ? { err: result.err } : {}),
    durationMs: result.durationMs ?? 1,
  };
  const adapter: ChannelAdapter = {
    name,
    async send(env): Promise<DispatchResult> {
      calls.push(env);
      return r;
    },
  };
  return Object.assign(adapter, { calls, result: r });
}

async function ledgerEntriesAfter(sinceSeq: number, subjectId?: string) {
  const where = subjectId
    ? and(gt(ledgerEntriesTable.seq, sinceSeq), eq(ledgerEntriesTable.subjectId, subjectId))
    : gt(ledgerEntriesTable.seq, sinceSeq);
  return db.select().from(ledgerEntriesTable).where(where).orderBy(ledgerEntriesTable.seq);
}

async function currentHeadSeq(): Promise<number> {
  const rows = await db.execute<{ max: number | null }>(
    "select max(seq)::int as max from ledger_entries",
  );
  return rows.rows[0]?.max ?? 0;
}

beforeAll(async () => {
  await bootstrap({ embeddingDim: 256 });
});

afterEach(() => {
  __resetChannelsForTest();
});

// ----- Pure unit tests --------------------------------------------------

describe("webhook signature", () => {
  it("buildSignatureBase joins timestamp and body with a dot", () => {
    expect(buildSignatureBase(1700000000, '{"a":1}')).toBe('1700000000.{"a":1}');
  });

  it("sign + verify round-trips on the exact bytes", () => {
    const secret = "0123456789abcdef-test-secret";
    const body = '{"hello":"world"}';
    const ts = 1700000123;
    const sig = signWebhookBody(secret, ts, body);
    expect(sig).toMatch(/^[0-9a-f]{64}$/);
    expect(verifyWebhookSignature(secret, ts, body, sig)).toBe(true);
  });

  it("verifyWebhookSignature returns false on any tamper without throwing", () => {
    const secret = "0123456789abcdef-test-secret";
    const sig = signWebhookBody(secret, 1700000123, "x");
    expect(verifyWebhookSignature(secret, 1700000123, "x" + "y", sig)).toBe(false);
    expect(verifyWebhookSignature(secret + "!", 1700000123, "x", sig)).toBe(false);
    expect(verifyWebhookSignature(secret, 1700000124, "x", sig)).toBe(false);
    expect(verifyWebhookSignature(secret, 1700000123, "x", "not-hex-zz")).toBe(false);
    expect(verifyWebhookSignature(secret, 1700000123, "x", "deadbeef")).toBe(false);
  });
});

describe("webhook adapter construction", () => {
  it("rejects target host not in allow-list", () => {
    expect(() =>
      createWebhookAdapter({
        url: "https://attacker.example/hook",
        secret: "0123456789abcdef-secret",
        allowedHosts: ["hooks.example.com"],
      }),
    ).toThrow(/not in.*allow-list/);
  });

  it("rejects too-short secret", () => {
    expect(() =>
      createWebhookAdapter({
        url: "https://hooks.example.com/hook",
        secret: "short",
        allowedHosts: ["hooks.example.com"],
      }),
    ).toThrow(/at least 16 chars/);
  });

  it("accepts an allow-listed host (case-insensitive)", () => {
    const a = createWebhookAdapter({
      url: "https://Hooks.Example.com/hook",
      secret: "0123456789abcdef-secret",
      allowedHosts: ["hooks.example.com"],
    });
    expect(a.name).toBe("webhook");
  });
});

describe("router selection", () => {
  it("includes channels whose minSeverity is at or below the event severity", () => {
    const a = makeFakeAdapter("a");
    const b = makeFakeAdapter("b");
    const c = makeFakeAdapter("c");
    const cfg = [
      { adapter: a, minSeverity: "warning" as const },
      { adapter: b, minSeverity: "high" as const },
      { adapter: c, minSeverity: "critical" as const },
    ];
    expect(selectChannels(cfg, "warning").map((x) => x.name)).toEqual(["a"]);
    expect(selectChannels(cfg, "high").map((x) => x.name)).toEqual(["a", "b"]);
    expect(selectChannels(cfg, "critical").map((x) => x.name)).toEqual(["a", "b", "c"]);
    expect(severityRank("critical")).toBeGreaterThan(severityRank("warning"));
  });
});

describe("buildChannelsFromEnv", () => {
  it("returns empty config when no channel env is set", () => {
    expect(buildChannelsFromEnv({})).toEqual([]);
  });

  it("skips webhook when URL is set but secret/hosts are missing", () => {
    const out = buildChannelsFromEnv({
      CHANNEL_WEBHOOK_URL: "https://hooks.example.com/x",
    } as NodeJS.ProcessEnv);
    expect(out).toEqual([]);
  });

  it("builds slack adapter when only URL is set", () => {
    const out = buildChannelsFromEnv({
      CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
    } as NodeJS.ProcessEnv);
    expect(out).toHaveLength(1);
    expect(out[0]!.adapter.name).toBe("slack");
    expect(out[0]!.minSeverity).toBe("warning");
  });

  it("respects CHANNEL_SLACK_MIN_SEVERITY", () => {
    const out = buildChannelsFromEnv({
      CHANNEL_SLACK_WEBHOOK_URL: "https://hooks.slack.com/services/T/B/X",
      CHANNEL_SLACK_MIN_SEVERITY: "critical",
    } as NodeJS.ProcessEnv);
    expect(out[0]!.minSeverity).toBe("critical");
  });

  it("builds webhook adapter when URL + secret + allow-list are all set and host matches", () => {
    const out = buildChannelsFromEnv({
      CHANNEL_WEBHOOK_URL: "https://hooks.example.com/hook",
      CHANNEL_WEBHOOK_SECRET: "0123456789abcdef-secret",
      CHANNEL_WEBHOOK_ALLOWED_HOSTS: "hooks.example.com,other.example.com",
    } as NodeJS.ProcessEnv);
    expect(out).toHaveLength(1);
    expect(out[0]!.adapter.name).toBe("webhook");
  });

  it("skips webhook adapter when target host is not in allow-list (no crash)", () => {
    const out = buildChannelsFromEnv({
      CHANNEL_WEBHOOK_URL: "https://attacker.example/hook",
      CHANNEL_WEBHOOK_SECRET: "0123456789abcdef-secret",
      CHANNEL_WEBHOOK_ALLOWED_HOSTS: "hooks.example.com",
    } as NodeJS.ProcessEnv);
    expect(out).toEqual([]);
  });
});

// ----- Adapter HTTP behavior (mocked fetch) -----------------------------

describe("slack adapter", () => {
  it("posts a flat text body to the webhook URL with no PHI-bearing fields", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    const origFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const adapter = createSlackAdapter({ webhookUrl: "https://hooks.slack.com/x" });
      const res = await adapter.send({
        severity: "critical",
        eventType: "ledger.chain_invalid",
        tenantId: TENANT,
        ledgerSeq: 42,
        ledgerHashShort: "abcdef0123456789",
        subjectType: "ledger",
        subjectId: "scope=24h",
        occurredAt: new Date(0).toISOString(),
      });
      expect(res.ok).toBe(true);
      expect(res.statusCode).toBe(200);
      expect(fetchMock).toHaveBeenCalledOnce();
      const args = fetchMock.mock.calls[0]!;
      expect(args[0]).toBe("https://hooks.slack.com/x");
      const body = JSON.parse((args[1] as RequestInit).body as string);
      expect(body.text).toContain("[CRITICAL]");
      expect(body.text).toContain("ledger.chain_invalid");
      expect(body.text).toContain("seq=42");
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("returns ok=false on non-2xx and never throws", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("nope", { status: 503 }));
    const origFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const adapter = createSlackAdapter({ webhookUrl: "https://hooks.slack.com/x" });
      const res = await adapter.send({
        severity: "warning",
        eventType: "x",
        tenantId: null,
        ledgerSeq: 1,
        ledgerHashShort: "h",
        subjectType: null,
        subjectId: null,
        occurredAt: new Date(0).toISOString(),
      });
      expect(res.ok).toBe(false);
      expect(res.statusCode).toBe(503);
      expect(res.err).toMatch(/503/);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

describe("pagerduty adapter", () => {
  it("maps severity onto the PagerDuty enum (high → error)", () => {
    expect(toPagerDutySeverity("warning")).toBe("warning");
    expect(toPagerDutySeverity("high")).toBe("error");
    expect(toPagerDutySeverity("critical")).toBe("critical");
  });

  it("derives a stable dedup key from tenant + event + subject", () => {
    const base: ChannelEnvelope = {
      severity: "critical",
      eventType: "ledger.chain_invalid",
      tenantId: TENANT,
      ledgerSeq: 5,
      ledgerHashShort: "abc",
      subjectType: "ledger",
      subjectId: "scope=24h",
      occurredAt: new Date(0).toISOString(),
    };
    const key = pagerDutyDedupKey(base);
    expect(key).toBe(`phi-audit/${TENANT}/ledger.chain_invalid/ledger/scope=24h`);
    // Same subject + event → same incident; only the seq changes.
    expect(pagerDutyDedupKey({ ...base, ledgerSeq: 99 })).toBe(key);
  });

  it("posts an Events API v2 trigger with metadata-only custom_details", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("", { status: 202 }));
    const origFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const adapter = createPagerDutyAdapter({ routingKey: "R0UT1NGK3Y00000000000000000000" });
      const res = await adapter.send({
        severity: "critical",
        eventType: "ledger.chain_invalid",
        tenantId: TENANT,
        ledgerSeq: 42,
        ledgerHashShort: "abcdef0123456789",
        subjectType: "ledger",
        subjectId: "scope=24h",
        occurredAt: new Date(0).toISOString(),
      });
      expect(res.ok).toBe(true);
      expect(res.statusCode).toBe(202);
      const args = fetchMock.mock.calls[0]!;
      expect(args[0]).toBe("https://events.pagerduty.com/v2/enqueue");
      const body = JSON.parse((args[1] as RequestInit).body as string);
      expect(body.routing_key).toBe("R0UT1NGK3Y00000000000000000000");
      expect(body.event_action).toBe("trigger");
      expect(body.payload.severity).toBe("critical");
      expect(body.payload.summary).toContain("ledger.chain_invalid");
      expect(body.dedup_key).toBe(
        `phi-audit/${TENANT}/ledger.chain_invalid/ledger/scope=24h`,
      );
      // custom_details is metadata only — no payload/actor/detector fields.
      expect(body.payload.custom_details).toEqual({
        ledger_seq: 42,
        ledger_hash_short: "abcdef0123456789",
        subject_type: "ledger",
        subject_id: "scope=24h",
      });
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("returns ok=false on non-2xx and never throws", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("nope", { status: 429 }));
    const origFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const adapter = createPagerDutyAdapter({ routingKey: "R0UT1NGK3Y00000000000000000000" });
      const res = await adapter.send({
        severity: "warning",
        eventType: "x",
        tenantId: null,
        ledgerSeq: 1,
        ledgerHashShort: "h",
        subjectType: null,
        subjectId: null,
        occurredAt: new Date(0).toISOString(),
      });
      expect(res.ok).toBe(false);
      expect(res.statusCode).toBe(429);
      expect(res.err).toMatch(/429/);
    } finally {
      globalThis.fetch = origFetch;
    }
  });

  it("throws at construction on a missing routing key or malformed events URL", () => {
    expect(() => createPagerDutyAdapter({ routingKey: "" })).toThrow(/routingKey is required/);
    expect(() =>
      createPagerDutyAdapter({ routingKey: "k", eventsUrl: "not-a-url" }),
    ).toThrow();
  });
});

describe("webhook adapter HTTP", () => {
  it("signs the body with HMAC-SHA256 over `${ts}.${body}` and includes the signature header", async () => {
    let capturedHeaders: Record<string, string> = {};
    let capturedBody = "";
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      capturedBody = init.body as string;
      const h = init.headers as Record<string, string>;
      capturedHeaders = h;
      return new Response("ok", { status: 200 });
    });
    const origFetch = globalThis.fetch;
    globalThis.fetch = fetchMock as unknown as typeof fetch;
    try {
      const secret = "0123456789abcdef-test-secret";
      const adapter = createWebhookAdapter({
        url: "https://hooks.example.com/hook",
        secret,
        allowedHosts: ["hooks.example.com"],
      });
      const env: ChannelEnvelope = {
        severity: "warning",
        eventType: "ingest.malformed_record",
        tenantId: TENANT,
        ledgerSeq: 9,
        ledgerHashShort: "abc",
        subjectType: null,
        subjectId: null,
        occurredAt: new Date(0).toISOString(),
      };
      const res = await adapter.send(env);
      expect(res.ok).toBe(true);
      const sigHeader = capturedHeaders["x-phi-audit-signature"]!;
      const ts = Number(capturedHeaders["x-phi-audit-timestamp"]!);
      expect(sigHeader).toMatch(/^sha256=[0-9a-f]{64}$/);
      const sig = sigHeader.slice("sha256=".length);
      expect(verifyWebhookSignature(secret, ts, capturedBody, sig)).toBe(true);
      // Receiver-side reference: rebuild signing input and confirm match.
      expect(buildSignatureBase(ts, capturedBody)).toBe(`${ts}.${capturedBody}`);
    } finally {
      globalThis.fetch = origFetch;
    }
  });
});

// ----- Dispatch hook integration (real DB / real appendLedger) ----------

describe("dispatchAlertFromLedger integration", () => {
  beforeEach(() => {
    __resetChannelsForTest();
  });

  it("alertable critical event reaches the adapter; envelope carries metadata only", async () => {
    const adapter = makeFakeAdapter("fake-crit");
    __setChannelsForTest([{ adapter, minSeverity: "warning" }]);
    const subj = `F-CH-${uniq()}`;

    // ledger.chain_invalid is critical per ALERT_RULES.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: subj,
      payload: { scope: "24h", reason: "test" },
    });
    await __drainChannelsForTest();

    expect(adapter.calls).toHaveLength(1);
    const env = adapter.calls[0]!;
    expect(env.severity).toBe("critical");
    expect(env.eventType).toBe("ledger.chain_invalid");
    expect(env.subjectId).toBe(subj);
    // Envelope has no payload / no actor — by construction.
    expect((env as unknown as Record<string, unknown>)["payload"]).toBeUndefined();
    expect((env as unknown as Record<string, unknown>)["actor"]).toBeUndefined();
  });

  it("non-alertable event (chat.user_turn) does NOT reach any adapter", async () => {
    const adapter = makeFakeAdapter("fake-noop");
    __setChannelsForTest([{ adapter, minSeverity: "warning" }]);
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "human", id: "u1" },
      eventType: "chat.user_turn",
      payload: { test: uniq() },
    });
    await __drainChannelsForTest();
    expect(adapter.calls).toHaveLength(0);
  });

  it("severity threshold gates: warning event does NOT reach a critical-only adapter", async () => {
    const adapter = makeFakeAdapter("fake-crit-only");
    __setChannelsForTest([{ adapter, minSeverity: "critical" }]);
    // ingest.malformed_record is warning per ALERT_RULES.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ingest.malformed_record",
      subjectType: "ingest",
      subjectId: `M-${uniq()}`,
      payload: { test: true },
    });
    await __drainChannelsForTest();
    expect(adapter.calls).toHaveLength(0);
  });

  it("channel.send_succeeded does NOT recurse into the dispatcher (loop guard)", async () => {
    const adapter = makeFakeAdapter("fake-loop");
    __setChannelsForTest([{ adapter, minSeverity: "warning" }]);
    const subj = `F-LOOP-${uniq()}`;
    // Trigger one critical event; adapter fires once; channel.send_succeeded
    // is ledgered but must NOT trigger the adapter again.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: subj,
      payload: {},
    });
    await __drainChannelsForTest();
    // Drain twice to give any phantom self-recursion a chance to run.
    await __drainChannelsForTest();
    expect(adapter.calls).toHaveLength(1);
  });

  it("an envelope containing PHI is BLOCKED before the adapter is called; ledgers channel.send_blocked_phi", async () => {
    const adapter = makeFakeAdapter("fake-phi");
    __setChannelsForTest([{ adapter, minSeverity: "warning" }]);
    // Subject id deliberately contains an SSN so the envelope PHI
    // rescan trips. (Real subject ids are opaque ids; this simulates
    // an accidental future field that admits content.)
    void CANARY_TOKEN;
    const subj = `F-PHI-123-45-6789-${uniq()}`;
    const headBefore = await currentHeadSeq();
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: subj,
      payload: {},
    });
    await __drainChannelsForTest();

    expect(adapter.calls).toHaveLength(0);
    const entries = await ledgerEntriesAfter(headBefore, subj);
    const blocked = entries.find((e) => e.eventType === "channel.send_blocked_phi");
    expect(blocked).toBeTruthy();
    const payload = blocked!.payload as { detectors: string[]; channels_skipped: string[] };
    expect(payload.detectors.length).toBeGreaterThan(0);
    expect(payload.channels_skipped).toContain("fake-phi");
  });

  it("an adapter failure writes channel.send_failed and does NOT throw out of appendLedger", async () => {
    const failing: ChannelAdapter = {
      name: "fake-fail",
      async send() {
        throw new Error("connection refused");
      },
    };
    __setChannelsForTest([{ adapter: failing, minSeverity: "warning" }]);
    const subj = `F-FAIL-${uniq()}`;
    const headBefore = await currentHeadSeq();
    // This MUST succeed even though the adapter throws.
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: subj,
      payload: {},
    });
    await __drainChannelsForTest();
    const entries = await ledgerEntriesAfter(headBefore, subj);
    const failedRow = entries.find((e) => e.eventType === "channel.send_failed");
    expect(failedRow).toBeTruthy();
    expect((failedRow!.payload as { err: string }).err).toMatch(/connection refused/);
  });

  it("per-channel rate limit ledgers channel.send_throttled past the cap", async () => {
    const prev = process.env["CHANNEL_RATE_LIMIT_PER_MINUTE"];
    process.env["CHANNEL_RATE_LIMIT_PER_MINUTE"] = "2";
    try {
      const adapter = makeFakeAdapter("fake-rl");
      __setChannelsForTest([{ adapter, minSeverity: "warning" }]);

      // Burst 3 critical events with unique subject ids; first 2 send,
      // third is throttled.
      const subjs = [`F-RL1-${uniq()}`, `F-RL2-${uniq()}`, `F-RL3-${uniq()}`];
      for (const s of subjs) {
        await appendLedger({
          tenantId: TENANT,
          actor: { kind: "system", id: "test" },
          eventType: "ledger.chain_invalid",
          subjectType: "ledger",
          subjectId: s,
          payload: {},
        });
      }
      await __drainChannelsForTest();
      expect(adapter.calls).toHaveLength(2);
      // The throttled subject's ledger row must include channel.send_throttled.
      const throttledRow = (
        await ledgerEntriesAfter(0, subjs[2]!)
      ).find((e) => e.eventType === "channel.send_throttled");
      expect(throttledRow).toBeTruthy();
      expect((throttledRow!.payload as { channel: string }).channel).toBe("fake-rl");
    } finally {
      if (prev === undefined) delete process.env["CHANNEL_RATE_LIMIT_PER_MINUTE"];
      else process.env["CHANNEL_RATE_LIMIT_PER_MINUTE"] = prev;
      __resetChannelsForTest();
    }
  });

  it("fan-out: a single event reaches multiple eligible adapters once each", async () => {
    const a = makeFakeAdapter("fan-a");
    const b = makeFakeAdapter("fan-b");
    __setChannelsForTest([
      { adapter: a, minSeverity: "warning" },
      { adapter: b, minSeverity: "critical" },
    ]);
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: `F-FAN-${uniq()}`,
      payload: {},
    });
    await __drainChannelsForTest();
    expect(a.calls).toHaveLength(1);
    expect(b.calls).toHaveLength(1);
  });

  it("inert config (no channels) is a no-op (no ledger churn)", async () => {
    __setChannelsForTest([]);
    const subj = `F-INERT-${uniq()}`;
    const headBefore = await currentHeadSeq();
    await appendLedger({
      tenantId: TENANT,
      actor: { kind: "system", id: "test" },
      eventType: "ledger.chain_invalid",
      subjectType: "ledger",
      subjectId: subj,
      payload: {},
    });
    await __drainChannelsForTest();
    const entries = await ledgerEntriesAfter(headBefore, subj);
    // Exactly the source event itself, nothing else.
    expect(entries).toHaveLength(1);
    expect(entries[0]!.eventType).toBe("ledger.chain_invalid");
  });
});
