// Unit tests for the RemediationExecutor seam factory + the pure (no-DB) parts
// of each backend. The factory contract mirrors every other provider seam
// (search / raw-evidence / log-bus / NER): default-inert unless explicitly
// opted in, fail-fast on a bad value or a partially-configured backend. The
// DB-touching backend (RedactionQueueExecutor) is covered in
// remediation-executor.integration.test.ts.

import { describe, it, expect, vi } from "vitest";
import {
  buildRemediationExecutorFromEnv,
  ChannelSendExecutor,
  DevNoopExecutor,
  GitHubIssueExecutor,
  RedactionQueueExecutor,
  RoutingRemediationExecutor,
  type RemediationExecutionInput,
} from "./remediation-executor";

const baseInput = (
  over: Partial<RemediationExecutionInput> = {},
): RemediationExecutionInput => ({
  proposalId: "prop-123",
  tenantId: "default",
  findingId: "F-1",
  actionType: "notify_owner",
  summary: "redacted summary",
  rationale: "redacted rationale",
  ...over,
});

describe("buildRemediationExecutorFromEnv", () => {
  it("returns null when REMEDIATION_EXECUTOR is unset (default-inert)", () => {
    expect(buildRemediationExecutorFromEnv({})).toBeNull();
  });

  it("returns null for 'none' (explicit off)", () => {
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "none" }),
    ).toBeNull();
  });

  it("treats whitespace/casing leniently and stays inert", () => {
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "  NONE  " }),
    ).toBeNull();
  });

  it("returns DevNoopExecutor for 'noop' and 'dev'", () => {
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "noop" }),
    ).toBeInstanceOf(DevNoopExecutor);
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "DEV" }),
    ).toBeInstanceOf(DevNoopExecutor);
  });

  it("returns ChannelSendExecutor for 'channel-send'", () => {
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "channel-send" }),
    ).toBeInstanceOf(ChannelSendExecutor);
  });

  it("returns RedactionQueueExecutor for 'redaction-queue'", () => {
    expect(
      buildRemediationExecutorFromEnv({
        REMEDIATION_EXECUTOR: "redaction-queue",
      }),
    ).toBeInstanceOf(RedactionQueueExecutor);
  });

  it("returns RoutingRemediationExecutor for 'routed'", () => {
    expect(
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "routed" }),
    ).toBeInstanceOf(RoutingRemediationExecutor);
  });

  it("returns GitHubIssueExecutor for 'github' when fully configured", () => {
    expect(
      buildRemediationExecutorFromEnv({
        REMEDIATION_EXECUTOR: "github",
        REMEDIATION_GITHUB_TOKEN: "t",
        REMEDIATION_GITHUB_OWNER: "o",
        REMEDIATION_GITHUB_REPO: "r",
      }),
    ).toBeInstanceOf(GitHubIssueExecutor);
  });

  it("throws fast on 'github' with a partial config (never silently no-ops)", () => {
    expect(() =>
      buildRemediationExecutorFromEnv({
        REMEDIATION_EXECUTOR: "github",
        REMEDIATION_GITHUB_TOKEN: "t",
      }),
    ).toThrow(/REMEDIATION_GITHUB_/);
  });

  it("throws fast on an unknown value", () => {
    expect(() =>
      buildRemediationExecutorFromEnv({ REMEDIATION_EXECUTOR: "open-pr" }),
    ).toThrow(/Unknown REMEDIATION_EXECUTOR/);
  });
});

describe("DevNoopExecutor", () => {
  it("reports success with a synthetic external_ref derived from the proposal id", async () => {
    const ex = new DevNoopExecutor();
    expect(ex.kind).toBe("noop");
    const result = await ex.execute(baseInput({ actionType: "redact_at_source" }));
    expect(result).toEqual({ ok: true, externalRef: "noop:prop-123" });
  });
});

describe("ChannelSendExecutor", () => {
  it("emits a PHI-safe alertable ledger event (ids + action_type only) and succeeds", async () => {
    const append = vi.fn().mockResolvedValue(undefined);
    const ex = new ChannelSendExecutor({
      append: append as never,
      channelsConfigured: () => true,
    });
    const result = await ex.execute(baseInput());
    expect(result).toEqual({
      ok: true,
      externalRef: "channel-send:prop-123",
    });
    expect(append).toHaveBeenCalledTimes(1);
    const event = append.mock.calls[0][0];
    expect(event.eventType).toBe("remediation.notify_dispatched");
    // PHI-safe: payload carries ONLY ids + the categorical action_type — never
    // the free-text summary/rationale.
    expect(event.payload).toEqual({
      proposal_id: "prop-123",
      finding_id: "F-1",
      action_type: "notify_owner",
    });
    const serialized = JSON.stringify(event);
    expect(serialized).not.toContain("redacted summary");
    expect(serialized).not.toContain("redacted rationale");
  });

  it("fails closed (no event emitted) when no channels are configured", async () => {
    const append = vi.fn().mockResolvedValue(undefined);
    const ex = new ChannelSendExecutor({
      append: append as never,
      channelsConfigured: () => false,
    });
    const result = await ex.execute(baseInput());
    expect(result).toEqual({ ok: false, reason: "no_channels_configured" });
    expect(append).not.toHaveBeenCalled();
  });
});

describe("GitHubIssueExecutor", () => {
  const config = { token: "t", owner: "o", repo: "r", labels: ["remediation"] };

  it("opens a tracking issue and returns the html_url as external_ref", async () => {
    const createIssue = vi
      .fn()
      .mockResolvedValue({ htmlUrl: "https://github.com/o/r/issues/7" });
    const ex = new GitHubIssueExecutor(config, createIssue);
    const result = await ex.execute(baseInput({ actionType: "open_pr" }));
    expect(result).toEqual({
      ok: true,
      externalRef: "github:https://github.com/o/r/issues/7",
    });
    const params = createIssue.mock.calls[0][0];
    expect(params.owner).toBe("o");
    expect(params.repo).toBe("r");
    expect(params.labels).toEqual(["remediation"]);
    expect(params.title).toContain("open_pr");
    expect(params.body).toContain("redacted summary");
  });

  it("refuses (no external call) when PHI is detected in the payload", async () => {
    const createIssue = vi.fn();
    const ex = new GitHubIssueExecutor(config, createIssue);
    // A clear PHI token (SSN) in the summary must hard-fail before the send.
    const result = await ex.execute(
      baseInput({ summary: "patient SSN 123-45-6789" }),
    );
    expect(result).toEqual({ ok: false, reason: "phi_in_payload" });
    expect(createIssue).not.toHaveBeenCalled();
  });

  it("returns a static, PHI-safe reason on an API error (no body leak)", async () => {
    const createIssue = vi
      .fn()
      .mockRejectedValue(new Error("422 with echoed request body"));
    const ex = new GitHubIssueExecutor(config, createIssue);
    const result = await ex.execute(baseInput({ actionType: "open_pr" }));
    expect(result).toEqual({ ok: false, reason: "github_api_error" });
  });
});

describe("RoutingRemediationExecutor", () => {
  it("dispatches each action_type to its mapped backend, else the fallback", async () => {
    const notify = { kind: "channel-send", execute: vi.fn().mockResolvedValue({ ok: true, externalRef: "channel-send:p" }) };
    const queue = { kind: "redaction-queue", execute: vi.fn().mockResolvedValue({ ok: true, externalRef: "redaction-queue:rq" }) };
    const fallback = { kind: "fb", execute: vi.fn().mockResolvedValue({ ok: true, externalRef: "fb:p" }) };
    const routes = new Map([
      ["notify_owner", notify],
      ["redact_at_source", queue],
    ]);
    const ex = new RoutingRemediationExecutor(routes, fallback);
    expect(ex.kind).toBe("routed");

    expect(await ex.execute(baseInput({ actionType: "notify_owner" }))).toEqual({
      ok: true,
      externalRef: "channel-send:p",
    });
    expect(
      await ex.execute(baseInput({ actionType: "redact_at_source" })),
    ).toEqual({ ok: true, externalRef: "redaction-queue:rq" });
    // Unmapped action_type falls back.
    expect(await ex.execute(baseInput({ actionType: "mystery" }))).toEqual({
      ok: true,
      externalRef: "fb:p",
    });
    expect(notify.execute).toHaveBeenCalledTimes(1);
    expect(queue.execute).toHaveBeenCalledTimes(1);
    expect(fallback.execute).toHaveBeenCalledTimes(1);
  });

  it("routed factory falls back to channel-send for the config family when GitHub is unconfigured", async () => {
    const ex = buildRemediationExecutorFromEnv({
      REMEDIATION_EXECUTOR: "routed",
    }) as RoutingRemediationExecutor;
    // No GitHub env ⇒ open_pr is not a GitHubIssueExecutor; routing falls back
    // to channel-send, which fails closed with no channels in the test env.
    const result = await ex.execute(baseInput({ actionType: "open_pr" }));
    expect(result).toEqual({ ok: false, reason: "no_channels_configured" });
  });
});
