import { describe, it, expect, beforeEach, vi } from "vitest";
import type { LedgerEntry } from "@workspace/db";

import {
  ALERT_RULES,
  maybeEmitAlertFromLedger,
  __resetAlertStateForTest,
} from "./alerts";
import { logger } from "./logger";

function fakeEntry(over: Partial<LedgerEntry>): LedgerEntry {
  return {
    seq: 1,
    ts: new Date(),
    tenantId: "tenant-acme",
    actor: { kind: "human", id: "u1" },
    eventType: "noop",
    subjectType: null,
    subjectId: null,
    payload: {},
    prevHash: "p",
    hash: "h",
    ...over,
  } as LedgerEntry;
}

describe("alerts", () => {
  let warnSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    vi.restoreAllMocks();
    __resetAlertStateForTest();
    warnSpy = vi.spyOn(logger, "warn").mockImplementation((() => {}) as never);
  });

  it("ALERT_RULES contains the M1.x security events", () => {
    expect(ALERT_RULES["agent.canary_in_tool_args"]).toBe("critical");
    expect(ALERT_RULES["break_glass.approval_denied_self_approval"]).toBe(
      "critical",
    );
    expect(ALERT_RULES["policy.text_field_rejected"]).toBe("high");
    expect(ALERT_RULES["break_glass.raw_phi_accessed"]).toBe("warning");
  });

  it("emits one structured alert per alertable ledger event", () => {
    maybeEmitAlertFromLedger(
      fakeEntry({ seq: 42, eventType: "agent.canary_in_tool_args" }),
    );
    expect(warnSpy).toHaveBeenCalledTimes(1);
    const [meta] = warnSpy.mock.calls[0]!;
    expect(meta).toMatchObject({
      alert: true,
      alert_severity: "critical",
      event_type: "agent.canary_in_tool_args",
      ledger_seq: 42,
    });
  });

  it("does not emit for non-alertable event types", () => {
    maybeEmitAlertFromLedger(fakeEntry({ eventType: "auth.login_success" }));
    expect(warnSpy).not.toHaveBeenCalled();
  });

  it("step_up_failed: single failure does NOT page; 3rd within window does", () => {
    const a = fakeEntry({ eventType: "auth.step_up_failed", seq: 1 });
    const b = fakeEntry({ eventType: "auth.step_up_failed", seq: 2 });
    const c = fakeEntry({ eventType: "auth.step_up_failed", seq: 3 });
    maybeEmitAlertFromLedger(a);
    maybeEmitAlertFromLedger(b);
    expect(warnSpy).not.toHaveBeenCalled();
    maybeEmitAlertFromLedger(c);
    expect(warnSpy).toHaveBeenCalledTimes(1);
    expect(warnSpy.mock.calls[0]![0]).toMatchObject({
      alert: true,
      event_type: "auth.step_up_failed.threshold",
      alert_severity: "high",
      failures_in_window: 3,
    });
  });

  it("step_up_failed threshold is keyed per-actor", () => {
    const u1 = (seq: number) =>
      fakeEntry({
        eventType: "auth.step_up_failed",
        actor: { kind: "human", id: "alice" },
        seq,
      });
    const u2 = (seq: number) =>
      fakeEntry({
        eventType: "auth.step_up_failed",
        actor: { kind: "human", id: "bob" },
        seq,
      });
    maybeEmitAlertFromLedger(u1(1));
    maybeEmitAlertFromLedger(u1(2));
    maybeEmitAlertFromLedger(u2(3));
    maybeEmitAlertFromLedger(u2(4));
    // Neither alice nor bob has crossed threshold (2 each).
    expect(warnSpy).not.toHaveBeenCalled();
    maybeEmitAlertFromLedger(u1(5));
    expect(warnSpy).toHaveBeenCalledTimes(1);
  });
});
