// Unit tests for the pure remediation-execution orchestration seam. No DB, no
// SDK: we inject a fake `RemediationExecutionActivities` and assert the
// orchestration delegates to the single cycle activity, mirroring the
// chain-verifier / notarizer pattern.

import { describe, it, expect, vi } from "vitest";
import {
  runRemediationExecutionCycle,
  REMEDIATION_EXECUTION_ACTIVITY_OPTIONS,
  type RemediationExecutionActivities,
} from "./remediation-execution-workflow";

describe("remediation-execution-workflow orchestration", () => {
  it("runRemediationExecutionCycle calls the runCycle activity once", async () => {
    const runCycle = vi.fn(async () => {});
    const acts: RemediationExecutionActivities = { runCycle };
    await runRemediationExecutionCycle(acts);
    expect(runCycle).toHaveBeenCalledTimes(1);
  });

  it("propagates activity rejection (retry is the cron's job, not the cycle's)", async () => {
    const acts: RemediationExecutionActivities = {
      runCycle: vi.fn(async () => {
        throw new Error("sweep failed");
      }),
    };
    await expect(runRemediationExecutionCycle(acts)).rejects.toThrow(
      "sweep failed",
    );
  });

  it("activity options disable auto-retry (at-most-once per tick)", () => {
    expect(REMEDIATION_EXECUTION_ACTIVITY_OPTIONS.retry.maximumAttempts).toBe(1);
    expect(REMEDIATION_EXECUTION_ACTIVITY_OPTIONS.startToCloseTimeout).toBe(
      "5 minutes",
    );
  });
});
