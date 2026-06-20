// Unit tests for the pure chain-verifier orchestration seam. No DB, no SDK:
// we inject a fake `ChainVerifierActivities` and assert the orchestration
// delegates to the right activity, mirroring the notarizer/review pattern.

import { describe, it, expect, vi } from "vitest";
import {
  runChainVerifierRolling,
  runChainVerifierFull,
  CHAIN_VERIFIER_ACTIVITY_OPTIONS,
  type ChainVerifierActivities,
} from "./chain-verifier-workflow";

function fakeActivities(): {
  acts: ChainVerifierActivities;
  rolling: ReturnType<typeof vi.fn>;
  full: ReturnType<typeof vi.fn>;
} {
  const rolling = vi.fn(async () => {});
  const full = vi.fn(async () => {});
  return { acts: { runRollingWalk: rolling, runFullWalk: full }, rolling, full };
}

describe("chain-verifier-workflow orchestration", () => {
  it("runChainVerifierRolling calls only the rolling activity", async () => {
    const { acts, rolling, full } = fakeActivities();
    await runChainVerifierRolling(acts);
    expect(rolling).toHaveBeenCalledTimes(1);
    expect(full).not.toHaveBeenCalled();
  });

  it("runChainVerifierFull calls only the full activity", async () => {
    const { acts, rolling, full } = fakeActivities();
    await runChainVerifierFull(acts);
    expect(full).toHaveBeenCalledTimes(1);
    expect(rolling).not.toHaveBeenCalled();
  });

  it("propagates activity rejection (no retry is the workflow's job)", async () => {
    const acts: ChainVerifierActivities = {
      runRollingWalk: vi.fn(async () => {
        throw new Error("walk failed");
      }),
      runFullWalk: vi.fn(async () => {}),
    };
    await expect(runChainVerifierRolling(acts)).rejects.toThrow("walk failed");
  });

  it("activity options disable auto-retry (at-most-once per tick)", () => {
    expect(CHAIN_VERIFIER_ACTIVITY_OPTIONS.retry.maximumAttempts).toBe(1);
    expect(CHAIN_VERIFIER_ACTIVITY_OPTIONS.startToCloseTimeout).toBe(
      "5 minutes",
    );
  });
});
