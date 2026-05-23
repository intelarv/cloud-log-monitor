// Tests for the M1.8 periodic chain verifier. We exercise the inner
// runOnce + emitInvalid via the `__test__` export so we don't need to
// spin up setInterval or a real DB. appendLedger is mocked at the
// module boundary so we can assert the chain_invalid payload shape
// without writing to the ledger.

import { describe, it, expect, vi, beforeEach } from "vitest";

type AppendLedgerArg = Parameters<typeof import("./ledger").appendLedger>[0];
const appendLedgerMock = vi.fn(async (_input: AppendLedgerArg) => ({
  ok: true,
}));

vi.mock("./ledger", async () => {
  const actual = await vi.importActual<typeof import("./ledger")>("./ledger");
  return {
    ...actual,
    appendLedger: (input: AppendLedgerArg) => appendLedgerMock(input),
  };
});

import { __test__ } from "./chain-verifier";
import type { VerifyResult } from "./ledger";

const okResult: VerifyResult = {
  ok: true,
  walked: 5,
  head_seq: 42,
  head_hash: "deadbeef".repeat(8),
  errors: [],
};

const badResult: VerifyResult = {
  ok: false,
  walked: 7,
  head_seq: 13,
  head_hash: "cafef00d".repeat(8),
  errors: [
    "seq 12: hash mismatch (recomputed aaa, stored bbb)",
    "seq 13: prev_hash mismatch (expected aaa, got ccc)",
  ],
};

describe("chain-verifier", () => {
  beforeEach(() => {
    appendLedgerMock.mockClear();
  });

  it("runOnce: ok result does NOT append ledger.chain_invalid", async () => {
    await __test__.runOnce("rolling_24h", async () => okResult);
    expect(appendLedgerMock).not.toHaveBeenCalled();
  });

  it("runOnce: failed result appends ledger.chain_invalid with scope + capped errors", async () => {
    await __test__.runOnce("full", async () => badResult);
    expect(appendLedgerMock).toHaveBeenCalledTimes(1);
    const call = appendLedgerMock.mock.calls[0]![0] as unknown as {
      eventType: string;
      actor: { kind: string; id: string };
      tenantId: null;
      subjectType: string;
      subjectId: string;
      payload: {
        scope: string;
        walked: number;
        head_seq: number;
        head_hash: string;
        error_count: number;
        first_errors: string[];
      };
    };
    expect(call.eventType).toBe("ledger.chain_invalid");
    expect(call.actor).toEqual({ kind: "system", id: "chain_verifier" });
    expect(call.tenantId).toBeNull();
    expect(call.subjectType).toBe("ledger");
    expect(call.subjectId).toBe("13");
    expect(call.payload.scope).toBe("full");
    expect(call.payload.error_count).toBe(2);
    expect(call.payload.first_errors).toHaveLength(2);
    expect(call.payload.first_errors[0]).toContain("hash mismatch");
  });

  it("runOnce: caps first_errors at 5 even with many failures", async () => {
    const many: VerifyResult = {
      ok: false,
      walked: 50,
      head_seq: 50,
      head_hash: "x",
      errors: Array.from({ length: 20 }, (_, i) => `seq ${i}: bad`),
    };
    await __test__.runOnce("rolling_24h", async () => many);
    const call = appendLedgerMock.mock.calls[0]![0] as unknown as {
      payload: { error_count: number; first_errors: string[] };
    };
    expect(call.payload.error_count).toBe(20);
    expect(call.payload.first_errors).toHaveLength(5);
  });

  it("runOnce: a thrown verifier does NOT append chain_invalid", async () => {
    // Operational failure (e.g. DB blip) must not muddy the security signal.
    await __test__.runOnce("rolling_24h", async () => {
      throw new Error("db blip");
    });
    expect(appendLedgerMock).not.toHaveBeenCalled();
  });
});
