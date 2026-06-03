import { describe, it, expect } from "vitest";
import { withTimeout, TimeoutError } from "./with-timeout";

const delay = <T>(ms: number, value: T): Promise<T> =>
  new Promise((r) => setTimeout(() => r(value), ms));

describe("withTimeout", () => {
  it("resolves when the promise settles before the deadline", async () => {
    await expect(withTimeout(delay(5, "ok"), 200, "fast")).resolves.toBe("ok");
  });

  it("rejects with TimeoutError when the promise is too slow", async () => {
    await expect(
      withTimeout(delay(200, "late"), 10, "slow"),
    ).rejects.toBeInstanceOf(TimeoutError);
  });

  it("TimeoutError carries the label and duration", async () => {
    try {
      await withTimeout(delay(200, "late"), 10, "llm_call");
      throw new Error("should have timed out");
    } catch (err) {
      expect(err).toBeInstanceOf(TimeoutError);
      expect((err as TimeoutError).label).toBe("llm_call");
      expect((err as TimeoutError).timeoutMs).toBe(10);
    }
  });

  it("propagates the original rejection (not a timeout)", async () => {
    const boom = Promise.reject(new Error("boom"));
    await expect(withTimeout(boom, 200, "x")).rejects.toThrow("boom");
  });

  it("a non-positive timeout disables the timeout", async () => {
    await expect(withTimeout(delay(20, "ok"), 0, "off")).resolves.toBe("ok");
  });
});
