import { describe, it, expect } from "vitest";
import { safeTimestamp, safeRelativeTime } from "./format";

// These helpers are the dashboard's last line of defense against a single
// malformed timestamp white-screening an entire page (findings list, audit
// ledger, finding detail). Every branch that could otherwise reach date-fns
// with an invalid Date must degrade to the placeholder instead of throwing.

describe("safeTimestamp", () => {
  it("formats a valid ISO string with the default pattern", () => {
    expect(safeTimestamp("2026-06-03T01:54:15.000Z")).toMatch(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/,
    );
  });

  it("honors a custom date-fns format string", () => {
    expect(safeTimestamp("2026-06-03T01:54:15.000Z", "HH:mm:ss")).toMatch(
      /^\d{2}:\d{2}:\d{2}$/,
    );
  });

  it.each([
    ["a malformed string", "not-a-date"],
    ["an empty string", ""],
    ["null", null],
    ["undefined", undefined],
    ["a number", 1780451651938],
    ["an object", { ts: "2026-06-03" }],
    ["NaN", Number.NaN],
  ])("returns the placeholder for %s instead of throwing", (_label, value) => {
    expect(() => safeTimestamp(value as unknown)).not.toThrow();
    expect(safeTimestamp(value as unknown)).toBe("unknown time");
  });
});

describe("safeRelativeTime", () => {
  it("formats a valid ISO string as a relative, suffixed phrase", () => {
    expect(safeRelativeTime(new Date().toISOString())).toMatch(/ago$/);
  });

  it.each([
    ["a malformed string", "nope"],
    ["an empty string", ""],
    ["null", null],
    ["undefined", undefined],
    ["a number", 0],
  ])("returns the placeholder for %s instead of throwing", (_label, value) => {
    expect(() => safeRelativeTime(value as unknown)).not.toThrow();
    expect(safeRelativeTime(value as unknown)).toBe("unknown time");
  });
});
