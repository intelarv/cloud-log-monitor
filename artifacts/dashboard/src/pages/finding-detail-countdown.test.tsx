import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, act } from "@testing-library/react";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Coverage for the finding-detail "emergency access countdown" (Task #111):
// while raw evidence is unlocked, a live-updating countdown shows the time
// remaining on the break-glass grant, and a non-intrusive notice warns the
// analyst shortly before the grant auto-expires.
//
// Two layers:
//   1. The pure `formatRemaining` helper — the M:SS / clamp math, tested in
//      isolation without timers.
//   2. A rendered FindingDetail integration test that unlocks raw evidence and
//      drives fake timers to assert the countdown ticks down and the warning
//      banner appears inside the warning threshold.
// ---------------------------------------------------------------------------

const mockUseGetFinding = vi.fn();
const mockUseGetFindingHistory = vi.fn();
const mockUseGetFindingReviewHistory = vi.fn();
const mockUseListBreakGlassGrants = vi.fn();
const mockToast = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useGetFinding: (...a: unknown[]) => mockUseGetFinding(...a),
    useGetFindingHistory: (...a: unknown[]) => mockUseGetFindingHistory(...a),
    useGetFindingReviewHistory: (...a: unknown[]) => mockUseGetFindingReviewHistory(...a),
    useListBreakGlassGrants: (...a: unknown[]) => mockUseListBreakGlassGrants(...a),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock("../components/layout", () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/break-glass-modal", () => ({ default: () => null }));
vi.mock("../components/resolve-finding-modal", () => ({ default: () => null }));
vi.mock("../components/reopen-finding-modal", () => ({ default: () => null }));
vi.mock("../components/re-review-finding-modal", () => ({ default: () => null }));

vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return { ...actual, useParams: () => ({ id: "f1" }) };
});

import FindingDetail, { formatRemaining, EXPIRY_WARNING_THRESHOLD_MS } from "./finding-detail";

describe("formatRemaining", () => {
  it("formats whole minutes and seconds as M:SS", () => {
    expect(formatRemaining(90_000)).toBe("1:30");
    expect(formatRemaining(60_000)).toBe("1:00");
  });
  it("zero-pads the seconds component", () => {
    expect(formatRemaining(65_000)).toBe("1:05");
    expect(formatRemaining(9_000)).toBe("0:09");
  });
  it("rounds up partial seconds so a fresh tick never shows one second short", () => {
    expect(formatRemaining(29_400)).toBe("0:30");
  });
  it("clamps negative/zero durations to 0:00", () => {
    expect(formatRemaining(0)).toBe("0:00");
    expect(formatRemaining(-5_000)).toBe("0:00");
  });
});

const finding = {
  id: "f1",
  fingerprint: "fp-1",
  severity: "high",
  status: "open",
  classification: "phi",
  subclass: null,
  source: "billing-svc",
  detector_version: "d1",
  occurrence_count: 1,
  first_seen_at: "2026-06-13T11:00:00.000Z",
  last_seen_at: "2026-06-13T11:30:00.000Z",
  redacted_evidence: { snippet: "redacted", redactions: [], trust: "untrusted" },
};

const NOW = new Date("2026-06-13T12:00:00.000Z").getTime();

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <FindingDetail />
    </QueryClientProvider>,
  );
}

// Unlock raw evidence by clicking "Break Glass": the page calls fetch() on the
// raw endpoint, which we stub to succeed with a grant expiry `secondsLeft` from
// the fake-clock NOW.
async function unlockWithExpiry(secondsLeft: number) {
  const expiresAt = new Date(NOW + secondsLeft * 1000).toISOString();
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ raw_evidence: { snippet: "SSN 123-45-6789" }, grant_expires_at: expiresAt }),
    }),
  );
  const button = screen.getByRole("button", { name: /Break Glass/i });
  await act(async () => {
    button.click();
  });
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  mockToast.mockReset();
  mockUseGetFinding.mockReturnValue({ data: finding, isLoading: false });
  mockUseGetFindingHistory.mockReturnValue({ data: [], isLoading: false });
  mockUseGetFindingReviewHistory.mockReturnValue({ data: { attempts: [], current_attempt: 0 }, isLoading: false });
  mockUseListBreakGlassGrants.mockReturnValue({ data: [] });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("FindingDetail emergency access countdown", () => {
  it("shows a live countdown that ticks down once per second while unlocked", async () => {
    renderPage();
    await unlockWithExpiry(120); // 2:00 remaining

    expect(screen.getByText("Access expires in 2:00")).toBeTruthy();

    // Advance the clock 5 seconds; the interval re-renders the timer.
    await act(async () => {
      vi.advanceTimersByTime(5_000);
    });
    expect(screen.getByText("Access expires in 1:55")).toBeTruthy();
  });

  it("does not show the warning banner while comfortably above the threshold", async () => {
    renderPage();
    await unlockWithExpiry(120);
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("surfaces a non-intrusive warning inside the final 30s before expiry", async () => {
    renderPage();
    await unlockWithExpiry(EXPIRY_WARNING_THRESHOLD_MS / 1000 + 5); // 35s left, no warning yet
    expect(screen.queryByRole("status")).toBeNull();

    // Tick past the threshold (down to ~25s): warning appears.
    await act(async () => {
      vi.advanceTimersByTime(10_000);
    });
    const warning = screen.getByRole("status");
    expect(warning.textContent).toMatch(/Emergency access expires in/);
  });

  it("offers a one-click re-request action inside the expiry warning (Task #113)", async () => {
    renderPage();
    await unlockWithExpiry(EXPIRY_WARNING_THRESHOLD_MS / 1000 - 5); // 25s left, warning shown
    const warning = screen.getByRole("status");
    const button = screen.getByRole("button", { name: /Re-request access/i });
    expect(warning.contains(button)).toBe(true);
  });

  it("does not show the re-request action before the warning threshold", async () => {
    renderPage();
    await unlockWithExpiry(120);
    expect(screen.queryByRole("button", { name: /Re-request access/i })).toBeNull();
  });

  it("shows an expired state once the countdown reaches zero", async () => {
    renderPage();
    await unlockWithExpiry(3);
    await act(async () => {
      vi.advanceTimersByTime(4_000);
    });
    expect(screen.getByText("Access expired")).toBeTruthy();
    expect(screen.queryByRole("status")).toBeNull();
  });

  it("falls back to the absolute timestamp when the expiry is malformed", async () => {
    renderPage();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ raw_evidence: { snippet: "x" }, grant_expires_at: "not-a-date" }),
      }),
    );
    const button = screen.getByRole("button", { name: /Break Glass/i });
    await act(async () => {
      button.click();
    });
    expect(screen.getByText(/^Expires /)).toBeTruthy();
  });
});
