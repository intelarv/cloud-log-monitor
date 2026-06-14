import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Regression guard for the finding-detail break-glass grant POLL wiring.
//
// The live-notice poll reads `latestGrantRef.current` inside the
// `refetchInterval` closure passed to `useListBreakGlassGrants`. react-query
// evaluates that closure *synchronously* while constructing the QueryObserver
// during the first render — before the page's own effects run. If the ref is
// declared *after* the hook call, that first synchronous evaluation hits a
// temporal dead zone and the whole page crashes on mount with
//   "Cannot access 'latestGrantRef' before initialization".
//
// The sibling `finding-detail-break-glass-notice.test.tsx` mocks
// `useListBreakGlassGrants`, so its `refetchInterval` never runs and the crash
// slips through. This test deliberately uses the REAL grants hook (only the
// other heavy hooks + child modals are stubbed) so the real closure executes
// against a real QueryObserver — reproducing the mount path that an end-to-end
// run exercises. Before the ref was hoisted above the hook, this render threw.
// ---------------------------------------------------------------------------

const mockUseGetFinding = vi.fn();
const mockUseGetFindingHistory = vi.fn();
const mockUseGetFindingReviewHistory = vi.fn();
const mockToast = vi.fn();

// NOTE: useListBreakGlassGrants is intentionally NOT mocked — the real hook is
// what evaluates the refetchInterval closure under test.
vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useGetFinding: (...a: unknown[]) => mockUseGetFinding(...a),
    useGetFindingHistory: (...a: unknown[]) => mockUseGetFindingHistory(...a),
    useGetFindingReviewHistory: (...a: unknown[]) => mockUseGetFindingReviewHistory(...a),
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

import FindingDetail from "./finding-detail";

const finding = {
  id: "f1",
  fingerprint: "fp-1",
  severity: "critical",
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

beforeEach(() => {
  mockToast.mockReset();
  mockUseGetFinding.mockReturnValue({ data: finding, isLoading: false });
  mockUseGetFindingHistory.mockReturnValue({ data: [], isLoading: false });
  mockUseGetFindingReviewHistory.mockReturnValue({ data: { attempts: [], current_attempt: 0 }, isLoading: false });
  // The real grants hook will fetch on mount; keep it off the network by
  // returning an empty grant list. (The crash under test happens at render,
  // before this ever resolves.)
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("FindingDetail grant-poll wiring", () => {
  it("mounts without a temporal-dead-zone crash when the real grants hook evaluates refetchInterval", () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    // The assertion is simply that this render does not throw — the real
    // useListBreakGlassGrants + refetchInterval closure runs during mount.
    expect(() =>
      render(
        <QueryClientProvider client={client}>
          <FindingDetail />
        </QueryClientProvider>,
      ),
    ).not.toThrow();
    expect(screen.getByText(/Fingerprint/)).toBeInTheDocument();
  });
});
