import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, within, fireEvent } from "@testing-library/react";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Coverage for the finding-detail PERSISTENT access-change banner (Task #116):
// when a finding the analyst is viewing has its emergency-access grant approved
// or revoked/expired *by someone else*, the page must show an inline notice
// that STAYS VISIBLE until acknowledged — not just a ~5s toast that can be
// missed. Mirrors `finding-detail-toast-render.test.tsx` but asserts the banner
// persists, is visually distinct for cut-off vs granted, and is dismissible.
// ---------------------------------------------------------------------------

const mockUseGetFinding = vi.fn();
const mockUseGetFindingHistory = vi.fn();
const mockUseGetFindingReviewHistory = vi.fn();
const mockUseListBreakGlassGrants = vi.fn();

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

// The transient toast is irrelevant to the banner — stub it out so this test
// isolates the persistent inline notice.
vi.mock("@/hooks/use-toast", () => ({ useToast: () => ({ toast: vi.fn() }) }));

vi.mock("../components/layout", () => ({ default: ({ children }: { children: React.ReactNode }) => <div>{children}</div> }));
vi.mock("../components/break-glass-modal", () => ({ default: () => null }));
vi.mock("../components/resolve-finding-modal", () => ({ default: () => null }));
vi.mock("../components/reopen-finding-modal", () => ({ default: () => null }));
vi.mock("../components/re-review-finding-modal", () => ({ default: () => null }));

vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return { ...actual, useParams: () => ({ id: "f1" }) };
});

import FindingDetail, { AccessChangeBanner } from "./finding-detail";
import type { BreakGlassGrant } from "@workspace/api-client-react";

function grant(overrides: Partial<BreakGlassGrant>): BreakGlassGrant {
  return {
    id: "g1",
    tenant_id: "t1",
    user_id: "u1",
    finding_id: "f1",
    justification: "Incident IR-1042",
    granted_at: "2026-06-13T12:00:00.000Z",
    expires_at: "2999-01-01T00:00:00.000Z",
    revoked_at: null,
    requires_second_approval: true,
    approver_user_id: null,
    approved_at: null,
    pending_approval: false,
    active: true,
    ...overrides,
  };
}

function setGrants(grants: BreakGlassGrant[] | undefined) {
  mockUseListBreakGlassGrants.mockReturnValue({ data: grants });
}

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

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  // A fresh element on every (re)render: React bails out of re-rendering when
  // handed a referentially-identical element, which would stop FindingDetail's
  // transition effect from ever re-running.
  const tree = () => (
    <QueryClientProvider client={client}>
      <FindingDetail />
    </QueryClientProvider>
  );
  const utils = render(tree());
  return { ...utils, rerender: () => utils.rerender(tree()) };
}

beforeEach(() => {
  mockUseGetFinding.mockReturnValue({ data: finding, isLoading: false });
  mockUseGetFindingHistory.mockReturnValue({ data: [], isLoading: false });
  mockUseGetFindingReviewHistory.mockReturnValue({ data: { attempts: [], current_attempt: 0 }, isLoading: false });
  setGrants([]);
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false, json: async () => ({}) }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("AccessChangeBanner", () => {
  it("renders approved as a non-destructive status banner", () => {
    render(<AccessChangeBanner notice="approved" onDismiss={() => {}} />);
    const banner = screen.getByTestId("break-glass-access-banner");
    expect(banner).toHaveAttribute("data-variant", "approved");
    expect(banner).toHaveAttribute("role", "status");
    expect(within(banner).getByText("Break-glass access approved")).toBeInTheDocument();
  });

  it("renders revoked and expired as destructive alert banners", () => {
    const { rerender } = render(<AccessChangeBanner notice="revoked" onDismiss={() => {}} />);
    let banner = screen.getByTestId("break-glass-access-banner");
    expect(banner).toHaveAttribute("data-variant", "destructive");
    expect(banner).toHaveAttribute("role", "alert");
    expect(within(banner).getByText("Break-glass access revoked")).toBeInTheDocument();

    rerender(<AccessChangeBanner notice="expired" onDismiss={() => {}} />);
    banner = screen.getByTestId("break-glass-access-banner");
    expect(banner).toHaveAttribute("data-variant", "destructive");
    expect(within(banner).getByText("Break-glass access expired")).toBeInTheDocument();
  });
});

describe("FindingDetail persistent access-change banner", () => {
  it("shows a non-destructive banner that PERSISTS when a pending grant becomes active", async () => {
    setGrants([grant({ pending_approval: true })]);
    const { rerender } = renderPage();
    expect(screen.queryByTestId("break-glass-access-banner")).not.toBeInTheDocument();

    // A second analyst approves: pending -> active.
    setGrants([grant({ pending_approval: false, approved_at: "2026-06-13T12:05:00.000Z" })]);
    rerender();

    const banner = await screen.findByTestId("break-glass-access-banner");
    expect(banner).toHaveAttribute("data-variant", "approved");
    expect(within(banner).getByText("Break-glass access approved")).toBeInTheDocument();

    // It must NOT auto-dismiss: still present after several re-renders / time.
    await new Promise((r) => setTimeout(r, 50));
    rerender();
    expect(screen.getByTestId("break-glass-access-banner")).toBeInTheDocument();
  });

  it("shows a destructive banner that PERSISTS when an active grant is revoked", async () => {
    setGrants([grant({ pending_approval: false })]);
    const { rerender } = renderPage();
    expect(screen.queryByTestId("break-glass-access-banner")).not.toBeInTheDocument();

    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();

    const banner = await screen.findByTestId("break-glass-access-banner");
    expect(banner).toHaveAttribute("data-variant", "destructive");
    expect(within(banner).getByText("Break-glass access revoked")).toBeInTheDocument();

    await new Promise((r) => setTimeout(r, 50));
    rerender();
    expect(screen.getByTestId("break-glass-access-banner")).toBeInTheDocument();
  });

  it("does not show a banner on first observation of a grant", async () => {
    setGrants([grant({ pending_approval: true })]);
    renderPage();
    await screen.findByText(/Fingerprint/);
    expect(screen.queryByTestId("break-glass-access-banner")).not.toBeInTheDocument();
  });

  it("dismisses the banner only when the analyst acknowledges it", async () => {
    setGrants([grant({ pending_approval: false })]);
    const { rerender } = renderPage();

    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();

    await screen.findByTestId("break-glass-access-banner");
    fireEvent.click(screen.getByRole("button", { name: /dismiss break-glass access notice/i }));

    await waitFor(() =>
      expect(screen.queryByTestId("break-glass-access-banner")).not.toBeInTheDocument(),
    );
  });

  it("STACKS successive access changes instead of overwriting the previous one", async () => {
    // A busy two-analyst incident: pending grant is approved, then revoked in
    // quick succession. Both transitions must remain visible as their own entry.
    setGrants([grant({ pending_approval: true })]);
    const { rerender } = renderPage();

    // 1. Second analyst approves: pending -> active.
    setGrants([grant({ pending_approval: false, approved_at: "2026-06-13T12:05:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access approved");

    // 2. Then revokes: active -> revoked.
    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access revoked");

    // Both banners coexist — the revoke did not overwrite the approval notice.
    const banners = screen.getAllByTestId("break-glass-access-banner");
    expect(banners).toHaveLength(2);
    expect(screen.getByText("Break-glass access approved")).toBeInTheDocument();
    expect(screen.getByText("Break-glass access revoked")).toBeInTheDocument();
    // Newest first: the revoke (destructive) is stacked above the approval.
    expect(banners[0]).toHaveAttribute("data-variant", "destructive");
    expect(banners[1]).toHaveAttribute("data-variant", "approved");
  });

  it("dismisses one stacked entry individually without affecting the others", async () => {
    setGrants([grant({ pending_approval: true })]);
    const { rerender } = renderPage();

    setGrants([grant({ pending_approval: false, approved_at: "2026-06-13T12:05:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access approved");

    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access revoked");

    expect(screen.getAllByTestId("break-glass-access-banner")).toHaveLength(2);

    // Dismiss only the newest (revoked) entry — the approval must remain.
    const dismissButtons = screen.getAllByRole("button", {
      name: /dismiss break-glass access notice/i,
    });
    fireEvent.click(dismissButtons[0]);

    await waitFor(() =>
      expect(screen.queryByText("Break-glass access revoked")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("Break-glass access approved")).toBeInTheDocument();
    expect(screen.getAllByTestId("break-glass-access-banner")).toHaveLength(1);
  });

  it("clears every stacked entry with Dismiss all", async () => {
    setGrants([grant({ pending_approval: true })]);
    const { rerender } = renderPage();

    setGrants([grant({ pending_approval: false, approved_at: "2026-06-13T12:05:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access approved");

    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();
    await screen.findByText("Break-glass access revoked");

    expect(screen.getAllByTestId("break-glass-access-banner")).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: /dismiss all/i }));

    await waitFor(() =>
      expect(screen.queryByTestId("break-glass-access-banner")).not.toBeInTheDocument(),
    );
  });

  it("shows no Dismiss all control for a single access change", async () => {
    setGrants([grant({ pending_approval: false })]);
    const { rerender } = renderPage();

    setGrants([grant({ pending_approval: false, revoked_at: "2026-06-13T12:10:00.000Z" })]);
    rerender();

    await screen.findByTestId("break-glass-access-banner");
    expect(screen.queryByRole("button", { name: /dismiss all/i })).not.toBeInTheDocument();
  });
});
