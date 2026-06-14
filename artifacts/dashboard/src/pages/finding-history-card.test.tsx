import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, within } from "@testing-library/react";

// ---------------------------------------------------------------------------
// Render-level coverage for the finding-detail lifecycle timeline
// (FindingHistoryCard) — the browser-side mirror of the API-level guarantees in
// `artifacts/api-server/src/routes/findings.history.route.test.ts`.
//
// The route test proves the endpoint returns the right events, ordering, reason,
// actor and timestamp. This proves the React component actually *renders* those
// fields with the correct human labels, in the order the API hands them back,
// and — critically — that a regression in the component (a payload field rename,
// an empty-state bug, or a malformed/partial ledger payload) is caught instead
// of slipping through. The hook is mocked so we exercise the pure render path
// deterministically without a network/DB.
// ---------------------------------------------------------------------------

const mockUseGetFindingHistory = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useGetFindingHistory: (...args: unknown[]) => mockUseGetFindingHistory(...args),
  };
});

import { FindingHistoryCard } from "./finding-detail";

type HistoryEvent = {
  seq: number;
  ts: string;
  event_type: string;
  actor: Record<string, unknown>;
  payload: Record<string, unknown>;
};

function setHistory(data: unknown, isLoading = false) {
  mockUseGetFindingHistory.mockReturnValue({ data, isLoading });
}

beforeEach(() => {
  mockUseGetFindingHistory.mockReset();
});

describe("FindingHistoryCard", () => {
  it("renders resolve + reopen + break-glass events most-recent-first with label, actor, timestamp and reason", () => {
    // API returns most-recent-first (desc by seq). Reopen is the newest event.
    const events: HistoryEvent[] = [
      {
        seq: 40,
        ts: "2026-05-31T15:00:00.000Z",
        event_type: "finding.reopened",
        actor: { kind: "human", id: "analyst-reopen" },
        payload: { reason: "Closed by mistake during triage; still under investigation." },
      },
      {
        seq: 30,
        ts: "2026-05-31T14:00:00.000Z",
        event_type: "break_glass.granted",
        actor: { kind: "human", id: "analyst-bg" },
        payload: { justification: "Need raw evidence to confirm SSN exposure." },
      },
      {
        seq: 20,
        ts: "2026-05-31T13:00:00.000Z",
        event_type: "finding.resolved",
        actor: { kind: "human", id: "analyst-resolve" },
        payload: { status: "resolved" },
      },
      {
        seq: 10,
        ts: "2026-05-31T12:00:00.000Z",
        event_type: "finding.created",
        actor: { kind: "system", id: "ingest" },
        payload: {},
      },
    ];
    setHistory(events);

    render(<FindingHistoryCard findingId="f_test" />);

    // Human labels (not raw event types) are shown.
    expect(screen.getByText("Reopened")).toBeInTheDocument();
    expect(screen.getByText("Break-glass granted")).toBeInTheDocument();
    expect(screen.getByText("Closed out")).toBeInTheDocument();
    expect(screen.getByText("Finding created")).toBeInTheDocument();

    // Most-recent-first ordering: reopen precedes resolve in the rendered list.
    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(4);
    const order = items.map((li) => li.textContent ?? "");
    const reopenIdx = order.findIndex((t) => t.includes("Reopened"));
    const resolveIdx = order.findIndex((t) => t.includes("Closed out"));
    const createdIdx = order.findIndex((t) => t.includes("Finding created"));
    expect(reopenIdx).toBeLessThan(resolveIdx);
    expect(resolveIdx).toBeLessThan(createdIdx);

    // Reopen carries reason, actor and a formatted timestamp.
    const reopenItem = items[reopenIdx]!;
    expect(within(reopenItem).getByText(/Closed by mistake during triage/)).toBeInTheDocument();
    expect(reopenItem.textContent).toContain("analyst-reopen");
    expect(reopenItem.textContent).toContain("2026-05-31 15:00:00");

    // Break-glass justification surfaces as the note.
    const bgItem = items.find((li) => li.textContent?.includes("Break-glass granted"))!;
    expect(within(bgItem).getByText(/Need raw evidence to confirm SSN exposure/)).toBeInTheDocument();

    // The resolved status chip is shown.
    expect(screen.getByText("resolved")).toBeInTheDocument();
  });

  it("renders an auto-revoked break-glass close-out distinctly from a manual revoke", () => {
    // After a finding is closed out, its active break-glass grant is
    // automatically revoked and ledgered as `break_glass.revoked` with
    // `auto_revoked: true`. The History card must render that as
    // "Break-glass revoked" *with* the "auto-revoked" qualifier, so an auditor
    // can tell at a glance that access ended because of the close-out, not
    // because a human manually pulled it. The manual revoke (newest event) must
    // NOT carry the qualifier.
    const events: HistoryEvent[] = [
      {
        seq: 50,
        ts: "2026-05-31T16:00:00.000Z",
        event_type: "break_glass.revoked",
        actor: { kind: "human", id: "analyst-manual" },
        payload: { reason: "Pulled access manually; investigation paused." },
      },
      {
        seq: 40,
        ts: "2026-05-31T15:00:00.000Z",
        event_type: "break_glass.revoked",
        actor: { kind: "system", id: "auto-revoke" },
        payload: { auto_revoked: true, reason: "Finding closed out." },
      },
      {
        seq: 30,
        ts: "2026-05-31T14:30:00.000Z",
        event_type: "finding.resolved",
        actor: { kind: "human", id: "analyst-close" },
        payload: { status: "resolved" },
      },
      {
        seq: 20,
        ts: "2026-05-31T14:00:00.000Z",
        event_type: "break_glass.granted",
        actor: { kind: "human", id: "analyst-bg" },
        payload: { justification: "Need raw evidence to confirm SSN exposure." },
      },
      {
        seq: 10,
        ts: "2026-05-31T12:00:00.000Z",
        event_type: "finding.created",
        actor: { kind: "system", id: "ingest" },
        payload: {},
      },
    ];
    setHistory(events);

    render(<FindingHistoryCard findingId="f_autorevoke" />);

    // Both revokes render under the same human label.
    expect(screen.getAllByText("Break-glass revoked")).toHaveLength(2);

    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(5);

    // The auto-revoke entry (seq 40) carries the "auto-revoked" qualifier badge.
    const autoItem = items.find(
      (li) => li.textContent?.includes("Break-glass revoked") && li.textContent?.includes("Finding closed out."),
    )!;
    expect(autoItem).toBeTruthy();
    expect(within(autoItem).getByText("auto-revoked")).toBeInTheDocument();

    // The manual revoke (seq 50) renders without the qualifier.
    const manualItem = items.find((li) =>
      li.textContent?.includes("Pulled access manually"),
    )!;
    expect(manualItem).toBeTruthy();
    expect(within(manualItem).queryByText("auto-revoked")).not.toBeInTheDocument();

    // The qualifier appears exactly once across the whole timeline.
    expect(screen.getAllByText("auto-revoked")).toHaveLength(1);

    // Ordering is preserved most-recent-first: manual revoke before auto-revoke.
    const order = items.map((li) => li.textContent ?? "");
    const manualIdx = order.findIndex((t) => t.includes("Pulled access manually"));
    const autoIdx = order.findIndex((t) => t.includes("Finding closed out."));
    expect(manualIdx).toBeLessThan(autoIdx);
  });

  it("shows the empty state when there are no events", () => {
    setHistory([]);
    render(<FindingHistoryCard findingId="f_empty" />);
    expect(screen.getByText("No recorded events yet.")).toBeInTheDocument();
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
  });

  it("shows a loading skeleton while the history is fetching", () => {
    setHistory(undefined, true);
    const { container } = render(<FindingHistoryCard findingId="f_loading" />);
    expect(screen.queryByText("No recorded events yet.")).not.toBeInTheDocument();
    expect(screen.queryAllByRole("listitem")).toHaveLength(0);
    expect(container.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("renders malformed / partial ledger payloads without crashing", () => {
    // A corrupt/partial set of rows: invalid timestamp, missing actor, null
    // payload, unknown event type, and a missing-reason reopen. None of these
    // may throw — the page must degrade gracefully, not white-screen.
    const events = [
      {
        seq: 4,
        ts: "not-a-real-timestamp",
        event_type: "finding.reopened",
        actor: { kind: "human", id: "analyst-x" },
        payload: {}, // reopen with no reason
      },
      {
        seq: 3,
        ts: "2026-05-31T10:00:00.000Z",
        event_type: "some.unknown.event_type",
        actor: {},
        payload: { reason: "kept generic note" },
      },
      {
        seq: 2,
        ts: "2026-05-31T09:00:00.000Z",
        event_type: "finding.resolved",
        actor: null,
        payload: null,
      },
    ] as unknown as HistoryEvent[];
    setHistory(events);

    expect(() => render(<FindingHistoryCard findingId="f_bad" />)).not.toThrow();

    const items = screen.getAllByRole("listitem");
    expect(items).toHaveLength(3);
    // Invalid timestamp degrades to a placeholder instead of throwing.
    expect(screen.getByText(/unknown time/)).toBeInTheDocument();
    // Unknown event type falls back to showing the raw type, not a crash.
    expect(screen.getByText("some.unknown.event_type")).toBeInTheDocument();
    // Missing actor degrades to "system".
    expect(screen.getAllByText(/system/).length).toBeGreaterThan(0);
  });

  it("does not crash when the API returns a non-array payload", () => {
    setHistory({ unexpected: "shape" });
    expect(() => render(<FindingHistoryCard findingId="f_weird" />)).not.toThrow();
    expect(screen.getByText("No recorded events yet.")).toBeInTheDocument();
  });
});
