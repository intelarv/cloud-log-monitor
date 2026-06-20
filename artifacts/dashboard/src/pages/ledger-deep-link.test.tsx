import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen } from "@testing-library/react";
import { QueryClientProvider, QueryClient } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Coverage for the Audit Ledger deep-link behavior (Task #72): a `?seq=<n>`
// query param (e.g. from a finding's history timeline) must FETCH and SHOW the
// targeted entry even when it falls outside the default most-recent window.
//
// The page widens its initial fetch cursor so the target row is loaded, then
// auto-expands + highlights it. If the target genuinely doesn't exist for the
// tenant (or is unreachable), the page must surface an explicit "not in the
// current view" notice rather than silently rendering the list with nothing
// highlighted. Both branches are exercised here against the real component with
// only the data hooks + Layout stubbed (no network/DB).
//
// scrollIntoView is not implemented in jsdom; stub it so the deep-link effect
// (which scrolls the target into view) doesn't throw during render.
// ---------------------------------------------------------------------------

const mockUseListLedger = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useListLedger: (...a: unknown[]) => mockUseListLedger(...a),
    useVerifyLedger: () => ({ data: undefined, refetch: vi.fn(), isFetching: false }),
    useListLedgerCheckpoints: () => ({
      data: undefined,
      refetch: vi.fn(),
      isFetching: false,
    }),
  };
});

vi.mock("../components/layout", () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

let mockSearch = "";
vi.mock("wouter", async (importOriginal) => {
  const actual = await importOriginal<typeof import("wouter")>();
  return { ...actual, useSearch: () => mockSearch };
});

import Ledger from "./ledger";

function entry(seq: number) {
  return {
    seq,
    ts: "2026-01-02T03:04:05.000Z",
    event_type: "finding.created",
    actor: { kind: "system", id: "ingest" },
    subject_type: "finding",
    subject_id: `finding-${seq}-abcdef01`,
    hash: `hash${seq}deadbeefcafef00d`,
    prev_hash: `prev${seq}`,
    payload: { note: `entry ${seq}` },
  };
}

function renderLedger() {
  const queryClient = new QueryClient();
  return render(
    <QueryClientProvider client={queryClient}>
      <Ledger />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  mockUseListLedger.mockReset();
  mockSearch = "";
  // jsdom has no layout engine; stub scrollIntoView so the deep-link effect
  // doesn't throw during render.
  window.HTMLElement.prototype.scrollIntoView = vi.fn();
});

describe("Ledger deep-link (?seq=)", () => {
  it("widens the fetch and shows an out-of-window target entry, auto-expanded", () => {
    // Target seq 7 would be far below the default most-recent head; the page
    // must request a window centered on it. We assert it (a) asks the server
    // with a cursor at/below the target, and (b) renders + expands the row.
    mockSearch = "seq=7";
    mockUseListLedger.mockReturnValue({
      data: { entries: [entry(5), entry(6), entry(7), entry(8)] },
      isFetching: false,
    });

    renderLedger();

    // The fetch cursor (after_seq) must be below the target so the target is
    // inside the loaded page — i.e. the page widened the window for the deep link.
    const firstCallArgs = mockUseListLedger.mock.calls[0]?.[0] as {
      after_seq: number;
      limit: number;
    };
    expect(firstCallArgs.after_seq).toBeLessThan(7);

    // The target row is rendered (seq cell) and its payload is auto-expanded.
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText(/"note": "entry 7"/)).toBeInTheDocument();
    // The "not in view" notice must NOT show when the target is present.
    expect(
      screen.queryByText(/is not in the current view/),
    ).not.toBeInTheDocument();
  });

  it("surfaces a notice when the deep-link target is not present in the loaded window", () => {
    mockSearch = "seq=999";
    mockUseListLedger.mockReturnValue({
      data: { entries: [entry(10), entry(11), entry(12)] },
      isFetching: false,
    });

    renderLedger();

    expect(
      screen.getByText(/Entry #999 is not in the current view/),
    ).toBeInTheDocument();
  });
});
