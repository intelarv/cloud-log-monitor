import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the finding-detail "Close Out" (resolve) action
// — the browser-side mirror of the HTTP/route guarantees in
// `artifacts/api-server/src/routes/admin.ts` (POST /admin/findings/:id/resolve).
//
// This exercises the full button -> submit -> toast -> query-invalidation wiring
// that the Close Out button drives via ResolveFindingModal, deterministically and
// without a network/DB (the mutation hook + toast are mocked). It specifically
// guards the regression that the History card must be refreshed after a close-out
// (the resolve modal MUST invalidate getGetFindingHistoryQueryKey, matching the
// re-review modal), plus the auto-revoke-on-close toast variant and the error
// path. The live end-to-end browser flow is additionally covered by the
// Playwright testing subagent.
// ---------------------------------------------------------------------------

const mockMutateAsync = vi.fn();
const mockToast = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useResolveFinding: () => ({ mutateAsync: mockMutateAsync, isPending: false }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

import ResolveFindingModal from "./resolve-finding-modal";
import {
  getGetFindingHistoryQueryKey,
  getGetFindingQueryKey,
  getListFindingsQueryKey,
} from "@workspace/api-client-react";

function renderModal(findingId = "f1") {
  const queryClient = new QueryClient();
  const invalidateSpy = vi
    .spyOn(queryClient, "invalidateQueries")
    .mockResolvedValue(undefined as never);
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(
    <QueryClientProvider client={queryClient}>
      <ResolveFindingModal
        open
        onOpenChange={onOpenChange}
        findingId={findingId}
        onSuccess={onSuccess}
      />
    </QueryClientProvider>,
  );
  return { invalidateSpy, onOpenChange, onSuccess };
}

function invalidatedKeys(invalidateSpy: ReturnType<typeof vi.spyOn>) {
  return invalidateSpy.mock.calls.map((c: unknown[]) =>
    JSON.stringify((c[0] as { queryKey?: unknown } | undefined)?.queryKey),
  );
}

beforeEach(() => {
  mockMutateAsync.mockReset();
  mockToast.mockReset();
});

describe("ResolveFindingModal (Close Out)", () => {
  it("renders the resolve options", () => {
    renderModal();
    expect(screen.getByText("Close out finding")).toBeInTheDocument();
    expect(screen.getByText("Resolved")).toBeInTheDocument();
    expect(screen.getByText("False positive")).toBeInTheDocument();
  });

  it("closes a finding as resolved: submits status, invalidates history, toasts, and closes", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true, revoked_grants: 0 });
    const { invalidateSpy, onOpenChange } = renderModal("f1");

    fireEvent.click(screen.getByText("Resolved"));

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({ id: "f1", data: { status: "resolved" } }),
    );
    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Finding marked resolved");

    // Regression guard: the History card query must be invalidated so the
    // "Closed out" entry shows without a manual page reload.
    const keys = invalidatedKeys(invalidateSpy);
    expect(keys).toContain(JSON.stringify(getGetFindingHistoryQueryKey("f1")));
    expect(keys).toContain(JSON.stringify(getGetFindingQueryKey("f1")));
    expect(keys).toContain(JSON.stringify(getListFindingsQueryKey()));

    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });

  it("closes a finding as a false positive", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true, revoked_grants: 0 });
    renderModal("f2");

    fireEvent.click(screen.getByText("False positive"));

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({
        id: "f2",
        data: { status: "false_positive" },
      }),
    );
    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Finding marked false positive");
  });

  it("reports automatically revoked emergency-access grants in the toast", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true, revoked_grants: 2 });
    renderModal("f3");

    fireEvent.click(screen.getByText("Resolved"));

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].description).toContain(
      "2 active emergency-access grants were",
    );
  });

  // Security-relevant variant (Task #104): closing out a finding that has a
  // SINGLE active break-glass grant must report it was automatically revoked,
  // with singular wording, and propagate the revoked count to onSuccess so the
  // detail page can react (e.g. drop a now-stale "Raw Unlocked" affordance).
  // The live UI -> real backend -> DB-revoke flow is additionally covered by the
  // Playwright testing subagent; the real HTTP/DB/ledger path by
  // artifacts/api-server/src/routes/admin.auto-revoke.route.test.ts.
  it("reports a single auto-revoked grant with singular wording and forwards the count to onSuccess", async () => {
    const result = { transitioned: true, revoked_grants: 1 };
    mockMutateAsync.mockResolvedValue(result);
    const { onSuccess, onOpenChange } = renderModal("f6");

    fireEvent.click(screen.getByText("Resolved"));

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Finding marked resolved");
    expect(mockToast.mock.calls[0][0].description).toBe(
      "1 active emergency-access grant was automatically revoked.",
    );
    // The auto-revoke outcome is handed back to the caller (count > 0) and the
    // modal closes itself on success.
    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith(result));
    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });

  it("surfaces the already-in-state message when no transition occurs", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: false, revoked_grants: 0 });
    renderModal("f4");

    fireEvent.click(screen.getByText("Resolved"));

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Already resolved");
  });

  it("shows a destructive toast and keeps the modal open on failure", async () => {
    mockMutateAsync.mockRejectedValue(new Error("boom"));
    const { onOpenChange } = renderModal("f5");

    fireEvent.click(screen.getByText("Resolved"));

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Could not close out finding");
    expect(mockToast.mock.calls[0][0].variant).toBe("destructive");
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });
});
