import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the finding-detail "Reopen" action — the
// browser-side mirror of the HTTP/route guarantees in
// `artifacts/api-server/src/routes/admin.ts` (POST /admin/findings/:id/reopen).
//
// Exercises the full button -> (optional reason) -> submit -> toast ->
// query-invalidation wiring ReopenFindingModal drives, deterministically without
// a network/DB (the mutation hook + toast are mocked). It covers reopening WITH
// and WITHOUT a reason note, the idempotent "Already open" path, and the error
// path, and guards the regression that the History card must be refreshed after
// a reopen (the reopen modal MUST invalidate getGetFindingHistoryQueryKey,
// matching the re-review modal). The live end-to-end browser flow is
// additionally covered by the Playwright testing subagent.
// ---------------------------------------------------------------------------

const mockMutateAsync = vi.fn();
const mockToast = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useReopenFinding: () => ({ mutateAsync: mockMutateAsync, isPending: false }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

import ReopenFindingModal from "./reopen-finding-modal";
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
  render(
    <QueryClientProvider client={queryClient}>
      <ReopenFindingModal open onOpenChange={onOpenChange} findingId={findingId} />
    </QueryClientProvider>,
  );
  return { invalidateSpy, onOpenChange };
}

function invalidatedKeys(invalidateSpy: ReturnType<typeof vi.spyOn>) {
  return invalidateSpy.mock.calls.map((c: unknown[]) =>
    JSON.stringify((c[0] as { queryKey?: unknown } | undefined)?.queryKey),
  );
}

const reopenButton = () => screen.getByRole("button", { name: "Reopen" });

beforeEach(() => {
  mockMutateAsync.mockReset();
  mockToast.mockReset();
});

describe("ReopenFindingModal (Reopen)", () => {
  it("renders the reopen form", () => {
    renderModal();
    expect(screen.getByText("Reopen finding")).toBeInTheDocument();
    expect(screen.getByRole("textbox")).toBeInTheDocument();
    expect(reopenButton()).toBeInTheDocument();
  });

  it("reopens with a reason: sends the reason, invalidates history, toasts, and closes", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true });
    const { invalidateSpy, onOpenChange } = renderModal("f1");

    fireEvent.change(screen.getByRole("textbox"), {
      target: { value: "Closed by mistake during triage" },
    });
    fireEvent.click(reopenButton());

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({
        id: "f1",
        data: { reason: "Closed by mistake during triage" },
      }),
    );
    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Finding reopened");

    // Regression guard: the History card query must be invalidated so the
    // "Reopened" entry shows without a manual page reload.
    const keys = invalidatedKeys(invalidateSpy);
    expect(keys).toContain(JSON.stringify(getGetFindingHistoryQueryKey("f1")));
    expect(keys).toContain(JSON.stringify(getGetFindingQueryKey("f1")));
    expect(keys).toContain(JSON.stringify(getListFindingsQueryKey()));

    await waitFor(() => expect(onOpenChange).toHaveBeenCalledWith(false));
  });

  it("reopens without a reason: sends undefined data", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true });
    renderModal("f2");

    fireEvent.click(reopenButton());

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({ id: "f2", data: undefined }),
    );
    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Finding reopened");
  });

  it("trims a whitespace-only reason down to no note", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: true });
    renderModal("f3");

    fireEvent.change(screen.getByRole("textbox"), { target: { value: "   " } });
    fireEvent.click(reopenButton());

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({ id: "f3", data: undefined }),
    );
  });

  it("surfaces the already-open message when no transition occurs", async () => {
    mockMutateAsync.mockResolvedValue({ transitioned: false });
    renderModal("f4");

    fireEvent.click(reopenButton());

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Already open");
  });

  it("shows a destructive toast and keeps the modal open on failure", async () => {
    mockMutateAsync.mockRejectedValue(new Error("nope"));
    const { onOpenChange } = renderModal("f5");

    fireEvent.click(reopenButton());

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Could not reopen finding");
    expect(mockToast.mock.calls[0][0].variant).toBe("destructive");
    expect(onOpenChange).not.toHaveBeenCalledWith(false);
  });
});
