import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the finding-detail "Break-Glass" (emergency
// raw-PHI access) action — the browser-side mirror of the HTTP/route
// guarantees in `artifacts/api-server/src/routes/admin.ts`
// (POST /admin/break-glass/grants).
//
// Exercises the full justification -> submit -> grant -> query-invalidation
// wiring BreakGlassModal drives, deterministically without a network/DB (the
// mutation hook + toast are mocked). It specifically guards the regression
// that the finding + History card queries must be refreshed after a
// successful grant (the break-glass modal MUST invalidate
// getGetFindingQueryKey and getGetFindingHistoryQueryKey, matching the
// resolve/reopen modals), plus the success-callback wiring and the error
// path. The live end-to-end browser flow is additionally covered by the
// Playwright testing subagent.
// ---------------------------------------------------------------------------

const mockMutateAsync = vi.fn();
const mockToast = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useCreateBreakGlassGrant: () => ({ mutateAsync: mockMutateAsync, isPending: false }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

// The step-up modal is unrelated to the refresh behaviour under test and pulls
// in its own mutation hooks; stub it to a noop so the break-glass modal renders
// in isolation.
vi.mock("./step-up-modal", () => ({
  default: () => null,
}));

import BreakGlassModal from "./break-glass-modal";
import {
  getGetFindingHistoryQueryKey,
  getGetFindingQueryKey,
  getListBreakGlassGrantsQueryKey,
} from "@workspace/api-client-react";

function renderModal(findingId = "f1", defaultJustification?: string) {
  const queryClient = new QueryClient();
  const invalidateSpy = vi
    .spyOn(queryClient, "invalidateQueries")
    .mockResolvedValue(undefined as never);
  const onOpenChange = vi.fn();
  const onSuccess = vi.fn();
  render(
    <QueryClientProvider client={queryClient}>
      <BreakGlassModal
        open
        onOpenChange={onOpenChange}
        findingId={findingId}
        onSuccess={onSuccess}
        defaultJustification={defaultJustification}
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

const justificationInput = () =>
  screen.getByPlaceholderText("e.g., Incident IR-1042 investigation");
const requestButton = () => screen.getByRole("button", { name: /Request Access/ });

beforeEach(() => {
  mockMutateAsync.mockReset();
  mockToast.mockReset();
});

describe("BreakGlassModal (Break-Glass)", () => {
  it("renders the break-glass form", () => {
    renderModal();
    expect(screen.getByText("Break-Glass Procedure")).toBeInTheDocument();
    expect(justificationInput()).toBeInTheDocument();
    expect(requestButton()).toBeInTheDocument();
  });

  it("grants access: submits the justification, invalidates finding + history, and reports success", async () => {
    mockMutateAsync.mockResolvedValue({ id: "grant-1" });
    const { invalidateSpy, onSuccess } = renderModal("f1");

    fireEvent.change(justificationInput(), {
      target: { value: "Incident IR-1042 investigation" },
    });
    fireEvent.click(requestButton());

    await waitFor(() =>
      expect(mockMutateAsync).toHaveBeenCalledWith({
        data: {
          finding_id: "f1",
          justification: "Incident IR-1042 investigation",
          ttl_seconds: 300,
        },
      }),
    );

    // Regression guard: the finding + History card queries must be invalidated
    // so the new emergency-access grant shows on the timeline without a manual
    // page reload.
    const keys = invalidatedKeys(invalidateSpy);
    expect(keys).toContain(JSON.stringify(getGetFindingQueryKey("f1")));
    expect(keys).toContain(JSON.stringify(getGetFindingHistoryQueryKey("f1")));

    // Regression guard: the analyst's own grants LIST query must also be
    // invalidated. finding-detail arms its live-notice poll off that list — if
    // it is not refreshed, its grant stays null, the refetchInterval predicate
    // stays false, polling never starts, and an analyst who keeps the tab
    // focused never receives the approve/revoke toast without reloading.
    expect(keys).toContain(JSON.stringify(getListBreakGlassGrantsQueryKey()));

    await waitFor(() => expect(onSuccess).toHaveBeenCalledWith({ id: "grant-1" }));
  });

  it("prefills the justification when re-requesting access (Task #113)", () => {
    renderModal("f1", "Incident IR-1042 investigation");
    expect((justificationInput() as HTMLInputElement).value).toBe(
      "Incident IR-1042 investigation",
    );
  });

  it("starts with an empty justification when none is carried over", () => {
    renderModal("f1");
    expect((justificationInput() as HTMLInputElement).value).toBe("");
  });

  it("does not invalidate or report success on failure", async () => {
    mockMutateAsync.mockRejectedValue(new Error("boom"));
    const { invalidateSpy, onSuccess } = renderModal("f2");

    fireEvent.change(justificationInput(), {
      target: { value: "Incident IR-2099 investigation" },
    });
    fireEvent.click(requestButton());

    await waitFor(() => expect(mockToast).toHaveBeenCalled());
    expect(mockToast.mock.calls[0][0].title).toBe("Break-glass request failed");
    expect(mockToast.mock.calls[0][0].variant).toBe("destructive");

    const keys = invalidatedKeys(invalidateSpy);
    expect(keys).not.toContain(JSON.stringify(getGetFindingQueryKey("f2")));
    expect(keys).not.toContain(JSON.stringify(getGetFindingHistoryQueryKey("f2")));
    expect(onSuccess).not.toHaveBeenCalled();
  });
});
