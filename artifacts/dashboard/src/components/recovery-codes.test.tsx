import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ApiError } from "@workspace/api-client-react";

// ---------------------------------------------------------------------------
// Component-level coverage for the M29 backup / recovery codes panel — the
// browser side of the generate / regenerate / remove-factor management flow
// served by `routes/auth.ts` (factor management is 404 under the dev provider).
//
// Guards: (1) the panel renders NOTHING for the dev provider and while status
// loads, keeping the default / eval-gate surface unchanged; (2) without a
// verified factor it shows the "enroll first" hint and no generate button;
// (3) generate shows the plaintext codes exactly once; (4) a 401 from generate
// opens the hosted StepUpModal rather than erroring; (5) remove-factor calls the
// mutation. The hooks and toast are mocked; StepUpModal is stubbed so we assert
// the step-up handoff without driving a full ceremony.
// ---------------------------------------------------------------------------

const mockStatus = vi.fn();
const mockRecoveryStatus = vi.fn();
const mockGenerateMutate = vi.fn();
const mockRemoveMutate = vi.fn();
const mockToast = vi.fn();
const mockModal = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useStepUpStatus: () => mockStatus(),
    useStepUpRecoveryStatus: () => mockRecoveryStatus(),
    useStepUpRecoveryGenerate: () => ({
      mutateAsync: mockGenerateMutate,
      isPending: false,
    }),
    useStepUpFactorRemove: () => ({
      mutateAsync: mockRemoveMutate,
      isPending: false,
    }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

// Stub the modal: record props so we can assert it is opened, and expose a way
// to fire its onSuccess. The real ceremony is covered by step-up-modal tests.
vi.mock("./step-up-modal", () => ({
  default: (props: { open: boolean; reason: string; onSuccess: () => void }) => {
    mockModal(props);
    return props.open ? (
      <div data-testid="step-up-modal" data-reason={props.reason}>
        <button onClick={() => props.onSuccess()}>complete-step-up</button>
      </div>
    ) : null;
  },
}));

import RecoveryCodes from "./recovery-codes";

/** Build an ApiError with a given HTTP status (constructor takes a Response). */
function apiError(status: number, data: unknown): ApiError {
  return new ApiError(new Response(null, { status }), data, {
    method: "POST",
    url: "/api/auth/step-up/recovery/generate",
  });
}

function renderPanel() {
  const queryClient = new QueryClient();
  vi.spyOn(queryClient, "invalidateQueries").mockResolvedValue(
    undefined as never,
  );
  render(
    <QueryClientProvider client={queryClient}>
      <RecoveryCodes />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  mockRecoveryStatus.mockReturnValue({ data: undefined });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("RecoveryCodes", () => {
  it("renders nothing while status is loading", () => {
    mockStatus.mockReturnValue({ data: undefined, isLoading: true });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <RecoveryCodes />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for the dev provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "dev", enrolled: false, verified: false },
      isLoading: false,
    });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <RecoveryCodes />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("prompts to enroll a factor first when none is verified", () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: false, verified: false },
      isLoading: false,
    });
    renderPanel();
    expect(
      screen.getByText(/Enroll and verify a second factor/i),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /Generate backup codes/i }),
    ).not.toBeInTheDocument();
  });

  it("generates and shows the plaintext codes exactly once", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
      isLoading: false,
    });
    mockRecoveryStatus.mockReturnValue({
      data: { enabled: false, remaining: 0 },
    });
    mockGenerateMutate.mockResolvedValue({ codes: ["AAAA-BBBB", "CCCC-DDDD"] });

    renderPanel();
    fireEvent.click(
      screen.getByRole("button", { name: /Generate backup codes/i }),
    );

    await waitFor(() =>
      expect(screen.getByTestId("recovery-code-list")).toBeInTheDocument(),
    );
    expect(screen.getByText("AAAA-BBBB")).toBeInTheDocument();
    expect(screen.getByText("CCCC-DDDD")).toBeInTheDocument();

    // Dismiss the show-once panel.
    fireEvent.click(screen.getByRole("button", { name: /I've saved them/i }));
    await waitFor(() =>
      expect(screen.queryByTestId("recovery-code-list")).not.toBeInTheDocument(),
    );
  });

  it("shows remaining count and a regenerate action when codes already exist", () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
      isLoading: false,
    });
    mockRecoveryStatus.mockReturnValue({
      data: { enabled: true, remaining: 7 },
    });
    renderPanel();
    expect(screen.getByText("7 left")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Regenerate codes/i }),
    ).toBeInTheDocument();
  });

  it("opens the step-up modal when generate returns 401, then retries", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
      isLoading: false,
    });
    mockRecoveryStatus.mockReturnValue({
      data: { enabled: false, remaining: 0 },
    });
    mockGenerateMutate
      .mockRejectedValueOnce(apiError(401, { error: "step_up_required" }))
      .mockResolvedValueOnce({ codes: ["EEEE-FFFF"] });

    renderPanel();
    fireEvent.click(
      screen.getByRole("button", { name: /Generate backup codes/i }),
    );

    await waitFor(() =>
      expect(screen.getByTestId("step-up-modal")).toBeInTheDocument(),
    );
    expect(screen.getByTestId("step-up-modal")).toHaveAttribute(
      "data-reason",
      "Generate recovery codes",
    );

    // Completing the ceremony retries generate and surfaces the codes.
    fireEvent.click(screen.getByRole("button", { name: "complete-step-up" }));
    await waitFor(() =>
      expect(screen.getByText("EEEE-FFFF")).toBeInTheDocument(),
    );
    expect(mockGenerateMutate).toHaveBeenCalledTimes(2);
  });

  it("removes the second factor via the remove action", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
      isLoading: false,
    });
    mockRecoveryStatus.mockReturnValue({
      data: { enabled: true, remaining: 3 },
    });
    mockRemoveMutate.mockResolvedValue({ removed: true });

    renderPanel();
    fireEvent.click(
      screen.getByRole("button", { name: /Remove second factor/i }),
    );
    await waitFor(() => expect(mockRemoveMutate).toHaveBeenCalledTimes(1));
  });
});
