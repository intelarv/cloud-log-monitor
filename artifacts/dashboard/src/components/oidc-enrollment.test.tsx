import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the IdP-federated (OIDC) step-up enrollment panel
// — the browser-side mirror of the register/begin -> IdP popup -> register/finish
// link ceremony served by `artifacts/api-server/src/routes/auth.ts`
// (STEP_UP_PROVIDER=oidc).
//
// Guards: (1) the panel renders ONLY for the oidc provider (dev/totp/webauthn
// and loading render nothing, keeping those surfaces + the eval-gate UI
// unchanged); (2) the connect button drives begin -> popup -> finish with the
// returned {code,state} and invalidates the step-up status query so the "Linked"
// badge refreshes; (3) a popup error surfaces a destructive toast and never
// calls finish. The popup itself is mocked (runOidcPopup is unit-tested in
// oidc-client.test.ts).
// ---------------------------------------------------------------------------

const mockStatus = vi.fn();
const mockBeginMutate = vi.fn();
const mockFinishMutate = vi.fn();
const mockToast = vi.fn();
const mockRunOidcPopup = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useStepUpStatus: () => mockStatus(),
    useStepUpOidcRegisterBegin: () => ({
      mutateAsync: mockBeginMutate,
      isPending: false,
    }),
    useStepUpOidcRegisterFinish: () => ({
      mutateAsync: mockFinishMutate,
      isPending: false,
    }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock("@/lib/oidc-client", () => ({
  runOidcPopup: (...args: unknown[]) => mockRunOidcPopup(...args),
}));

import OidcEnrollment from "./oidc-enrollment";
import { getStepUpStatusQueryKey } from "@workspace/api-client-react";

function renderPanel() {
  const queryClient = new QueryClient();
  const invalidateSpy = vi
    .spyOn(queryClient, "invalidateQueries")
    .mockResolvedValue(undefined as never);
  render(
    <QueryClientProvider client={queryClient}>
      <OidcEnrollment />
    </QueryClientProvider>,
  );
  return { invalidateSpy };
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("OidcEnrollment", () => {
  it("renders nothing while status is loading", () => {
    mockStatus.mockReturnValue({ data: undefined, isLoading: true });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <OidcEnrollment />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for the webauthn provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: true, verified: true },
      isLoading: false,
    });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <OidcEnrollment />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the not-linked state for the oidc provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "oidc", enrolled: false, verified: false },
      isLoading: false,
    });
    renderPanel();
    expect(
      screen.getByText("Identity Provider (OIDC) Step-up"),
    ).toBeInTheDocument();
    expect(screen.getByText("Not linked")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Link identity provider" }),
    ).toBeInTheDocument();
  });

  it("drives begin -> popup -> finish and invalidates status on connect", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "oidc", enrolled: false, verified: false },
      isLoading: false,
    });
    mockBeginMutate.mockResolvedValue({
      authorization_url: "https://idp.example/authorize?x=1",
    });
    mockRunOidcPopup.mockResolvedValue({ code: "the-code", state: "the-state" });
    mockFinishMutate.mockResolvedValue({ verified: true });

    const { invalidateSpy } = renderPanel();
    fireEvent.click(
      screen.getByRole("button", { name: "Link identity provider" }),
    );

    await waitFor(() => expect(mockFinishMutate).toHaveBeenCalledTimes(1));
    expect(mockBeginMutate).toHaveBeenCalledTimes(1);
    expect(mockRunOidcPopup).toHaveBeenCalledWith(
      "https://idp.example/authorize?x=1",
    );
    expect(mockFinishMutate).toHaveBeenCalledWith({
      data: { code: "the-code", state: "the-state" },
    });
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: getStepUpStatusQueryKey(),
    });
  });

  it("surfaces an error toast and does not call finish when the popup is cancelled", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "oidc", enrolled: false, verified: false },
      isLoading: false,
    });
    mockBeginMutate.mockResolvedValue({
      authorization_url: "https://idp.example/authorize?x=1",
    });
    mockRunOidcPopup.mockRejectedValue(new Error("Authentication was cancelled."));

    renderPanel();
    fireEvent.click(
      screen.getByRole("button", { name: "Link identity provider" }),
    );

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    expect(mockFinishMutate).not.toHaveBeenCalled();
  });
});
