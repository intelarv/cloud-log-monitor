import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the WebAuthn (passkey) step-up enrollment panel
// — the browser-side mirror of the register/begin -> navigator.credentials
// .create() -> register/finish ceremony served by
// `artifacts/api-server/src/routes/auth.ts` (STEP_UP_PROVIDER=webauthn).
//
// Guards: (1) the panel renders ONLY for the webauthn provider (dev/totp and
// loading render nothing, keeping those surfaces + the eval-gate UI unchanged);
// (2) the register button drives begin -> create() -> finish with the correctly
// base64url-encoded attestation and invalidates the step-up status query so the
// "Enrolled" badge refreshes. The live browser flow needs a real authenticator
// and is out of scope here; the ceremony seam is unit-tested in
// webauthn-client.test.ts.
// ---------------------------------------------------------------------------

const mockStatus = vi.fn();
const mockBeginMutate = vi.fn();
const mockFinishMutate = vi.fn();
const mockToast = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useStepUpStatus: () => mockStatus(),
    useStepUpWebauthnRegisterBegin: () => ({
      mutateAsync: mockBeginMutate,
      isPending: false,
    }),
    useStepUpWebauthnRegisterFinish: () => ({
      mutateAsync: mockFinishMutate,
      isPending: false,
    }),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

import WebauthnEnrollment from "./webauthn-enrollment";
import { getStepUpStatusQueryKey } from "@workspace/api-client-react";

const mockCreate = vi.fn();

function renderPanel() {
  const queryClient = new QueryClient();
  const invalidateSpy = vi
    .spyOn(queryClient, "invalidateQueries")
    .mockResolvedValue(undefined as never);
  render(
    <QueryClientProvider client={queryClient}>
      <WebauthnEnrollment />
    </QueryClientProvider>,
  );
  return { invalidateSpy };
}

beforeEach(() => {
  vi.clearAllMocks();
  // jsdom has no WebAuthn; stub the feature-detect + the create() ceremony.
  (window as any).PublicKeyCredential = function () {};
  Object.defineProperty(navigator, "credentials", {
    value: { create: mockCreate, get: vi.fn() },
    configurable: true,
  });
});

afterEach(() => {
  delete (window as any).PublicKeyCredential;
});

describe("WebauthnEnrollment", () => {
  it("renders nothing while status is loading", () => {
    mockStatus.mockReturnValue({ data: undefined, isLoading: true });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <WebauthnEnrollment />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing for the totp provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
      isLoading: false,
    });
    const { container } = render(
      <QueryClientProvider client={new QueryClient()}>
        <WebauthnEnrollment />
      </QueryClientProvider>,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the not-enrolled state for the webauthn provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: false, verified: false },
      isLoading: false,
    });
    renderPanel();
    expect(screen.getByText("Passkey (WebAuthn) Step-up")).toBeInTheDocument();
    expect(screen.getByText("Not enrolled")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Register passkey" }),
    ).toBeInTheDocument();
  });

  it("drives begin -> create() -> finish and invalidates status on register", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: false, verified: false },
      isLoading: false,
    });
    // base64url "AQID" decodes to bytes [1,2,3] — valid for b64urlToBytes.
    mockBeginMutate.mockResolvedValue({
      challenge: "AQID",
      rpId: "example.com",
      rpName: "PHI Audit",
      userIdB64url: "AQID",
      userName: "analyst@example.com",
    });
    mockCreate.mockResolvedValue({
      rawId: new Uint8Array([1, 2, 3]).buffer,
      response: {
        attestationObject: new Uint8Array([4, 5, 6]).buffer,
        clientDataJSON: new Uint8Array([7, 8, 9]).buffer,
      },
    });
    mockFinishMutate.mockResolvedValue({ verified: true });

    const { invalidateSpy } = renderPanel();
    fireEvent.click(screen.getByRole("button", { name: "Register passkey" }));

    await waitFor(() => expect(mockFinishMutate).toHaveBeenCalledTimes(1));
    expect(mockBeginMutate).toHaveBeenCalledTimes(1);
    expect(mockCreate).toHaveBeenCalledTimes(1);
    // attestation fields are base64url-encoded from the ceremony response.
    expect(mockFinishMutate).toHaveBeenCalledWith({
      data: {
        attestationObject: "BAUG", // [4,5,6]
        clientDataJSON: "BwgJ", // [7,8,9]
      },
    });
    expect(invalidateSpy).toHaveBeenCalledWith({
      queryKey: getStepUpStatusQueryKey(),
    });
  });

  it("surfaces an error toast and does not call finish when create() is cancelled", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: false, verified: false },
      isLoading: false,
    });
    mockBeginMutate.mockResolvedValue({
      challenge: "AQID",
      rpId: "example.com",
      rpName: "PHI Audit",
      userIdB64url: "AQID",
      userName: "analyst@example.com",
    });
    mockCreate.mockRejectedValue(new Error("NotAllowedError"));

    renderPanel();
    fireEvent.click(screen.getByRole("button", { name: "Register passkey" }));

    await waitFor(() =>
      expect(mockToast).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    expect(mockFinishMutate).not.toHaveBeenCalled();
  });
});
