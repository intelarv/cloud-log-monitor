import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// ---------------------------------------------------------------------------
// Component-level coverage for the step-up modal's provider branching — the
// browser-side mirror of POST /auth/step-up (+ the webauthn challenge endpoint)
// in `artifacts/api-server/src/routes/auth.ts`.
//
// Guards: (1) the dev/totp path still submits the typed token verbatim; (2) the
// webauthn path hides the token field, drives challenge -> navigator.credentials
// .get() -> assembles the JSON assertion token ({credentialId, clientDataJSON,
// authenticatorData, signature}, all base64url) and submits THAT as the step-up
// token. Deterministic; the mutation hooks + toast + WebAuthn API are mocked.
// ---------------------------------------------------------------------------

const mockStepUpMutate = vi.fn();
const mockChallengeMutate = vi.fn();
const mockOidcChallengeMutate = vi.fn();
const mockRecoveryMutate = vi.fn();
const mockStatus = vi.fn();
const mockToast = vi.fn();
const mockRunOidcPopup = vi.fn();

vi.mock("@workspace/api-client-react", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("@workspace/api-client-react")>();
  return {
    ...actual,
    useStepUp: () => ({ mutateAsync: mockStepUpMutate, isPending: false }),
    useStepUpWebauthnChallenge: () => ({
      mutateAsync: mockChallengeMutate,
      isPending: false,
    }),
    useStepUpOidcChallenge: () => ({
      mutateAsync: mockOidcChallengeMutate,
      isPending: false,
    }),
    useStepUpRecovery: () => ({
      mutateAsync: mockRecoveryMutate,
      isPending: false,
    }),
    useStepUpStatus: () => mockStatus(),
  };
});

vi.mock("@/hooks/use-toast", () => ({
  useToast: () => ({ toast: mockToast }),
}));

vi.mock("@/lib/oidc-client", () => ({
  runOidcPopup: (...args: unknown[]) => mockRunOidcPopup(...args),
}));

import StepUpModal from "./step-up-modal";

const mockGet = vi.fn();

function renderModal() {
  const onSuccess = vi.fn();
  const onOpenChange = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <StepUpModal
        open
        onOpenChange={onOpenChange}
        onSuccess={onSuccess}
        reason="Break-glass raw PHI"
      />
    </QueryClientProvider>,
  );
  return { onSuccess, onOpenChange };
}

beforeEach(() => {
  vi.clearAllMocks();
  mockStepUpMutate.mockResolvedValue({ ok: true });
  mockRecoveryMutate.mockResolvedValue({ ok: true });
  (window as any).PublicKeyCredential = function () {};
  Object.defineProperty(navigator, "credentials", {
    value: { create: vi.fn(), get: mockGet },
    configurable: true,
  });
});

afterEach(() => {
  delete (window as any).PublicKeyCredential;
});

describe("StepUpModal", () => {
  it("submits the typed token for the dev provider", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "dev", enrolled: false, verified: false },
    });
    const { onSuccess } = renderModal();
    fireEvent.change(screen.getByPlaceholderText("Enter token..."), {
      target: { value: "dev-stepup" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Verify & Continue" }),
    );
    await waitFor(() => expect(mockStepUpMutate).toHaveBeenCalledTimes(1));
    expect(mockStepUpMutate).toHaveBeenCalledWith({
      data: { token: "dev-stepup", reason: "Break-glass raw PHI" },
    });
    expect(mockChallengeMutate).not.toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalled();
  });

  it("drives the passkey ceremony and submits the assertion token for webauthn", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: true, verified: true },
    });
    mockChallengeMutate.mockResolvedValue({
      challenge: "AQID",
      rpId: "example.com",
      allowCredentials: ["AQID"],
    });
    mockGet.mockResolvedValue({
      rawId: new Uint8Array([1, 2, 3]).buffer, // -> "AQID"
      response: {
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer, // -> "BAUG"
        authenticatorData: new Uint8Array([7, 8, 9]).buffer, // -> "BwgJ"
        signature: new Uint8Array([10, 11, 12]).buffer, // -> "CgsM"
      },
    });

    const { onSuccess } = renderModal();
    // No token field in webauthn mode.
    expect(screen.queryByPlaceholderText("Enter token...")).toBeNull();

    fireEvent.click(
      screen.getByRole("button", { name: "Use passkey & continue" }),
    );

    await waitFor(() => expect(mockStepUpMutate).toHaveBeenCalledTimes(1));
    expect(mockChallengeMutate).toHaveBeenCalledTimes(1);
    expect(mockGet).toHaveBeenCalledTimes(1);
    const call = mockStepUpMutate.mock.calls[0][0];
    expect(call.data.reason).toBe("Break-glass raw PHI");
    expect(JSON.parse(call.data.token)).toEqual({
      credentialId: "AQID",
      clientDataJSON: "BAUG",
      authenticatorData: "BwgJ",
      signature: "CgsM",
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it("drives the IdP popup and submits the {code,state} token for oidc", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "oidc", enrolled: true, verified: true },
    });
    mockOidcChallengeMutate.mockResolvedValue({
      authorization_url: "https://idp.example/authorize?x=1",
    });
    mockRunOidcPopup.mockResolvedValue({ code: "the-code", state: "the-state" });

    const { onSuccess } = renderModal();
    // No typed token field in the ceremony (oidc) mode.
    expect(screen.queryByPlaceholderText("Enter token...")).toBeNull();

    fireEvent.click(
      screen.getByRole("button", { name: "Sign in & continue" }),
    );

    await waitFor(() => expect(mockStepUpMutate).toHaveBeenCalledTimes(1));
    expect(mockOidcChallengeMutate).toHaveBeenCalledTimes(1);
    expect(mockRunOidcPopup).toHaveBeenCalledWith(
      "https://idp.example/authorize?x=1",
    );
    expect(mockChallengeMutate).not.toHaveBeenCalled();
    const call = mockStepUpMutate.mock.calls[0][0];
    expect(call.data.reason).toBe("Break-glass raw PHI");
    expect(JSON.parse(call.data.token)).toEqual({
      code: "the-code",
      state: "the-state",
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it("does not offer the recovery-code toggle for the dev provider", () => {
    mockStatus.mockReturnValue({
      data: { provider: "dev", enrolled: false, verified: false },
    });
    renderModal();
    expect(
      screen.queryByRole("button", { name: /Use a recovery code/i }),
    ).toBeNull();
  });

  it("switches a webauthn step-up to a typed recovery code and submits via the recovery endpoint", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "webauthn", enrolled: true, verified: true },
    });
    const { onSuccess } = renderModal();

    // Ceremony mode: no token field until we switch to recovery.
    expect(screen.queryByPlaceholderText("XXXX-XXXX")).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: /Lost your device\? Use a recovery code/i }),
    );

    const input = screen.getByPlaceholderText("XXXX-XXXX");
    fireEvent.change(input, { target: { value: "AAAA-BBBB" } });
    fireEvent.click(screen.getByRole("button", { name: "Verify & Continue" }));

    await waitFor(() => expect(mockRecoveryMutate).toHaveBeenCalledTimes(1));
    expect(mockRecoveryMutate).toHaveBeenCalledWith({
      data: { token: "AAAA-BBBB", reason: "Break-glass raw PHI" },
    });
    // The factor ceremony + normal step-up paths are NOT used in recovery mode.
    expect(mockChallengeMutate).not.toHaveBeenCalled();
    expect(mockStepUpMutate).not.toHaveBeenCalled();
    expect(onSuccess).toHaveBeenCalled();
  });

  it("toggles back from recovery to the factor ceremony", async () => {
    mockStatus.mockReturnValue({
      data: { provider: "totp", enrolled: true, verified: true },
    });
    renderModal();
    fireEvent.click(
      screen.getByRole("button", { name: /Lost your device\? Use a recovery code/i }),
    );
    expect(screen.getByPlaceholderText("XXXX-XXXX")).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: /Use my second factor instead/i }),
    );
    // Back to the TOTP token field.
    expect(screen.queryByPlaceholderText("XXXX-XXXX")).toBeNull();
    expect(screen.getByPlaceholderText("123456")).toBeInTheDocument();
  });
});
