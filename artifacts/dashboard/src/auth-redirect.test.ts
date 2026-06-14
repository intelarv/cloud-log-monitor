import { describe, it, expect, vi } from "vitest";
import { ApiError } from "@workspace/api-client-react";
import { redirectOnAuthFailure } from "./App";

// ---------------------------------------------------------------------------
// Regression guard for the global react-query 401 handling in App.tsx.
//
// A plain session-expiry 401 must bounce the user to /login. But a *step-up*
// challenge is also delivered as a 401 (`{ step_up_required: true }`) and is
// caught locally by the break-glass request/approve/revoke flows to open their
// MFA dialog. If the global handler redirects to /login on that step-up 401, it
// unmounts the in-flight dialog and silently aborts the action — which is
// exactly what broke the live break-glass flow end-to-end. The break-glass
// component tests mock the mutation, so they never exercised this global path.
// ---------------------------------------------------------------------------

function makeApiError(status: number, data: unknown): ApiError {
  const response = new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
  return new ApiError(response, data, { method: "POST", url: "/api/x" });
}

describe("redirectOnAuthFailure", () => {
  it("redirects to /login on a plain session-expiry 401", () => {
    const setLocation = vi.fn();
    redirectOnAuthFailure(makeApiError(401, { error: "not authenticated" }), "/findings/F-003", setLocation);
    expect(setLocation).toHaveBeenCalledWith("/login");
  });

  it("does NOT redirect on a step-up-required 401 (handled locally by the flow)", () => {
    const setLocation = vi.fn();
    redirectOnAuthFailure(
      makeApiError(401, { error: "step up required", step_up_required: true }),
      "/findings/F-003",
      setLocation,
    );
    expect(setLocation).not.toHaveBeenCalled();
  });

  it("does not redirect when already on /login", () => {
    const setLocation = vi.fn();
    redirectOnAuthFailure(makeApiError(401, { error: "not authenticated" }), "/login", setLocation);
    expect(setLocation).not.toHaveBeenCalled();
  });

  it("ignores non-401 ApiErrors", () => {
    const setLocation = vi.fn();
    redirectOnAuthFailure(makeApiError(500, { error: "boom" }), "/findings/F-003", setLocation);
    expect(setLocation).not.toHaveBeenCalled();
  });

  it("ignores non-ApiError values", () => {
    const setLocation = vi.fn();
    redirectOnAuthFailure(new Error("network"), "/findings/F-003", setLocation);
    expect(setLocation).not.toHaveBeenCalled();
  });
});
