import { describe, it, expect } from "vitest";

// ---------------------------------------------------------------------------
// Coverage for the finding-detail break-glass notice TRANSITION LOGIC: when a
// finding the analyst is viewing has its emergency-access grant approved or
// revoked/expired *by someone else* (on the admin page), the page must decide
// whether a notice is warranted and distinguish approved (access available)
// from revoked/expired (access cut off).
//
// These are the pure transition helpers (grantStatus / grantTransition) tested
// exhaustively in isolation. The rendered integration (the persistent banner
// the helpers drive) lives in `finding-detail-break-glass-banner.test.tsx`.
// ---------------------------------------------------------------------------

import { grantStatus, grantTransition, type GrantStatus } from "./finding-detail";
import type { BreakGlassGrant } from "@workspace/api-client-react";

function grant(overrides: Partial<BreakGlassGrant>): BreakGlassGrant {
  return {
    id: "g1",
    tenant_id: "t1",
    user_id: "u1",
    finding_id: "f1",
    justification: "Incident IR-1042",
    granted_at: "2026-06-13T12:00:00.000Z",
    expires_at: "2999-01-01T00:00:00.000Z",
    revoked_at: null,
    requires_second_approval: true,
    approver_user_id: null,
    approved_at: null,
    pending_approval: false,
    active: true,
    ...overrides,
  };
}

describe("grantStatus", () => {
  it("maps null/undefined to none", () => {
    expect(grantStatus(null)).toBe("none");
    expect(grantStatus(undefined)).toBe("none");
  });
  it("treats a revoked grant as revoked even if also expired/pending", () => {
    expect(grantStatus(grant({ revoked_at: "2026-06-13T13:00:00.000Z", pending_approval: true }))).toBe("revoked");
  });
  it("treats a grant awaiting second approval as pending", () => {
    expect(grantStatus(grant({ pending_approval: true }))).toBe("pending");
  });
  it("treats a past expiry as expired", () => {
    expect(grantStatus(grant({ expires_at: "2000-01-01T00:00:00.000Z" }))).toBe("expired");
  });
  it("treats a live, approved, non-expired grant as active", () => {
    expect(grantStatus(grant({}))).toBe("active");
  });
});

describe("grantTransition", () => {
  it("is silent on first observation and on no-change", () => {
    expect(grantTransition(null, "active")).toBeNull();
    expect(grantTransition("active", "active")).toBeNull();
  });
  it("flags pending -> active as approved", () => {
    expect(grantTransition("pending", "active")).toBe("approved");
  });
  it("flags pending/active -> revoked as revoked", () => {
    expect(grantTransition("pending", "revoked")).toBe("revoked");
    expect(grantTransition("active", "revoked")).toBe("revoked");
  });
  it("flags pending/active -> expired as expired", () => {
    expect(grantTransition("pending", "expired")).toBe("expired");
    expect(grantTransition("active", "expired")).toBe("expired");
  });
  it("does not fire a cut-off notice for transitions that never had access", () => {
    const noisy: GrantStatus[] = ["none", "revoked", "expired"];
    for (const from of noisy) {
      expect(grantTransition(from, "revoked")).toBeNull();
      expect(grantTransition(from, "expired")).toBeNull();
    }
  });
});
