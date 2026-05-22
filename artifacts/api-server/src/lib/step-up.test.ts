import { describe, expect, it, beforeAll } from "vitest";
import {
  issueStepUpCookie,
  parseStepUpCookie,
  parseCookie,
  issueCookie,
  STEP_UP_TTL_SECONDS,
  verifyStepUpToken,
} from "./auth";

// Build a minimal Response shim that captures the Set-Cookie value so we can
// round-trip it through the parser without spinning up express.
function fakeRes(): {
  cookies: Record<string, string>;
  cookie: (n: string, v: string) => void;
} {
  const cookies: Record<string, string> = {};
  return {
    cookies,
    cookie(n, v) {
      cookies[n] = v;
    },
  };
}

beforeAll(() => {
  process.env.SESSION_SECRET ??= "test-session-secret-1234567890";
});

describe("step-up cookies", () => {
  it("round-trips a freshly issued step-up cookie", () => {
    const res = fakeRes();
    const s = issueStepUpCookie(res as unknown as Parameters<typeof issueStepUpCookie>[0], {
      sub: "alice",
      tenant_id: "default",
      reason: "investigating F-001",
    });
    const cookieVal = res.cookies["phia_stepup"]!;
    const parsed = parseStepUpCookie(cookieVal);
    expect(parsed).not.toBeNull();
    expect(parsed!.sub).toBe("alice");
    expect(parsed!.tenant_id).toBe("default");
    expect(parsed!.reason).toBe("investigating F-001");
    expect(parsed!.exp).toBe(s.exp);
    expect(s.exp - Math.floor(Date.now() / 1000)).toBeLessThanOrEqual(
      STEP_UP_TTL_SECONDS,
    );
  });

  it("rejects a tampered step-up cookie", () => {
    const res = fakeRes();
    issueStepUpCookie(res as unknown as Parameters<typeof issueStepUpCookie>[0], {
      sub: "alice",
      tenant_id: "default",
      reason: "ok",
    });
    const cookieVal = res.cookies["phia_stepup"]!;
    // Flip the last byte of the signature.
    const tampered =
      cookieVal.slice(0, -1) + (cookieVal.slice(-1) === "a" ? "b" : "a");
    expect(parseStepUpCookie(tampered)).toBeNull();
  });

  it("session and step-up signatures are domain-separated (no cross-replay)", () => {
    const res = fakeRes();
    // Issue a session cookie...
    issueCookie(res as unknown as Parameters<typeof issueCookie>[0], {
      sub: "alice",
      tenant_id: "default",
    });
    const sessionVal = res.cookies["phia_sess"]!;
    // ... and try to replay it as a step-up cookie. Must fail because the
    // step-up signature is tagged differently in the HMAC input.
    expect(parseStepUpCookie(sessionVal)).toBeNull();
    expect(parseCookie(sessionVal)).not.toBeNull();
  });

  it("verifyStepUpToken is constant-time-safe and rejects wrong tokens", () => {
    process.env["STEP_UP_DEV_TOKEN"] = "the-correct-dev-token";
    expect(verifyStepUpToken("the-correct-dev-token")).toBe(true);
    expect(verifyStepUpToken("the-wrong-dev-token!")).toBe(false);
    expect(verifyStepUpToken("short")).toBe(false);
    expect(verifyStepUpToken("the-correct-dev-token-x")).toBe(false);
  });
});
