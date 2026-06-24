import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runOidcPopup, deliverOidcCallback, oidcCallbackUrl } from "./oidc-client";

// ---------------------------------------------------------------------------
// Unit coverage for the browser-side OIDC redirect seam. Unlike WebAuthn (a
// local ceremony), the OIDC second factor is a popup round-trip to the IdP: the
// opener (runOidcPopup) waits for a same-origin postMessage carrying {code,
// state}; the callback page (deliverOidcCallback) reads the redirect's query
// params and posts that envelope back. jsdom gives us window.open / postMessage
// stubs so we can drive both halves deterministically without a real IdP.
// ---------------------------------------------------------------------------

const ORIGIN = window.location.origin;
const MESSAGE_TYPE = "phia-oidc-callback";

describe("oidcCallbackUrl", () => {
  it("is the app-origin callback path under BASE_URL", () => {
    expect(oidcCallbackUrl()).toBe(`${ORIGIN}${import.meta.env.BASE_URL}oidc-callback`);
  });
});

describe("runOidcPopup", () => {
  let fakePopup: { closed: boolean; close: ReturnType<typeof vi.fn> };
  let openSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    fakePopup = { closed: false, close: vi.fn() };
    openSpy = vi
      .spyOn(window, "open")
      .mockReturnValue(fakePopup as unknown as Window);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  function postCallback(msg: Record<string, unknown>, origin = ORIGIN) {
    window.dispatchEvent(new MessageEvent("message", { data: msg, origin }));
  }

  it("resolves with {code,state} from a same-origin callback message", async () => {
    const p = runOidcPopup("https://idp.example/authorize");
    expect(openSpy).toHaveBeenCalledTimes(1);
    postCallback({ type: MESSAGE_TYPE, code: "the-code", state: "the-state" });
    await expect(p).resolves.toEqual({ code: "the-code", state: "the-state" });
    expect(fakePopup.close).toHaveBeenCalled();
  });

  it("ignores messages from a foreign origin", async () => {
    vi.useFakeTimers();
    try {
      const p = runOidcPopup("https://idp.example/authorize", { timeoutMs: 1000 });
      const rejected = p.catch((e: Error) => e.message);
      // Cross-origin message must be ignored — only the timeout settles it.
      postCallback(
        { type: MESSAGE_TYPE, code: "x", state: "y" },
        "https://evil.example",
      );
      await vi.advanceTimersByTimeAsync(1000);
      expect(await rejected).toMatch(/timed out/i);
    } finally {
      vi.useRealTimers();
    }
  });

  it("ignores messages without the expected envelope type", async () => {
    vi.useFakeTimers();
    try {
      const p = runOidcPopup("https://idp.example/authorize", { timeoutMs: 1000 });
      const rejected = p.catch((e: Error) => e.message);
      postCallback({ type: "something-else", code: "x", state: "y" });
      await vi.advanceTimersByTimeAsync(1000);
      expect(await rejected).toMatch(/timed out/i);
    } finally {
      vi.useRealTimers();
    }
  });

  it("rejects when the callback reports an IdP error", async () => {
    const p = runOidcPopup("https://idp.example/authorize");
    postCallback({ type: MESSAGE_TYPE, error: "access_denied" });
    await expect(p).rejects.toThrow("access_denied");
  });

  it("rejects when the popup is blocked", async () => {
    openSpy.mockReturnValue(null);
    await expect(runOidcPopup("https://idp.example/authorize")).rejects.toThrow(
      /popup blocked/i,
    );
  });

  it("rejects when the user closes the popup", async () => {
    vi.useFakeTimers();
    try {
      const p = runOidcPopup("https://idp.example/authorize");
      const rejected = p.catch((e: Error) => e.message);
      fakePopup.closed = true;
      await vi.advanceTimersByTimeAsync(600);
      expect(await rejected).toMatch(/cancelled/i);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("deliverOidcCallback", () => {
  const realOpener = window.opener;

  afterEach(() => {
    Object.defineProperty(window, "opener", {
      value: realOpener,
      configurable: true,
    });
    window.history.replaceState({}, "", "/");
  });

  function withSearch(search: string) {
    window.history.replaceState({}, "", `/oidc-callback${search}`);
  }

  it("posts {code,state} back to the opener and reports success", () => {
    const post = vi.fn();
    Object.defineProperty(window, "opener", {
      value: { postMessage: post },
      configurable: true,
    });
    withSearch("?code=abc&state=xyz");
    const msg = deliverOidcCallback();
    expect(msg).toMatch(/complete/i);
    expect(post).toHaveBeenCalledWith(
      { type: MESSAGE_TYPE, code: "abc", state: "xyz" },
      ORIGIN,
    );
  });

  it("forwards an IdP error to the opener", () => {
    const post = vi.fn();
    Object.defineProperty(window, "opener", {
      value: { postMessage: post },
      configurable: true,
    });
    withSearch("?error=access_denied&error_description=nope");
    const msg = deliverOidcCallback();
    expect(msg).toMatch(/failed/i);
    expect(post).toHaveBeenCalledWith(
      { type: MESSAGE_TYPE, error: "nope" },
      ORIGIN,
    );
  });

  it("reports missing code when neither code nor error is present", () => {
    const post = vi.fn();
    Object.defineProperty(window, "opener", {
      value: { postMessage: post },
      configurable: true,
    });
    withSearch("?foo=bar");
    deliverOidcCallback();
    expect(post).toHaveBeenCalledWith(
      { type: MESSAGE_TYPE, error: "Missing authorization code." },
      ORIGIN,
    );
  });

  it("returns guidance when there is no opener", () => {
    Object.defineProperty(window, "opener", {
      value: null,
      configurable: true,
    });
    withSearch("?code=abc&state=xyz");
    expect(deliverOidcCallback()).toMatch(/opened from the dashboard/i);
  });
});
