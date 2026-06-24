// Browser-side OIDC redirect helpers for STEP_UP_PROVIDER=oidc.
//
// Unlike WebAuthn (a local ceremony), the OIDC second factor is a redirect
// round-trip to the user's identity provider. The server issues an
// authorization URL; we open it in a popup; the IdP redirects back to our
// callback page (`/oidc-callback`), which postMessages the {code, state} pair
// back to the opener (this module). Kept framework-free so it can be unit-tested
// directly.

export interface OidcCallbackResult {
  code: string;
  state: string;
}

// The message envelope the callback page posts back. The `type` discriminator
// guards against unrelated postMessage traffic on the same origin.
const MESSAGE_TYPE = "phia-oidc-callback";

interface OidcCallbackMessage {
  type: typeof MESSAGE_TYPE;
  code?: string;
  state?: string;
  error?: string;
}

export function oidcCallbackUrl(): string {
  // BASE_URL ends with a trailing slash (Vite guarantees this).
  return `${window.location.origin}${import.meta.env.BASE_URL}oidc-callback`;
}

/** Open the IdP authorization URL in a popup and resolve with the {code,state}
 *  the callback page posts back. Rejects on user-closed popup, IdP-returned
 *  error, blocked popup, or timeout. */
export function runOidcPopup(
  authorizationUrl: string,
  opts: { timeoutMs?: number } = {},
): Promise<OidcCallbackResult> {
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;
  return new Promise((resolve, reject) => {
    const popup = window.open(
      authorizationUrl,
      "phia-oidc-step-up",
      "width=480,height=720,menubar=no,toolbar=no,location=yes",
    );
    if (!popup) {
      reject(new Error("Popup blocked. Allow popups for this site to step up."));
      return;
    }

    let settled = false;
    const cleanup = () => {
      window.removeEventListener("message", onMessage);
      clearInterval(closedTimer);
      clearTimeout(timeoutTimer);
    };
    const finish = (fn: () => void) => {
      if (settled) return;
      settled = true;
      cleanup();
      try {
        popup.close();
      } catch {
        // ignore — cross-origin close may throw in some browsers
      }
      fn();
    };

    const onMessage = (ev: MessageEvent) => {
      // Only trust messages from our own origin and our envelope shape.
      if (ev.origin !== window.location.origin) return;
      // Defense-in-depth against same-origin message confusion: when the source
      // window is available, require it to be the popup we opened. (Synthetic
      // events without a source still pass — real browser postMessages set it.)
      if (ev.source && ev.source !== popup) return;
      const data = ev.data as OidcCallbackMessage | null;
      if (!data || data.type !== MESSAGE_TYPE) return;
      if (data.error) {
        finish(() => reject(new Error(data.error)));
        return;
      }
      if (typeof data.code === "string" && typeof data.state === "string") {
        const { code, state } = data;
        finish(() => resolve({ code, state }));
      }
    };
    window.addEventListener("message", onMessage);

    // Detect a user who closes the popup without completing the flow.
    const closedTimer = setInterval(() => {
      if (popup.closed) {
        finish(() => reject(new Error("Authentication was cancelled.")));
      }
    }, 500);

    const timeoutTimer = setTimeout(() => {
      finish(() => reject(new Error("Authentication timed out.")));
    }, timeoutMs);
  });
}

/** Run from the callback page after the IdP redirect: read code/state (or error)
 *  from the current URL, post it back to the opener, and close. Returns a short
 *  human-readable status the page can render if it cannot self-close. */
export function deliverOidcCallback(): string {
  const params = new URLSearchParams(window.location.search);
  const code = params.get("code");
  const state = params.get("state");
  const error = params.get("error_description") || params.get("error");
  const target = window.opener as Window | null;
  const origin = window.location.origin;
  const message: OidcCallbackMessage = error
    ? { type: MESSAGE_TYPE, error }
    : code && state
      ? { type: MESSAGE_TYPE, code, state }
      : { type: MESSAGE_TYPE, error: "Missing authorization code." };
  if (target) {
    target.postMessage(message, origin);
    return error
      ? "Authentication failed. You can close this window."
      : "Authentication complete. You can close this window.";
  }
  return "This window must be opened from the dashboard step-up flow.";
}
