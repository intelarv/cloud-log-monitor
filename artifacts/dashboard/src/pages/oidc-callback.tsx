import React from "react";
import { deliverOidcCallback } from "@/lib/oidc-client";

// The IdP redirects here at the end of an OIDC step-up popup flow. This page
// runs entirely client-side: it forwards the {code,state} (or error) back to the
// opener window via postMessage and then closes itself. It is only ever loaded
// inside the step-up popup; if opened directly it shows a short notice.
export default function OidcCallback() {
  const [message, setMessage] = React.useState<string>(
    "Completing authentication…",
  );

  React.useEffect(() => {
    const status = deliverOidcCallback();
    setMessage(status);
    // Give the opener a beat to receive the message, then self-close.
    const t = setTimeout(() => {
      try {
        window.close();
      } catch {
        // ignore — some browsers block scripted close of non-popup windows
      }
    }, 300);
    return () => clearTimeout(t);
  }, []);

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-6">
      <p className="text-sm text-muted-foreground text-center">{message}</p>
    </div>
  );
}
