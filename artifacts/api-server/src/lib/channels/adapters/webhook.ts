// Generic HMAC-signed webhook adapter.
//
// Why signed: threat_model §Spoofing requires inbound webhook provider
// signatures to be verified; symmetric obligation here. Receivers
// validate `X-PHI-Audit-Signature: sha256=<hex>` over the body and
// `X-PHI-Audit-Timestamp` against the current time (±5min replay
// window). Sign-then-encrypt-then-send pattern: we use TLS for
// confidentiality, HMAC for integrity + authenticity.
//
// Why host allow-list: an attacker who can flip env config (e.g. via a
// supply-chain compromise of a config file) could otherwise repoint the
// adapter at attacker.example. The allow-list is the same defense pattern
// as the egress allow-list in threat_model §EoP "Agents".

import { createHmac, timingSafeEqual } from "node:crypto";
import type { ChannelAdapter, ChannelEnvelope, DispatchResult } from "../types";

export interface WebhookAdapterOpts {
  readonly url: string;
  readonly secret: string;
  readonly allowedHosts: ReadonlyArray<string>;
  readonly timeoutMs?: number;
}

/** Builds the canonical signing input. Exported for tests + receiver
 *  reference implementations. */
export function buildSignatureBase(timestampSec: number, body: string): string {
  return `${timestampSec}.${body}`;
}

/** HMAC-SHA256 hex of the canonical signing input. */
export function signWebhookBody(secret: string, timestampSec: number, body: string): string {
  return createHmac("sha256", secret).update(buildSignatureBase(timestampSec, body)).digest("hex");
}

/** Constant-time signature verifier for receivers and tests. Returns
 *  false on any length / hex parse mismatch — never throws. */
export function verifyWebhookSignature(
  secret: string,
  timestampSec: number,
  body: string,
  sigHex: string,
): boolean {
  const expected = signWebhookBody(secret, timestampSec, body);
  if (expected.length !== sigHex.length) return false;
  try {
    return timingSafeEqual(Buffer.from(expected, "hex"), Buffer.from(sigHex, "hex"));
  } catch {
    return false;
  }
}

export function createWebhookAdapter(opts: WebhookAdapterOpts): ChannelAdapter {
  const timeoutMs = opts.timeoutMs ?? 5000;
  if (opts.secret.length < 16) {
    throw new Error("webhook adapter: secret must be at least 16 chars");
  }
  // Resolve once at construction; misconfig fails loudly at boot, not at
  // first alert.
  const targetHost = new URL(opts.url).host.toLowerCase();
  const allowed = new Set(opts.allowedHosts.map((h) => h.toLowerCase()));
  if (!allowed.has(targetHost)) {
    throw new Error(
      `webhook adapter: target host ${targetHost} is not in CHANNEL_WEBHOOK_ALLOWED_HOSTS allow-list`,
    );
  }

  return {
    name: "webhook",
    async send(env: ChannelEnvelope): Promise<DispatchResult> {
      const started = Date.now();
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        // Stable serialization — receivers verify against the EXACT bytes
        // sent, so the body must not be re-serialized in transit. We don't
        // pretty-print and we don't include extra whitespace.
        const body = JSON.stringify(env);
        const timestampSec = Math.floor(Date.now() / 1000);
        const sig = signWebhookBody(opts.secret, timestampSec, body);
        // `redirect: "error"` blocks redirect-based SSRF: an allow-listed
        // host that gets compromised (or misconfigured) cannot bounce the
        // signed payload to an internal IP or attacker-controlled domain.
        // The boot-time host allow-list only protects against config-time
        // misconfig; this protects against runtime redirect.
        const res = await fetch(opts.url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "x-phi-audit-signature": `sha256=${sig}`,
            "x-phi-audit-timestamp": String(timestampSec),
          },
          body,
          signal: ctrl.signal,
          redirect: "error",
        });
        return {
          channel: "webhook",
          ok: res.ok,
          statusCode: res.status,
          durationMs: Date.now() - started,
          ...(res.ok ? {} : { err: `webhook returned status ${res.status}` }),
        };
      } catch (err) {
        return {
          channel: "webhook",
          ok: false,
          err: err instanceof Error ? err.message : String(err),
          durationMs: Date.now() - started,
        };
      } finally {
        clearTimeout(t);
      }
    },
  };
}
