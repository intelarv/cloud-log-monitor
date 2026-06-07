// Cross-cloud mTLS transport seam for the A2A agent plane
// (threat_model §Spoofing — "A2A caller identity" / §Information Disclosure —
// "TLS everywhere"; §Elevation of Privilege — "A2A authorization").
//
// Two halves, both INERT by default — loopback dev has no PKI, so nothing here
// runs unless `A2A_REQUIRE_MTLS` is explicitly turned on:
//
//   CLIENT  — when mTLS is required AND client cert material is configured,
//             outbound A2A calls go over a mutually-authenticated TLS channel.
//             Node's native `fetch` performs TLS client auth only through an
//             undici `Dispatcher`, so we lazy-load `undici` (an OPTIONAL dep,
//             same posture as the cloud SDKs in cloud-embedders.ts — not in the
//             dev bundle; a missing dep becomes a clear runtime error only when
//             an operator turns mTLS on) and build an Agent whose `connect`
//             options carry the client key/cert + the CA that signs the peer.
//
//   SERVER  — when mTLS is required, the agent card + JSON-RPC routes demand
//             evidence of a VERIFIED client certificate before any handler runs.
//             Two TLS-termination models are supported:
//               (a) direct TLS at this Node process → `req.socket.authorized`
//               (b) TLS terminated at the ingress    → a trusted verify header
//                   (nginx-ingress emits `ssl-client-verify: SUCCESS`). The
//                   header name + expected value are configurable; this is only
//                   trustworthy because the agent routes are loopback-internal
//                   (not in the shared proxy path table), reachable solely from
//                   behind such an ingress / from the co-located supervisor.
//
// The application-layer caller-identity JWT (caller-identity.ts) still rides
// INSIDE this channel: mTLS answers "is this host allowed to connect at all",
// the JWT answers "which agent + skill is this caller authorized for". Defense
// in depth — neither layer replaces the other.

import { readFileSync } from "node:fs";
import type { RequestHandler } from "express";
import { logger } from "../logger";
import { appendLedger, type LedgerWriteInput } from "../ledger";
import {
  extractPeerIdentity,
  getAllowedPeers,
  peerMatchesAllowList,
  type PeerIdentity,
} from "./peer-identity";

// Aliasing the dynamic import through a variable hides the specifier from the TS
// static analyzer, so `undici` is not required for typecheck or for the dev
// bundle — exactly the loadOptional pattern used for the cloud SDKs.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function loadOptional(id: string): Promise<any> {
  return (await import(/* @vite-ignore */ id)) as unknown;
}

function envTruthy(name: string): boolean {
  const v = process.env[name];
  return v === "1" || v?.toLowerCase() === "true";
}

/** Is cross-cloud mTLS enforcement turned on? Read fresh each call (no cache)
 *  so tests and config reloads see the current value. */
export function isA2AMtlsRequired(): boolean {
  return envTruthy("A2A_REQUIRE_MTLS");
}

const DEFAULT_VERIFY_HEADER = "x-ssl-client-verify";
const DEFAULT_VERIFY_VALUE = "SUCCESS";

function verifyHeaderName(): string {
  const v = process.env["A2A_MTLS_CLIENT_VERIFY_HEADER"];
  return (v !== undefined && v.length > 0 ? v : DEFAULT_VERIFY_HEADER).toLowerCase();
}

function verifyHeaderValue(): string {
  const v = process.env["A2A_MTLS_CLIENT_VERIFY_VALUE"];
  return v !== undefined && v.length > 0 ? v : DEFAULT_VERIFY_VALUE;
}

// ---------------------------------------------------------------------------
// Client side: build an mTLS dispatcher for outbound A2A calls.
// ---------------------------------------------------------------------------

let dispatcherPromise: Promise<unknown | undefined> | null = null;

/** Resolve the undici Dispatcher used for outbound A2A `fetch` calls, or
 *  `undefined` when mTLS is not required (the loopback default — plain fetch).
 *  Cached after first resolution. Throws a clear configuration error when mTLS
 *  is required but the client cert/key are not configured (fail closed). The
 *  optional `undici` import only happens AFTER cert/key are present, so the
 *  dev/eval path never touches it. */
export function getA2AClientDispatcher(): Promise<unknown | undefined> {
  if (!isA2AMtlsRequired()) return Promise.resolve(undefined);
  if (dispatcherPromise === null) {
    dispatcherPromise = buildDispatcher();
  }
  return dispatcherPromise;
}

async function buildDispatcher(): Promise<unknown> {
  const certPath = process.env["A2A_MTLS_CERT"];
  const keyPath = process.env["A2A_MTLS_KEY"];
  const caPath = process.env["A2A_MTLS_CA"];
  if (!certPath || !keyPath) {
    throw new Error(
      "A2A_REQUIRE_MTLS is set but A2A_MTLS_CERT and/or A2A_MTLS_KEY are not configured; " +
        "outbound A2A calls cannot present a client certificate. Set both (PEM file paths) " +
        "or unset A2A_REQUIRE_MTLS for loopback dev.",
    );
  }
  const cert = readFileSync(certPath);
  const key = readFileSync(keyPath);
  const ca = caPath ? readFileSync(caPath) : undefined;

  // undici is an optional dependency (operators enabling cross-cloud mTLS
  // install it, the same way they install the cloud SDKs). Missing dep here is
  // a loud, actionable runtime error rather than a silent plaintext fallback.
  let undici: { Agent: new (opts: unknown) => unknown };
  try {
    undici = (await loadOptional("undici")) as typeof undici;
  } catch {
    throw new Error(
      "A2A_REQUIRE_MTLS is set but the optional 'undici' dependency is not installed. " +
        "Run `pnpm --filter @workspace/api-server add undici` to enable mTLS client auth.",
    );
  }
  return new undici.Agent({
    connect: { cert, key, ca, rejectUnauthorized: true },
  });
}

/** Reset cached client dispatcher — test-only. */
export function __resetA2ATransportForTest(): void {
  dispatcherPromise = null;
}

// ---------------------------------------------------------------------------
// Server side: require a verified client certificate.
// ---------------------------------------------------------------------------

/** True when the request arrived over a verified mutually-authenticated TLS
 *  channel — either direct TLS at this process, or TLS terminated at a trusted
 *  ingress that stamped the verify header. */
export function hasVerifiedClientCert(req: {
  header(name: string): string | undefined;
  socket?: { authorized?: boolean };
}): boolean {
  // (a) Direct TLS termination at the Node process.
  if (req.socket?.authorized === true) return true;
  // (b) TLS terminated at the ingress, which forwards a verify header.
  const got = req.header(verifyHeaderName());
  if (got !== undefined && got.toLowerCase() === verifyHeaderValue().toLowerCase()) {
    return true;
  }
  return false;
}

type LedgerWriteFn = (input: LedgerWriteInput) => Promise<unknown>;

/** Builds the Express middleware enforcing mTLS on the A2A routes. INERT
 *  (pass-through) unless `A2A_REQUIRE_MTLS` is set, so loopback dev and the
 *  offline test suite are unaffected. When enforced, a request without a
 *  verified client cert is refused 403 BEFORE the shared-secret /
 *  caller-identity layers run (transport auth is outermost).
 *
 *  The refusal is also recorded on the tamper-evident ledger
 *  (`a2a.transport_rejected`, threat_model §Repudiation / §Spoofing — "A2A
 *  caller identity"): system-scoped (an unverified caller has no tenant), with
 *  a payload that carries ONLY the fixed agent route + a static reason — never
 *  request headers or bodies, which are attacker-influenced. The write is
 *  fire-and-forget AFTER the 403 (and isolated with `.catch`) so a slow or
 *  failing ledger can neither delay nor roll back the refusal; the append is
 *  advisory-lock serialized and these routes are loopback-only behind ingress,
 *  so probe amplification of the append-only ledger is bounded. The ledger
 *  writer is injected (default = real `appendLedger`) so the offline a2a test
 *  suite can assert the event without touching the database. */
export function createA2AMtlsMiddleware(
  ledgerWrite: LedgerWriteFn = appendLedger,
): RequestHandler {
  return (req, res, next) => {
    if (!isA2AMtlsRequired()) {
      next();
      return;
    }
    // Use `req.baseUrl` (the matched mount, e.g. "/a2a/triage"), NOT `req.path`:
    // under `app.use(mount, ...)` semantics `req.path` is the post-mount
    // remainder, which can carry attacker-influenced suffixes. `req.baseUrl` is
    // the fixed route this middleware is mounted on, so the ledger payload stays
    // attacker-data-free.
    const route = req.baseUrl;
    const refuse = (reason: string): void => {
      logger.warn({ route, reason }, "A2A request refused at mTLS transport layer");
      res.status(403).json({ error: "client certificate required" });
      void ledgerWrite({
        tenantId: null,
        actor: { kind: "system", id: "a2a_transport" },
        eventType: "a2a.transport_rejected",
        subjectType: "a2a_route",
        subjectId: route,
        payload: { route, reason },
      }).catch((err: unknown) => {
        logger.error({ err }, "failed to ledger A2A mTLS transport rejection");
      });
    };

    // Layer 1: a VERIFIED client certificate must be present at all.
    if (!hasVerifiedClientCert(req as Parameters<typeof hasVerifiedClientCert>[0])) {
      refuse("no_verified_client_cert");
      return;
    }

    // Layer 2: per-claim ABAC against the peer's certificate identity. Always
    // extract + stash the identity (so the downstream peer↔caller binding
    // middleware can read it); only ENFORCE an allow-list when one is configured
    // (`A2A_MTLS_ALLOWED_PEERS`). Identity stays out of the ledger payload — only
    // the fixed route + static reason are recorded.
    const peer = extractPeerIdentity(req as Parameters<typeof extractPeerIdentity>[0]);
    (req as unknown as { a2aPeer?: PeerIdentity | null }).a2aPeer = peer;
    const allowed = getAllowedPeers();
    if (allowed !== null) {
      if (peer === null) {
        refuse("peer_identity_unavailable");
        return;
      }
      if (!peerMatchesAllowList(peer, allowed)) {
        refuse("peer_not_allowed");
        return;
      }
    }
    next();
  };
}

/** Default instance wired to the real ledger, mounted by `mountA2AAgents`. */
export const a2aMtlsMiddleware: RequestHandler = createA2AMtlsMiddleware();
