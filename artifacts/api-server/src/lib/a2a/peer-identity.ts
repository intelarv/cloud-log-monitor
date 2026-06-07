// Per-claim ABAC against the mTLS peer's certificate identity (threat_model
// §Spoofing — "A2A caller identity" / §Elevation of Privilege — "A2A
// authorization": "the called agent MUST verify the caller's ABAC claims").
//
// The mTLS transport seam (transport.ts) answers "did a VERIFIED client cert
// arrive at all". This module answers the stronger, deferred question: "WHOSE
// cert is it, and is that peer allowed to do THIS?" — i.e. ABAC against the
// certificate's SAN / Subject-DN claims. Two independent, env-gated controls,
// both INERT unless configured (so loopback dev + the offline eval gate are
// unchanged, exactly like the rest of the mTLS seam):
//
//   1. PEER ALLOW-LIST (`A2A_MTLS_ALLOWED_PEERS`) — enforced in transport.ts:
//      the peer's SAN/CN/DN must match an allow-listed identity, else the
//      connection is refused at the transport layer (ledgered).
//
//   2. PEER↔CALLER BINDING (`A2A_MTLS_PEER_BINDINGS`) — enforced here, AFTER the
//      caller-identity JWT has been verified: the network identity (cert) and
//      the application identity (JWT `sub`) must AGREE. This defeats a confused-
//      deputy where a host holding a valid cert for service X presents a JWT
//      minted for the supervisor. Mismatch is refused 403 + ledgered.
//
// Both reuse the existing `a2a.transport_rejected` ledger event (a peer-identity
// failure is an mTLS-identity failure) with a distinct `reason`, so no new event
// type is introduced. The ledger payload stays attacker-data-free: fixed route +
// static reason only — never the peer DN/SAN or any request header value.

import { X509Certificate } from "node:crypto";
import type { RequestHandler } from "express";
import { logger } from "../logger";
import { appendLedger, type LedgerWriteInput } from "../ledger";
import { isA2AMtlsRequired } from "./transport";
import type { VerifiedCaller } from "./caller-identity";

export interface PeerIdentity {
  /** SAN entries, each kept in raw `TYPE:value` form (e.g. "DNS:svc",
   *  "URI:spiffe://cluster/ns/sa"). */
  sans: string[];
  /** Subject Distinguished Name (comma-joined RDNs), or null. */
  subjectDN: string | null;
  /** Subject Common Name, or null. */
  subjectCN: string | null;
}

const DEFAULT_SUBJECT_DN_HEADER = "x-ssl-client-subject-dn";
const DEFAULT_CLIENT_CERT_HEADER = "x-ssl-client-cert";

function headerName(envName: string, fallback: string): string {
  const v = process.env[envName];
  return (v !== undefined && v.length > 0 ? v : fallback).toLowerCase();
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

interface PeerCertObject {
  subject?: Record<string, string | string[]> | string;
  subjectaltname?: string;
}

interface PeerReq {
  header(name: string): string | undefined;
  socket?: {
    getPeerCertificate?: (detailed?: boolean) => PeerCertObject | undefined;
  };
}

/** Parse a SAN string ("DNS:a, URI:b, IP:1.2.3.4") into raw `TYPE:value`
 *  entries. */
function parseSanString(san: string | undefined): string[] {
  if (!san) return [];
  return san
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Pull the CN out of a DN string ("CN=svc,O=org" or multiline "CN=svc\nO=org"). */
function cnFromDN(dn: string | null): string | null {
  if (dn === null) return null;
  for (const part of dn.split(/[\n,]/)) {
    const m = /^\s*CN\s*=\s*(.+?)\s*$/i.exec(part);
    if (m && m[1] !== undefined) return m[1];
  }
  return null;
}

/** Render a getPeerCertificate() `subject` object as a stable DN string. */
function dnFromSubjectObject(subject: Record<string, string | string[]>): string {
  const parts: string[] = [];
  for (const [k, v] of Object.entries(subject)) {
    const vals = Array.isArray(v) ? v : [v];
    for (const val of vals) parts.push(`${k}=${val}`);
  }
  return parts.join(",");
}

function fromPeerCertObject(cert: PeerCertObject): PeerIdentity | null {
  const hasSubject =
    cert.subject !== undefined &&
    (typeof cert.subject === "string"
      ? cert.subject.length > 0
      : Object.keys(cert.subject).length > 0);
  const sans = parseSanString(cert.subjectaltname);
  if (!hasSubject && sans.length === 0) return null;
  let subjectDN: string | null = null;
  let subjectCN: string | null = null;
  if (typeof cert.subject === "string") {
    subjectDN = cert.subject;
    subjectCN = cnFromDN(cert.subject);
  } else if (cert.subject !== undefined) {
    subjectDN = dnFromSubjectObject(cert.subject);
    const cn = cert.subject["CN"];
    subjectCN = Array.isArray(cn) ? (cn[0] ?? null) : (cn ?? null);
  }
  return { sans, subjectDN, subjectCN };
}

/** Extract the verified peer's certificate identity from either direct TLS
 *  termination (`socket.getPeerCertificate()`) or an ingress that forwards the
 *  client cert. Returns null when no identity is recoverable. */
export function extractPeerIdentity(req: PeerReq): PeerIdentity | null {
  // (a) Direct TLS at this Node process.
  const cert = req.socket?.getPeerCertificate?.(true);
  if (cert !== undefined) {
    const id = fromPeerCertObject(cert);
    if (id !== null) return id;
  }
  // (b) Ingress forwards the URL-encoded client cert PEM — parse it for the
  //     authoritative SAN + subject.
  const pemHeader = req.header(headerName("A2A_MTLS_CLIENT_CERT_HEADER", DEFAULT_CLIENT_CERT_HEADER));
  if (pemHeader !== undefined && pemHeader.length > 0) {
    const id = fromPem(pemHeader);
    if (id !== null) return id;
  }
  // (c) Ingress forwards only the subject DN string.
  const dnHeader = req.header(headerName("A2A_MTLS_SUBJECT_DN_HEADER", DEFAULT_SUBJECT_DN_HEADER));
  if (dnHeader !== undefined && dnHeader.length > 0) {
    return { sans: [], subjectDN: dnHeader, subjectCN: cnFromDN(dnHeader) };
  }
  return null;
}

function fromPem(rawHeader: string): PeerIdentity | null {
  // nginx `ssl_client_escaped_cert` URL-encodes the PEM; tolerate both encoded
  // and already-decoded values.
  let pem = rawHeader;
  if (pem.includes("%")) {
    try {
      pem = decodeURIComponent(pem);
    } catch {
      // Leave as-is; X509Certificate will reject a malformed value below.
    }
  }
  try {
    const x = new X509Certificate(pem);
    const sans = parseSanString(x.subjectAltName ?? undefined);
    const subjectDN = x.subject.length > 0 ? x.subject : null;
    return { sans, subjectDN, subjectCN: cnFromDN(subjectDN) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/** All candidate identifier strings a policy entry may match against: the
 *  subject DN, the CN, and each SAN in both raw (`URI:x`) and bare (`x`) form. */
export function peerIdentifiers(peer: PeerIdentity): string[] {
  const out: string[] = [];
  if (peer.subjectDN !== null) out.push(peer.subjectDN);
  if (peer.subjectCN !== null) out.push(peer.subjectCN);
  for (const san of peer.sans) {
    out.push(san);
    const idx = san.indexOf(":");
    if (idx >= 0) out.push(san.slice(idx + 1));
  }
  return out.map((s) => s.trim()).filter((s) => s.length > 0);
}

function splitList(envName: string): string[] | null {
  const raw = process.env[envName];
  if (raw === undefined || raw.trim().length === 0) return null;
  const items = raw
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  return items.length > 0 ? items : null;
}

/** Parsed `A2A_MTLS_ALLOWED_PEERS`, or null when unset (control inert). */
export function getAllowedPeers(): string[] | null {
  return splitList("A2A_MTLS_ALLOWED_PEERS");
}

/** True when any of the peer's identifiers is on the allow-list. */
export function peerMatchesAllowList(peer: PeerIdentity, allowed: string[]): boolean {
  const ids = new Set(peerIdentifiers(peer).map((s) => s.toLowerCase()));
  return allowed.some((a) => ids.has(a.trim().toLowerCase()));
}

/** Parsed `A2A_MTLS_PEER_BINDINGS` (`peerId=callerSubject` pairs) as
 *  subject → allowed peer-identifier set, or null when unset (control inert). */
export function getPeerBindings(): Map<string, Set<string>> | null {
  const items = splitList("A2A_MTLS_PEER_BINDINGS");
  if (items === null) return null;
  const map = new Map<string, Set<string>>();
  for (const item of items) {
    const eq = item.indexOf("=");
    if (eq <= 0 || eq === item.length - 1) {
      logger.warn({ item }, "ignoring malformed A2A_MTLS_PEER_BINDINGS entry (expected peer=subject)");
      continue;
    }
    const peerId = item.slice(0, eq).trim().toLowerCase();
    const subject = item.slice(eq + 1).trim();
    if (peerId.length === 0 || subject.length === 0) continue;
    const set = map.get(subject) ?? new Set<string>();
    set.add(peerId);
    map.set(subject, set);
  }
  return map.size > 0 ? map : null;
}

/** True when the verified caller `subject` is bound to one of the peer's
 *  certificate identifiers. */
export function peerSatisfiesBinding(
  peer: PeerIdentity,
  subject: string,
  bindings: Map<string, Set<string>>,
): boolean {
  const allowedForSubject = bindings.get(subject);
  if (allowedForSubject === undefined) return false;
  const ids = peerIdentifiers(peer).map((s) => s.toLowerCase());
  return ids.some((id) => allowedForSubject.has(id));
}

// ---------------------------------------------------------------------------
// Binding middleware (runs after caller-identity JWT verification)
// ---------------------------------------------------------------------------

type LedgerWriteFn = (input: LedgerWriteInput) => Promise<unknown>;

interface PeerAwareRequest {
  baseUrl: string;
  a2aPeer?: PeerIdentity | null;
  a2aCaller?: VerifiedCaller;
}

/** Builds the middleware enforcing the mTLS peer ↔ JWT-subject binding. INERT
 *  unless mTLS is required AND `A2A_MTLS_PEER_BINDINGS` is configured. On a
 *  mismatch it refuses 403 and records `a2a.transport_rejected`
 *  (reason `peer_subject_mismatch`) — system-scoped, payload = fixed route +
 *  static reason only (never the DN/SAN or any header). The ledger writer is
 *  injected (default = real `appendLedger`) so the offline suite stays DB-free. */
export function createA2APeerBindingMiddleware(
  ledgerWrite: LedgerWriteFn = appendLedger,
): RequestHandler {
  return (req, res, next) => {
    if (!isA2AMtlsRequired()) {
      next();
      return;
    }
    const bindings = getPeerBindings();
    if (bindings === null) {
      next();
      return;
    }
    const r = req as unknown as PeerAwareRequest;
    const peer = r.a2aPeer ?? null;
    const subject = r.a2aCaller?.subject;
    const ok =
      peer !== null && subject !== undefined && peerSatisfiesBinding(peer, subject, bindings);
    if (ok) {
      next();
      return;
    }
    const route = r.baseUrl;
    logger.warn(
      { route },
      "A2A request refused: mTLS peer certificate identity is not bound to the caller-identity subject",
    );
    res.status(403).json({ error: "client certificate identity not authorized" });
    void ledgerWrite({
      tenantId: null,
      actor: { kind: "system", id: "a2a_transport" },
      eventType: "a2a.transport_rejected",
      subjectType: "a2a_route",
      subjectId: route,
      payload: { route, reason: "peer_subject_mismatch" },
    }).catch((err: unknown) => {
      logger.error({ err }, "failed to ledger A2A peer-binding rejection");
    });
  };
}

/** Default instance wired to the real ledger, mounted by `mountA2AAgents`. */
export const a2aPeerBindingMiddleware: RequestHandler = createA2APeerBindingMiddleware();
