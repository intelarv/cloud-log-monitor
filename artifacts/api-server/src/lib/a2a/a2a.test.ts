// A2A loopback round-trip test (credential-free, offline).
//
// Spins up the Triage + Verifier A2A servers on an ephemeral loopback port,
// then drives them through the real `A2AAgentInvoker` (official @a2a-js/sdk
// client → Agent Card resolution → JSON-RPC message/send). The agents'
// underlying LLM call is stubbed via the injectable runtime seam, so no
// network or credentials are required.

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import express, { type Express } from "express";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";
import type { FindingSafe } from "@workspace/db";
import {
  __setLlmRuntimeForTest,
  __resetLlmRuntimeForTest,
  type LlmAgentRuntime,
} from "../llm-runtime";
import { mountA2AAgents } from "./server";
import { A2AAgentInvoker } from "./client";
import {
  getA2ASharedSecret,
  __resetA2ASecretForTest,
  buildA2AClientFetch,
} from "./auth";
import {
  mintCallerToken,
  __resetCallerIdentityForTest,
  A2A_CALLER_IDENTITY_HEADER,
  SUPERVISOR_CALLER_ID,
  TRIAGE_AUDIENCE,
  VERIFY_AUDIENCE,
  TRIAGE_SKILL,
  VERIFY_SKILL,
} from "./caller-identity";
import {
  TRIAGE_AGENT_PATH,
  VERIFY_AGENT_PATH,
  A2A_CARD_SUFFIX,
} from "./protocol";
import {
  isA2AMtlsRequired,
  hasVerifiedClientCert,
  createA2AMtlsMiddleware,
  getA2AClientDispatcher,
  __resetA2ATransportForTest,
} from "./transport";
import {
  extractPeerIdentity,
  peerIdentifiers,
  getAllowedPeers,
  peerMatchesAllowList,
  getPeerBindings,
  peerSatisfiesBinding,
  createA2APeerBindingMiddleware,
  type PeerIdentity,
} from "./peer-identity";

const TRIAGE_JSON = JSON.stringify({
  recommended_severity: "critical",
  recommended_action: "page_oncall",
  rationale: "Redacted SSN in a production log group; page on-call.",
  confidence: 0.9,
  prompt_injection_suspected: false,
});
const VERIFIER_JSON = JSON.stringify({
  verdict: "true_positive",
  rationale: "Agrees with triage; redacted SSN pattern is genuine.",
  confidence: 0.85,
  prompt_injection_suspected: false,
  agrees_with_triage: true,
});

// Hands back the canned responses in order (one per agent call), like the
// supervisor suite's fake runtime — robust to prompt wording overlaps.
function makeRuntime(responses: string[]): LlmAgentRuntime {
  let i = 0;
  return {
    async generate(opts) {
      const text = responses[i++] ?? "";
      return { text, approxOutputTokens: Math.ceil(text.length / 4), modelId: opts.modelId };
    },
  };
}

const FINDING = {
  id: "F-A2A-TEST",
  tenantId: "default",
  classification: "phi",
  subclass: "ssn",
  severity: "high",
  status: "open",
  source: "test:a2a",
  fingerprint: "test:a2a",
  redactedEvidence: {
    snippet: "applicant_ssn=[REDACTED:ssn] status=retry",
    redactions: ["ssn"],
    truncated: false,
    trust: "untrusted",
  },
  detectorVersion: "test@0.0.0",
} as unknown as FindingSafe;

let server: Server;
let baseUrl: string;
let prevBaseUrl: string | undefined;

beforeAll(async () => {
  prevBaseUrl = process.env["A2A_BASE_URL"];
  const app: Express = express();
  app.use(express.json());
  mountA2AAgents(app);
  server = app.listen(0);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const port = (server.address() as AddressInfo).port;
  baseUrl = `http://127.0.0.1:${port}`;
  process.env["A2A_BASE_URL"] = baseUrl;
  __resetA2ASecretForTest();
  __resetCallerIdentityForTest();
});

afterAll(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((err) => (err ? reject(err) : resolve())),
  );
  if (prevBaseUrl === undefined) delete process.env["A2A_BASE_URL"];
  else process.env["A2A_BASE_URL"] = prevBaseUrl;
  __resetA2ASecretForTest();
});

afterEach(() => {
  __resetLlmRuntimeForTest();
});

describe("A2A loopback round-trip", () => {
  it("triage returns the verdict over the A2A protocol", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON]));
    const invoker = new A2AAgentInvoker(baseUrl);
    const out = await invoker.triage(FINDING);
    expect(out.verdict).toMatchObject({
      recommended_severity: "critical",
      recommended_action: "page_oncall",
      prompt_injection_suspected: false,
    });
    expect(out.approxOutputTokens).toBeGreaterThan(0);
    expect(out.modelId).toBeTruthy();
  });

  it("verify returns the verdict over the A2A protocol", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON, VERIFIER_JSON]));
    const invoker = new A2AAgentInvoker(baseUrl);
    const triage = (await invoker.triage(FINDING)).verdict;
    const out = await invoker.verify(FINDING, triage);
    expect(out.verdict).toMatchObject({
      verdict: "true_positive",
      agrees_with_triage: true,
    });
  });

  it("serves a valid Agent Card whose url points at the JSON-RPC endpoint", async () => {
    const res = await buildA2AClientFetch()(
      `${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`,
    );
    expect(res.status).toBe(200);
    const card = (await res.json()) as { name: string; url: string; skills: unknown[] };
    expect(card.name).toBe("Triage Agent");
    expect(card.url).toBe(`${baseUrl}${TRIAGE_AGENT_PATH}`);
    expect(Array.isArray(card.skills)).toBe(true);
  });

  it("rejects an unauthenticated caller with 401", async () => {
    // Sanity: the shared secret is in effect.
    expect(getA2ASharedSecret().length).toBeGreaterThan(0);
    const res = await fetch(`${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`);
    expect(res.status).toBe(401);
  });

  it("strips rawEvidence at the boundary — it never reaches the agent prompt", async () => {
    // A buggy/compromised caller sends a finding that smuggles raw PHI. The
    // executor must parse+strip so the agent (and thus the LLM prompt) never
    // sees it.
    const SENTINEL = "RAW-PHI-SENTINEL-999-88-7777";
    const prompts: string[] = [];
    __setLlmRuntimeForTest({
      async generate(opts) {
        prompts.push(opts.userPrompt);
        return { text: TRIAGE_JSON, approxOutputTokens: 8, modelId: opts.modelId };
      },
    });
    const poisoned = {
      ...(FINDING as unknown as Record<string, unknown>),
      rawEvidence: { snippet: SENTINEL },
      rawEvidenceRef: { first: SENTINEL, latest: SENTINEL },
    } as unknown as FindingSafe;

    const invoker = new A2AAgentInvoker(baseUrl);
    const out = await invoker.triage(poisoned);
    expect(out.verdict.recommended_severity).toBe("critical");
    expect(prompts.length).toBe(1);
    expect(prompts[0]).not.toContain(SENTINEL);
  });

  it("rejects a malformed finding payload (missing required field)", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON]));
    // Drop the required `id` field — schema parse in the executor must reject.
    const { id: _omit, ...rest } = FINDING as unknown as Record<string, unknown>;
    const malformed = rest as unknown as FindingSafe;
    const invoker = new A2AAgentInvoker(baseUrl);
    await expect(invoker.triage(malformed)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Caller identity + ABAC scope (threat_model §Spoofing / §Elevation of
// Privilege — "A2A authorization"). These drive the JSON-RPC endpoint directly
// with hand-crafted headers to prove the scope middleware gates the call BEFORE
// the executor runs.
// ---------------------------------------------------------------------------

const RPC_BODY = JSON.stringify({
  jsonrpc: "2.0",
  id: "1",
  method: "message/send",
  params: {
    message: {
      kind: "message",
      messageId: "msg_test",
      role: "user",
      parts: [{ kind: "data", data: { kind: "triage_request", finding: FINDING } }],
    },
  },
});

async function postRpc(path: string, identityToken?: string): Promise<Response> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    authorization: `Bearer ${getA2ASharedSecret()}`,
  };
  if (identityToken !== undefined) headers[A2A_CALLER_IDENTITY_HEADER] = identityToken;
  return fetch(`${baseUrl}${path}`, { method: "POST", headers, body: RPC_BODY });
}

describe("A2A caller identity + ABAC scope", () => {
  it("rejects a JSON-RPC call with NO caller-identity token (401)", async () => {
    const res = await postRpc(TRIAGE_AGENT_PATH);
    expect(res.status).toBe(401);
  });

  it("rejects a token whose audience is for a DIFFERENT agent (401)", async () => {
    // A verify-audience token replayed against the triage endpoint.
    const token = await mintCallerToken({
      subject: SUPERVISOR_CALLER_ID,
      audience: VERIFY_AUDIENCE,
      scope: [VERIFY_SKILL],
    });
    const res = await postRpc(TRIAGE_AGENT_PATH, token);
    expect(res.status).toBe(401);
  });

  it("rejects a triage-audience token lacking the triage skill in scope (403)", async () => {
    const token = await mintCallerToken({
      subject: SUPERVISOR_CALLER_ID,
      audience: TRIAGE_AUDIENCE,
      scope: [VERIFY_SKILL], // wrong skill for this agent
    });
    const res = await postRpc(TRIAGE_AGENT_PATH, token);
    expect(res.status).toBe(403);
  });

  it("rejects a tampered token (401)", async () => {
    const token = await mintCallerToken({
      subject: SUPERVISOR_CALLER_ID,
      audience: TRIAGE_AUDIENCE,
      scope: [TRIAGE_SKILL],
    });
    const tampered = `${token.slice(0, -3)}AAA`;
    const res = await postRpc(TRIAGE_AGENT_PATH, tampered);
    expect(res.status).toBe(401);
  });

  it("accepts a correctly-scoped triage token (200)", async () => {
    __setLlmRuntimeForTest(makeRuntime([TRIAGE_JSON]));
    const token = await mintCallerToken({
      subject: SUPERVISOR_CALLER_ID,
      audience: TRIAGE_AUDIENCE,
      scope: [TRIAGE_SKILL],
    });
    const res = await postRpc(TRIAGE_AGENT_PATH, token);
    expect(res.status).toBe(200);
  });

  it("verify endpoint rejects a triage-scoped token (401 audience mismatch)", async () => {
    const token = await mintCallerToken({
      subject: SUPERVISOR_CALLER_ID,
      audience: TRIAGE_AUDIENCE,
      scope: [TRIAGE_SKILL],
    });
    const res = await postRpc(VERIFY_AGENT_PATH, token);
    expect(res.status).toBe(401);
  });
});

// ---------------------------------------------------------------------------
// Cross-cloud mTLS transport seam (threat_model §Spoofing — "A2A caller
// identity" / §Information Disclosure — "TLS everywhere"). The seam is INERT by
// default (loopback dev has no PKI); these tests toggle A2A_REQUIRE_MTLS within
// a try/finally and reset transport state so the rest of the suite (which runs
// against the same live server) is unaffected.
// ---------------------------------------------------------------------------

type PeerCertObject = {
  subject?: Record<string, string | string[]> | string;
  subjectaltname?: string;
};

type FakeReq = {
  path: string;
  baseUrl: string;
  headers: Record<string, string>;
  socket?: {
    authorized?: boolean;
    getPeerCertificate?: (detailed?: boolean) => PeerCertObject | undefined;
  };
  header(name: string): string | undefined;
};

function fakeReq(opts: {
  headers?: Record<string, string>;
  authorized?: boolean;
  baseUrl?: string;
  path?: string;
  peerCert?: PeerCertObject;
}): FakeReq {
  const headers = Object.fromEntries(
    Object.entries(opts.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const needsSocket = opts.authorized !== undefined || opts.peerCert !== undefined;
  return {
    baseUrl: opts.baseUrl ?? "/a2a/triage",
    path: opts.path ?? "/",
    headers,
    socket: needsSocket
      ? {
          authorized: opts.authorized,
          getPeerCertificate:
            opts.peerCert === undefined ? undefined : () => opts.peerCert,
        }
      : undefined,
    header(name: string) {
      return headers[name.toLowerCase()];
    },
  };
}

function runMiddleware(req: FakeReq): {
  status?: number;
  nextCalled: boolean;
  ledgerCalls: Array<Record<string, unknown>>;
} {
  let status: number | undefined;
  let nextCalled = false;
  const ledgerCalls: Array<Record<string, unknown>> = [];
  const res = {
    status(code: number) {
      status = code;
      return this;
    },
    json() {
      return this;
    },
  };
  // Inject a fake ledger writer so this offline suite never touches the DB while
  // still asserting the refusal is recorded.
  const middleware = createA2AMtlsMiddleware((input) => {
    ledgerCalls.push(input as unknown as Record<string, unknown>);
    return Promise.resolve();
  });
  middleware(
    req as never,
    res as never,
    () => {
      nextCalled = true;
    },
  );
  return { status, nextCalled, ledgerCalls };
}

describe("A2A mTLS transport seam", () => {
  const ENV_KEYS = [
    "A2A_REQUIRE_MTLS",
    "A2A_MTLS_CERT",
    "A2A_MTLS_KEY",
    "A2A_MTLS_CA",
    "A2A_MTLS_CLIENT_VERIFY_HEADER",
    "A2A_MTLS_CLIENT_VERIFY_VALUE",
  ];
  let saved: Record<string, string | undefined>;

  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    __resetA2ATransportForTest();
  });

  it("is inert by default — middleware passes through and is not required", () => {
    delete process.env["A2A_REQUIRE_MTLS"];
    expect(isA2AMtlsRequired()).toBe(false);
    const { nextCalled, status } = runMiddleware(fakeReq({}));
    expect(nextCalled).toBe(true);
    expect(status).toBeUndefined();
  });

  it("recognizes truthy A2A_REQUIRE_MTLS values", () => {
    process.env["A2A_REQUIRE_MTLS"] = "true";
    expect(isA2AMtlsRequired()).toBe(true);
    process.env["A2A_REQUIRE_MTLS"] = "1";
    expect(isA2AMtlsRequired()).toBe(true);
    process.env["A2A_REQUIRE_MTLS"] = "0";
    expect(isA2AMtlsRequired()).toBe(false);
  });

  it("refuses 403 when required but no verified client cert is present", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { nextCalled, status } = runMiddleware(fakeReq({}));
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
  });

  it("ledgers the refusal (system-scoped, no PHI/headers) on 403", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { status, ledgerCalls } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "FAILED" } }),
    );
    expect(status).toBe(403);
    expect(ledgerCalls).toHaveLength(1);
    const entry = ledgerCalls[0]!;
    expect(entry["eventType"]).toBe("a2a.transport_rejected");
    expect(entry["tenantId"]).toBeNull();
    expect(entry["actor"]).toEqual({ kind: "system", id: "a2a_transport" });
    // Payload must carry only the fixed route + static reason — never the
    // attacker-influenced verify header value.
    expect(entry["payload"]).toEqual({
      route: "/a2a/triage",
      reason: "no_verified_client_cert",
    });
    expect(JSON.stringify(entry)).not.toContain("FAILED");
  });

  it("records the fixed mount route, not the attacker-influenced request path", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { ledgerCalls } = runMiddleware(
      fakeReq({
        baseUrl: "/a2a/verify",
        path: "/extra/evil-suffix",
        headers: { "x-ssl-client-verify": "FAILED" },
      }),
    );
    expect(ledgerCalls).toHaveLength(1);
    const payload = ledgerCalls[0]!["payload"] as Record<string, unknown>;
    expect(payload["route"]).toBe("/a2a/verify");
    // The manipulated request-path suffix must not leak into the ledger entry.
    expect(JSON.stringify(ledgerCalls[0])).not.toContain("evil-suffix");
  });

  it("does not ledger when the request is accepted", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { nextCalled, ledgerCalls } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "SUCCESS" } }),
    );
    expect(nextCalled).toBe(true);
    expect(ledgerCalls).toHaveLength(0);
  });

  it("does not ledger when mTLS is inert (not required)", () => {
    delete process.env["A2A_REQUIRE_MTLS"];
    const { nextCalled, ledgerCalls } = runMiddleware(fakeReq({}));
    expect(nextCalled).toBe(true);
    expect(ledgerCalls).toHaveLength(0);
  });

  it("accepts a request whose ingress stamped the default verify header", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { nextCalled, status } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "SUCCESS" } }),
    );
    expect(nextCalled).toBe(true);
    expect(status).toBeUndefined();
  });

  it("rejects a verify header with the wrong value (e.g. FAILED)", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { nextCalled, status } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "FAILED" } }),
    );
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
  });

  it("honors a configurable verify header name + value", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_CLIENT_VERIFY_HEADER"] = "x-client-verified";
    process.env["A2A_MTLS_CLIENT_VERIFY_VALUE"] = "ok";
    expect(
      hasVerifiedClientCert(fakeReq({ headers: { "x-client-verified": "OK" } })),
    ).toBe(true);
    // The default header no longer applies once a custom one is configured.
    expect(
      hasVerifiedClientCert(fakeReq({ headers: { "x-ssl-client-verify": "SUCCESS" } })),
    ).toBe(false);
  });

  it("accepts a directly-terminated authorized TLS socket", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    const { nextCalled } = runMiddleware(fakeReq({ authorized: true }));
    expect(nextCalled).toBe(true);
  });

  it("client dispatcher is undefined when mTLS is not required", async () => {
    delete process.env["A2A_REQUIRE_MTLS"];
    __resetA2ATransportForTest();
    await expect(getA2AClientDispatcher()).resolves.toBeUndefined();
  });

  it("client dispatcher fails closed when required but cert/key are unset", async () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    delete process.env["A2A_MTLS_CERT"];
    delete process.env["A2A_MTLS_KEY"];
    __resetA2ATransportForTest();
    await expect(getA2AClientDispatcher()).rejects.toThrow(/A2A_MTLS_CERT/);
  });

  it("the live server returns 403 (mTLS) before 401 (shared-secret) when enforced", async () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    try {
      // No verify header, no bearer: mTLS is outermost so it short-circuits 403.
      const res = await fetch(`${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`);
      expect(res.status).toBe(403);
      // With the ingress verify header it passes mTLS and falls through to the
      // shared-secret layer, which rejects the missing bearer with 401.
      const res2 = await fetch(`${baseUrl}${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`, {
        headers: { "x-ssl-client-verify": "SUCCESS" },
      });
      expect(res2.status).toBe(401);
    } finally {
      delete process.env["A2A_REQUIRE_MTLS"];
    }
  });
});

// ---------------------------------------------------------------------------
// Per-claim ABAC against the mTLS peer's certificate identity (SAN/DN).
// Both controls (peer allow-list + peer↔caller binding) are INERT unless
// configured; these tests toggle env in a save/restore block so the rest of the
// suite (live server) is unaffected.
// ---------------------------------------------------------------------------

// Self-signed test cert: subject CN=supervisor.phi.svc,O=phi-audit;
// SAN URI:spiffe://cluster.local/ns/phi/sa/supervisor, DNS:supervisor.phi.svc.
const TEST_PEER_PEM = `-----BEGIN CERTIFICATE-----
MIIDkTCCAnmgAwIBAgIUQZYO9YR7Dqs7rUSz6iIEQomC2x0wDQYJKoZIhvcNAQEL
BQAwMTEbMBkGA1UEAwwSc3VwZXJ2aXNvci5waGkuc3ZjMRIwEAYDVQQKDAlwaGkt
YXVkaXQwHhcNMjYwNjA0MDIxODI4WhcNMzYwNjAxMDIxODI4WjAxMRswGQYDVQQD
DBJzdXBlcnZpc29yLnBoaS5zdmMxEjAQBgNVBAoMCXBoaS1hdWRpdDCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZ0ItYTRn9+ol15zmLsOOs6mXWu1ZO/
G9umq5Q5nR383pOMTpjlFB81oPcLEUzl02kBO/PrFYmqv1HlGCZdrmOGmm2VNnTk
Oh6gJIhmOhoTydQ6VeEO3mcQUFk+OibmLQIRvTHY60zClt5bI9ETQjDxfP2j0BcP
RXr0zYkHvi4M3Cd0siOxCEq9mCUZrEM3X8ZMEI7w91INW8B7vF2BsLTMa9KM6nDw
1YfJxZJlYxW63Pb4x0XH2FvNVtcz/XPKYMO6DLg71H1LFm3sBhGqc78LEL4x8AwI
u68tjx3QoWF2tyUpG3MkxeX0lSZY0eI+QpbFShMDIJhqgWuOmOgyqH0CAwEAAaOB
oDCBnTAdBgNVHQ4EFgQUJRnkJgzJwDrewoA+PfTFsx3yCE0wHwYDVR0jBBgwFoAU
JRnkJgzJwDrewoA+PfTFsx3yCE0wDwYDVR0TAQH/BAUwAwEB/zBKBgNVHREEQzBB
hitzcGlmZmU6Ly9jbHVzdGVyLmxvY2FsL25zL3BoaS9zYS9zdXBlcnZpc29yghJz
dXBlcnZpc29yLnBoaS5zdmMwDQYJKoZIhvcNAQELBQADggEBAMT5RsIg7dZCq0L4
XZcpkq73KjVFswk8iQzgfiXeKmn3H4xPWaU3UKPigek1vU4IvI5srt0HSWpp06L8
aFll7YQSDNSrrQnThA55aEX8Udr74XR0D0PH3Se39gNkMb4Kh/zWQTRAFWxG7fgk
olv77JXWR3jvU7eWgB3+pWrX5L0KWjcefsEgNOfwkhiEn/Y+kHI1yJa0ZNlspBEC
zBnaQKrWZgYNxihcLVlFAPEYKRmKsMLjsEIKAkal377xEmMtt0tF80IRvTyn84oE
Xm9wvhQFuedB+bG588IbWnwZjnP5lE+9x4ZVbaMNJY3aMeuFqnUichAczSXQ8baO
jV0NQt4=
-----END CERTIFICATE-----`;

const SUPERVISOR_SPIFFE = "spiffe://cluster.local/ns/phi/sa/supervisor";

// getPeerCertificate()-shaped object for the direct-TLS path.
const DIRECT_PEER_CERT = {
  subject: { CN: "supervisor.phi.svc", O: "phi-audit" },
  subjectaltname: `URI:${SUPERVISOR_SPIFFE}, DNS:supervisor.phi.svc`,
};

function runBinding(opts: {
  peer: PeerIdentity | null;
  caller?: { subject: string; scope: string[] };
  baseUrl?: string;
}): { status?: number; nextCalled: boolean; ledgerCalls: Array<Record<string, unknown>> } {
  let status: number | undefined;
  let nextCalled = false;
  const ledgerCalls: Array<Record<string, unknown>> = [];
  const req = {
    baseUrl: opts.baseUrl ?? "/a2a/triage",
    a2aPeer: opts.peer,
    a2aCaller: opts.caller,
  };
  const res = {
    status(code: number) {
      status = code;
      return this;
    },
    json() {
      return this;
    },
  };
  const mw = createA2APeerBindingMiddleware((input) => {
    ledgerCalls.push(input as unknown as Record<string, unknown>);
    return Promise.resolve();
  });
  mw(req as never, res as never, () => {
    nextCalled = true;
  });
  return { status, nextCalled, ledgerCalls };
}

describe("A2A peer-identity extraction", () => {
  it("extracts SAN + subject from a directly-terminated TLS socket", () => {
    const peer = extractPeerIdentity(fakeReq({ peerCert: DIRECT_PEER_CERT }) as never);
    expect(peer).not.toBeNull();
    expect(peer!.subjectCN).toBe("supervisor.phi.svc");
    expect(peer!.sans).toContain(`URI:${SUPERVISOR_SPIFFE}`);
    expect(peer!.sans).toContain("DNS:supervisor.phi.svc");
    // Bare-value identifiers are derived for matching.
    expect(peerIdentifiers(peer!)).toContain(SUPERVISOR_SPIFFE);
  });

  it("parses an ingress-forwarded URL-encoded client cert PEM (SAN + subject)", () => {
    const req = fakeReq({
      headers: { "x-ssl-client-cert": encodeURIComponent(TEST_PEER_PEM) },
    });
    const peer = extractPeerIdentity(req as never);
    expect(peer).not.toBeNull();
    expect(peer!.subjectCN).toBe("supervisor.phi.svc");
    expect(peerIdentifiers(peer!)).toContain(SUPERVISOR_SPIFFE);
  });

  it("falls back to an ingress-forwarded subject-DN header", () => {
    const req = fakeReq({
      headers: { "x-ssl-client-subject-dn": "CN=supervisor.phi.svc,O=phi-audit" },
    });
    const peer = extractPeerIdentity(req as never);
    expect(peer).not.toBeNull();
    expect(peer!.subjectCN).toBe("supervisor.phi.svc");
    expect(peer!.sans).toHaveLength(0);
  });

  it("returns null when no certificate identity is recoverable", () => {
    expect(extractPeerIdentity(fakeReq({ headers: {} }) as never)).toBeNull();
  });
});

describe("A2A peer allow-list + binding helpers", () => {
  const ENV_KEYS = ["A2A_MTLS_ALLOWED_PEERS", "A2A_MTLS_PEER_BINDINGS"];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  const PEER: PeerIdentity = {
    sans: [`URI:${SUPERVISOR_SPIFFE}`, "DNS:supervisor.phi.svc"],
    subjectDN: "CN=supervisor.phi.svc,O=phi-audit",
    subjectCN: "supervisor.phi.svc",
  };

  it("getAllowedPeers is null when unset (control inert)", () => {
    delete process.env["A2A_MTLS_ALLOWED_PEERS"];
    expect(getAllowedPeers()).toBeNull();
  });

  it("matches on bare SAN value, raw SAN, CN, and DN", () => {
    expect(peerMatchesAllowList(PEER, [SUPERVISOR_SPIFFE])).toBe(true);
    expect(peerMatchesAllowList(PEER, [`URI:${SUPERVISOR_SPIFFE}`])).toBe(true);
    expect(peerMatchesAllowList(PEER, ["supervisor.phi.svc"])).toBe(true);
    expect(peerMatchesAllowList(PEER, ["CN=supervisor.phi.svc,O=phi-audit"])).toBe(true);
    expect(peerMatchesAllowList(PEER, ["spiffe://cluster.local/ns/phi/sa/attacker"])).toBe(
      false,
    );
  });

  it("getPeerBindings parses peer=subject pairs and binds correctly", () => {
    process.env["A2A_MTLS_PEER_BINDINGS"] = `${SUPERVISOR_SPIFFE}=${SUPERVISOR_CALLER_ID}`;
    const bindings = getPeerBindings();
    expect(bindings).not.toBeNull();
    expect(peerSatisfiesBinding(PEER, SUPERVISOR_CALLER_ID, bindings!)).toBe(true);
    // A different claimed subject is not bound to this peer.
    expect(peerSatisfiesBinding(PEER, "attacker", bindings!)).toBe(false);
  });

  it("getPeerBindings is null when unset and ignores malformed entries", () => {
    delete process.env["A2A_MTLS_PEER_BINDINGS"];
    expect(getPeerBindings()).toBeNull();
    process.env["A2A_MTLS_PEER_BINDINGS"] = "no-equals-sign";
    expect(getPeerBindings()).toBeNull();
  });
});

describe("A2A transport peer allow-list enforcement", () => {
  const ENV_KEYS = ["A2A_REQUIRE_MTLS", "A2A_MTLS_ALLOWED_PEERS"];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    __resetA2ATransportForTest();
  });

  it("accepts an allow-listed peer over direct TLS", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_ALLOWED_PEERS"] = SUPERVISOR_SPIFFE;
    const { nextCalled, status, ledgerCalls } = runMiddleware(
      fakeReq({ authorized: true, peerCert: DIRECT_PEER_CERT }),
    );
    expect(nextCalled).toBe(true);
    expect(status).toBeUndefined();
    expect(ledgerCalls).toHaveLength(0);
  });

  it("refuses a non-allow-listed peer (403, reason peer_not_allowed, no DN leak)", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_ALLOWED_PEERS"] = "spiffe://cluster.local/ns/phi/sa/other";
    const { nextCalled, status, ledgerCalls } = runMiddleware(
      fakeReq({ authorized: true, peerCert: DIRECT_PEER_CERT }),
    );
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
    expect(ledgerCalls).toHaveLength(1);
    expect(ledgerCalls[0]!["payload"]).toEqual({
      route: "/a2a/triage",
      reason: "peer_not_allowed",
    });
    // The peer's certificate identity must never enter the ledger payload.
    expect(JSON.stringify(ledgerCalls[0])).not.toContain("supervisor.phi.svc");
    expect(JSON.stringify(ledgerCalls[0])).not.toContain(SUPERVISOR_SPIFFE);
  });

  it("refuses 403 (peer_identity_unavailable) when cert verified but identity unreadable", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_ALLOWED_PEERS"] = SUPERVISOR_SPIFFE;
    // Verify header passes layer 1, but there is no peer cert / DN to inspect.
    const { nextCalled, status, ledgerCalls } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "SUCCESS" } }),
    );
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
    expect(ledgerCalls[0]!["payload"]).toEqual({
      route: "/a2a/triage",
      reason: "peer_identity_unavailable",
    });
  });

  it("does not enforce the allow-list when it is unset (backward compatible)", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    delete process.env["A2A_MTLS_ALLOWED_PEERS"];
    const { nextCalled, status } = runMiddleware(
      fakeReq({ headers: { "x-ssl-client-verify": "SUCCESS" } }),
    );
    expect(nextCalled).toBe(true);
    expect(status).toBeUndefined();
  });
});

describe("A2A peer↔caller binding middleware", () => {
  const ENV_KEYS = ["A2A_REQUIRE_MTLS", "A2A_MTLS_PEER_BINDINGS"];
  let saved: Record<string, string | undefined>;
  beforeEach(() => {
    saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]));
  });
  afterEach(() => {
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  });

  const PEER: PeerIdentity = {
    sans: [`URI:${SUPERVISOR_SPIFFE}`],
    subjectDN: "CN=supervisor.phi.svc,O=phi-audit",
    subjectCN: "supervisor.phi.svc",
  };

  it("is inert when mTLS is not required", () => {
    delete process.env["A2A_REQUIRE_MTLS"];
    process.env["A2A_MTLS_PEER_BINDINGS"] = `${SUPERVISOR_SPIFFE}=${SUPERVISOR_CALLER_ID}`;
    const { nextCalled, ledgerCalls } = runBinding({ peer: null });
    expect(nextCalled).toBe(true);
    expect(ledgerCalls).toHaveLength(0);
  });

  it("is inert when no bindings are configured", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    delete process.env["A2A_MTLS_PEER_BINDINGS"];
    const { nextCalled, ledgerCalls } = runBinding({ peer: null });
    expect(nextCalled).toBe(true);
    expect(ledgerCalls).toHaveLength(0);
  });

  it("accepts when the peer is bound to the verified caller subject", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_PEER_BINDINGS"] = `${SUPERVISOR_SPIFFE}=${SUPERVISOR_CALLER_ID}`;
    const { nextCalled, status, ledgerCalls } = runBinding({
      peer: PEER,
      caller: { subject: SUPERVISOR_CALLER_ID, scope: [TRIAGE_SKILL] },
    });
    expect(nextCalled).toBe(true);
    expect(status).toBeUndefined();
    expect(ledgerCalls).toHaveLength(0);
  });

  it("refuses (403, peer_subject_mismatch) when cert identity != claimed subject", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_PEER_BINDINGS"] = `${SUPERVISOR_SPIFFE}=${SUPERVISOR_CALLER_ID}`;
    // Valid supervisor cert, but the JWT claims to be a different subject.
    const { nextCalled, status, ledgerCalls } = runBinding({
      peer: PEER,
      caller: { subject: "attacker", scope: [TRIAGE_SKILL] },
    });
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
    expect(ledgerCalls).toHaveLength(1);
    expect(ledgerCalls[0]!["eventType"]).toBe("a2a.transport_rejected");
    expect(ledgerCalls[0]!["payload"]).toEqual({
      route: "/a2a/triage",
      reason: "peer_subject_mismatch",
    });
    // No certificate identity in the ledger payload.
    expect(JSON.stringify(ledgerCalls[0])).not.toContain("supervisor.phi.svc");
  });

  it("refuses when the peer identity is missing entirely", () => {
    process.env["A2A_REQUIRE_MTLS"] = "1";
    process.env["A2A_MTLS_PEER_BINDINGS"] = `${SUPERVISOR_SPIFFE}=${SUPERVISOR_CALLER_ID}`;
    const { nextCalled, status, ledgerCalls } = runBinding({
      peer: null,
      caller: { subject: SUPERVISOR_CALLER_ID, scope: [TRIAGE_SKILL] },
    });
    expect(nextCalled).toBe(false);
    expect(status).toBe(403);
    expect(ledgerCalls[0]!["payload"]).toMatchObject({ reason: "peer_subject_mismatch" });
  });
});
