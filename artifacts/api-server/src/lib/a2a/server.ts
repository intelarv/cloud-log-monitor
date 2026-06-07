// Mounts the Triage + Verifier specialist agents as real A2A servers on the
// Express app. Each agent gets:
//   GET  <path>/.well-known/agent-card.json  — its Agent Card (shared-secret)
//   POST <path>                              — JSON-RPC message/send endpoint
//                                              (shared-secret + caller-identity
//                                              JWT + ABAC scope check)
//
// Defense-in-depth ladder on the JSON-RPC endpoint (threat_model §Spoofing /
// §Elevation of Privilege — "A2A authorization"):
//   1. a2aAuthMiddleware    — shared-secret bearer: is this a known caller?
//   2. a2aScopeMiddleware   — signed caller-identity JWT (WHO) + ABAC: is this
//                             caller authorized for THIS agent's skill? A token
//                             minted for triage cannot be replayed against the
//                             verifier (audience-bound) and a caller without the
//                             skill in its `scope` claim is rejected 403.
//
// CROSS-CLOUD / mTLS SEAM: in a multi-cluster deployment the loopback transport
// is replaced by an mTLS channel between clusters (network-layer caller auth);
// the same caller-identity JWT rides inside it for application-layer ABAC. The
// dev sandbox has no PKI, so loopback runs plaintext but keeps the JWT layer.
// `A2A_REQUIRE_MTLS` is reserved to assert client-cert termination at the
// ingress in production; it is intentionally inert in loopback dev.
//
// Cards are computed per-request from `getA2ABaseUrl()` so an ephemeral test
// port (set via A2A_BASE_URL) is reflected without re-mounting.

import type { Express } from "express";
import {
  DefaultRequestHandler,
  InMemoryTaskStore,
} from "@a2a-js/sdk/server";
import {
  agentCardHandler,
  jsonRpcHandler,
  UserBuilder,
} from "@a2a-js/sdk/server/express";
import { TriageExecutor, VerifierExecutor } from "./executors";
import { buildTriageCard, buildVerifierCard } from "./cards";
import { a2aAuthMiddleware, getA2ABaseUrl } from "./auth";
import { a2aMtlsMiddleware } from "./transport";
import { a2aPeerBindingMiddleware } from "./peer-identity";
import {
  a2aScopeMiddleware,
  TRIAGE_AUDIENCE,
  VERIFY_AUDIENCE,
  TRIAGE_SKILL,
  VERIFY_SKILL,
} from "./caller-identity";
import {
  A2A_CARD_SUFFIX,
  TRIAGE_AGENT_PATH,
  VERIFY_AGENT_PATH,
} from "./protocol";

export function mountA2AAgents(app: Express): void {
  const baseUrl = getA2ABaseUrl();

  const triageHandler = new DefaultRequestHandler(
    buildTriageCard(baseUrl),
    new InMemoryTaskStore(),
    new TriageExecutor(),
  );
  app.use(
    `${TRIAGE_AGENT_PATH}${A2A_CARD_SUFFIX}`,
    a2aMtlsMiddleware,
    a2aAuthMiddleware,
    agentCardHandler({
      agentCardProvider: () => Promise.resolve(buildTriageCard(getA2ABaseUrl())),
    }),
  );
  app.use(
    TRIAGE_AGENT_PATH,
    a2aMtlsMiddleware,
    a2aAuthMiddleware,
    a2aScopeMiddleware({ audience: TRIAGE_AUDIENCE, requiredSkill: TRIAGE_SKILL }),
    a2aPeerBindingMiddleware,
    jsonRpcHandler({
      requestHandler: triageHandler,
      userBuilder: UserBuilder.noAuthentication,
    }),
  );

  const verifierHandler = new DefaultRequestHandler(
    buildVerifierCard(baseUrl),
    new InMemoryTaskStore(),
    new VerifierExecutor(),
  );
  app.use(
    `${VERIFY_AGENT_PATH}${A2A_CARD_SUFFIX}`,
    a2aMtlsMiddleware,
    a2aAuthMiddleware,
    agentCardHandler({
      agentCardProvider: () => Promise.resolve(buildVerifierCard(getA2ABaseUrl())),
    }),
  );
  app.use(
    VERIFY_AGENT_PATH,
    a2aMtlsMiddleware,
    a2aAuthMiddleware,
    a2aScopeMiddleware({ audience: VERIFY_AUDIENCE, requiredSkill: VERIFY_SKILL }),
    a2aPeerBindingMiddleware,
    jsonRpcHandler({
      requestHandler: verifierHandler,
      userBuilder: UserBuilder.noAuthentication,
    }),
  );
}
