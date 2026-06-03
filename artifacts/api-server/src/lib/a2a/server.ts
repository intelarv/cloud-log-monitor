// Mounts the Triage + Verifier specialist agents as real A2A servers on the
// Express app. Each agent gets:
//   GET  <path>/.well-known/agent-card.json  — its Agent Card
//   POST <path>                              — JSON-RPC message/send endpoint
// Both are guarded by the shared-secret middleware (loopback-only callers).
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
    a2aAuthMiddleware,
    agentCardHandler({
      agentCardProvider: () => Promise.resolve(buildTriageCard(getA2ABaseUrl())),
    }),
  );
  app.use(
    TRIAGE_AGENT_PATH,
    a2aAuthMiddleware,
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
    a2aAuthMiddleware,
    agentCardHandler({
      agentCardProvider: () => Promise.resolve(buildVerifierCard(getA2ABaseUrl())),
    }),
  );
  app.use(
    VERIFY_AGENT_PATH,
    a2aAuthMiddleware,
    jsonRpcHandler({
      requestHandler: verifierHandler,
      userBuilder: UserBuilder.noAuthentication,
    }),
  );
}
