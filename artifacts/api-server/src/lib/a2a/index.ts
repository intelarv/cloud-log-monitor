// A2A (agent-to-agent) integration barrel.
//
// The Supervisor talks to the Triage and Verifier specialist agents over the
// official A2A protocol (@a2a-js/sdk) on a loopback transport, instead of the
// previous in-process function calls. See protocol.ts for the wire contract and
// the security rationale (redacted-only payloads, shared-secret caller auth).

export {
  type AgentInvoker,
  type TriageInvokeResult,
  type VerifierInvokeResult,
  TRIAGE_AGENT_PATH,
  VERIFY_AGENT_PATH,
} from "./protocol";
export {
  A2AAgentInvoker,
  inProcessAgentInvoker,
  getAgentInvoker,
  __setAgentInvokerForTest,
  __resetAgentInvokerForTest,
} from "./client";
export { mountA2AAgents } from "./server";
export {
  isA2AMtlsRequired,
  a2aMtlsMiddleware,
  hasVerifiedClientCert,
  getA2AClientDispatcher,
  __resetA2ATransportForTest,
} from "./transport";
export {
  getA2ABaseUrl,
  getA2ASharedSecret,
  __resetA2ASecretForTest,
} from "./auth";
export { buildTriageCard, buildVerifierCard } from "./cards";
export {
  mintCallerToken,
  verifyCallerToken,
  a2aScopeMiddleware,
  CallerIdentityError,
  A2A_CALLER_IDENTITY_HEADER,
  SUPERVISOR_CALLER_ID,
  TRIAGE_AUDIENCE,
  VERIFY_AUDIENCE,
  TRIAGE_SKILL,
  VERIFY_SKILL,
  __resetCallerIdentityForTest,
} from "./caller-identity";
