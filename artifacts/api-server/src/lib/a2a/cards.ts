// A2A Agent Cards (threat_model §Spoofing — capability cards MUST NOT advertise
// tools outside scope). Each specialist agent publishes a minimal card whose
// `url` points at its own JSON-RPC endpoint. Cards are built from the runtime
// base URL so the served card and the loopback client always agree.

import type { AgentCard } from "@a2a-js/sdk";
import {
  A2A_PROTOCOL_VERSION,
  TRIAGE_AGENT_PATH,
  VERIFY_AGENT_PATH,
} from "./protocol";

const COMMON = {
  protocolVersion: A2A_PROTOCOL_VERSION,
  preferredTransport: "JSONRPC",
  provider: {
    organization: "PHI Audit",
    url: "https://example.invalid/phi-audit",
  },
  // Data-only agents: redacted finding in, structured verdict out.
  defaultInputModes: ["application/json"],
  defaultOutputModes: ["application/json"],
  // Loopback request/response; no SSE streaming on the agent plane.
  capabilities: { streaming: false },
  version: "1.0.0",
} satisfies Partial<AgentCard>;

export function buildTriageCard(baseUrl: string): AgentCard {
  return {
    ...COMMON,
    name: "Triage Agent",
    description:
      "Classifies a redacted PHI/PII/secret finding and recommends a severity and action. Operates on the redacted finding projection only.",
    url: `${baseUrl}${TRIAGE_AGENT_PATH}`,
    skills: [
      {
        id: "triage_finding",
        name: "Triage finding",
        description:
          "Given a redacted finding, return recommended_severity, recommended_action, rationale, confidence, and a prompt-injection flag.",
        tags: ["triage", "phi", "compliance"],
      },
    ],
  };
}

export function buildVerifierCard(baseUrl: string): AgentCard {
  return {
    ...COMMON,
    name: "Verifier Agent",
    description:
      "Second-opinion reviewer that confirms or challenges a triage verdict on a redacted finding. Operates on the redacted finding projection only.",
    url: `${baseUrl}${VERIFY_AGENT_PATH}`,
    skills: [
      {
        id: "verify_finding",
        name: "Verify finding",
        description:
          "Given a redacted finding and a triage verdict, return verdict, rationale, confidence, agreement, and a prompt-injection flag.",
        tags: ["verify", "phi", "compliance"],
      },
    ],
  };
}
