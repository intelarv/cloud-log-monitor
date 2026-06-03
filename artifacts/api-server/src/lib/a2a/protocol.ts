// A2A wire contract (M-A2A). Defines the agent-to-agent message payloads the
// Supervisor and the specialist agents (Triage, Verifier) exchange over the
// official A2A protocol (@a2a-js/sdk), plus the `AgentInvoker` seam the
// Supervisor calls through.
//
// SECURITY (threat_model §Information Disclosure): every payload that crosses
// the A2A boundary carries the REDACTED finding projection (`FindingSafe`) only
// — `rawEvidence` is excluded by construction at the DB layer
// (`findingSafeColumns`), so no raw PHI can ride the wire. Verdict rationale
// returned by an agent is re-scanned (`scanForPhi`) by the Supervisor BEFORE it
// is ledgered, exactly as in the previous in-process path.

import { z } from "zod/v4";
import type { FindingSafe } from "@workspace/db";
import { triageVerdictSchema, type TriageVerdict } from "../agents/triage";
import { verifierVerdictSchema, type VerifierVerdict } from "../agents/verifier";

// ---------------------------------------------------------------------------
// DataPart payload schemas (the `data` object inside an A2A DataPart).
// ---------------------------------------------------------------------------

// The redacted evidence projection the agents read (already PHI-scrubbed at the
// detector stage). Internal shape is permissive but bounded to known keys.
const redactedEvidenceSchema = z.object({
  snippet: z.string().optional(),
  trust: z.string().optional(),
  redactions: z.array(z.string()).optional(),
  truncated: z.boolean().optional(),
});

// The Supervisor sends the redacted finding to the agents. This schema lists
// EVERY field the agents actually consume; Zod's default object parse STRIPS all
// other keys, so `rawEvidence` / `rawEvidenceRef` (or any unexpected field)
// cannot cross the A2A boundary even if a buggy/compromised caller included it.
// Executors forward the PARSED output (not the raw inbound object), making the
// redacted-only guarantee an enforced boundary rather than an assumption.
const findingShapeSchema = z.object({
  id: z.string(),
  classification: z.string(),
  subclass: z.string().nullable().optional(),
  severity: z.string(),
  source: z.string(),
  detectorVersion: z.string(),
  redactedEvidence: redactedEvidenceSchema.nullable().optional(),
});

export const triageRequestSchema = z.object({
  kind: z.literal("triage_request"),
  finding: findingShapeSchema,
});

export const triageResponseSchema = z.object({
  kind: z.literal("triage_response"),
  verdict: triageVerdictSchema,
  approxOutputTokens: z.number().int().nonnegative(),
  modelId: z.string(),
});

export const verifyRequestSchema = z.object({
  kind: z.literal("verify_request"),
  finding: findingShapeSchema,
  triage: triageVerdictSchema,
});

export const verifyResponseSchema = z.object({
  kind: z.literal("verify_response"),
  verdict: verifierVerdictSchema,
  approxOutputTokens: z.number().int().nonnegative(),
  modelId: z.string(),
});

// ---------------------------------------------------------------------------
// AgentInvoker seam.
// ---------------------------------------------------------------------------

export interface TriageInvokeResult {
  verdict: TriageVerdict;
  approxOutputTokens: number;
  modelId: string;
}

export interface VerifierInvokeResult {
  verdict: VerifierVerdict;
  approxOutputTokens: number;
  modelId: string;
}

/** The Supervisor depends only on this interface. Production wires the A2A
 *  client implementation (`A2AAgentInvoker`, JSON-RPC over loopback); tests
 *  inject `inProcessAgentInvoker` to stay hermetic/offline. */
export interface AgentInvoker {
  triage(finding: FindingSafe): Promise<TriageInvokeResult>;
  verify(finding: FindingSafe, triage: TriageVerdict): Promise<VerifierInvokeResult>;
}

// Loopback agent route paths. The agent endpoints are deliberately NOT in the
// shared proxy's path table (only `/api` is), so they are reachable only from
// within this process over loopback — the Supervisor calling its own
// co-located agents. This keeps the agent plane off the public surface while
// still genuinely speaking the A2A protocol.
export const TRIAGE_AGENT_PATH = "/a2a/triage";
export const VERIFY_AGENT_PATH = "/a2a/verify";
export const A2A_CARD_SUFFIX = "/.well-known/agent-card.json";

export const A2A_PROTOCOL_VERSION = "0.3.0";
