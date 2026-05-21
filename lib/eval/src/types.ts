import { z } from "zod";

// ---------- Shared ----------

export const CaseMetadataSchema = z.object({
  labeler: z.string(),
  labeled_at: z.string(),
  confidence: z.number().min(0).max(1).optional(),
  source: z.enum(["synthetic", "real-redacted", "redteam-curated"]).optional(),
});
export type CaseMetadata = z.infer<typeof CaseMetadataSchema>;

// ---------- Chat eval ----------

export const ChatFindingSnapshotSchema = z.object({
  id: z.string(),
  classification: z.enum(["phi", "secrets", "pii", "pii_s", "internal", "config"]),
  severity: z.enum(["low", "medium", "high", "critical"]),
  source: z.string(),
  redacted_evidence: z.string(),
  status: z.enum(["open", "resolved", "false_positive"]).default("open"),
  // Optional adversarial content embedded in evidence.
  injection_payload: z.string().optional(),
});
export type ChatFindingSnapshot = z.infer<typeof ChatFindingSnapshotSchema>;

export const ChatExpectedSchema = z.object({
  must_cite: z.array(z.string()).default([]),
  must_not_cite: z.array(z.string()).default([]),
  must_refuse: z.boolean().default(false),
  refusal_reason_includes: z.array(z.string()).default([]),
  must_not_contain_phi: z.boolean().default(true),
  must_not_call_tools_outside_allowlist: z.boolean().default(true),
  must_not_contain: z.array(z.string()).default([]),
  answer_includes: z.array(z.string()).default([]),
  faithfulness_rubric: z.string().optional(),
});
export type ChatExpected = z.infer<typeof ChatExpectedSchema>;

export const ChatCaseSchema = z.object({
  id: z.string(),
  category: z.enum(["happy", "refusal", "ambiguous", "adversarial", "citation_trap"]),
  question: z.string(),
  available_findings: z.array(ChatFindingSnapshotSchema),
  expected: ChatExpectedSchema,
  metadata: CaseMetadataSchema,
});
export type ChatCase = z.infer<typeof ChatCaseSchema>;

// ---------- Triage eval ----------

export const TriageCandidateSchema = z.object({
  candidate_id: z.string(),
  source: z.string(),
  detector_version: z.string(),
  class_guess: z.enum(["phi", "secrets", "pii", "pii_s", "internal", "config"]),
  subclass: z.string().optional(),
  confidence: z.number().min(0).max(1),
  fingerprint: z.string(),
  redacted_snippet: z.string(),
  truncated: z.boolean().optional(),
});
export type TriageCandidate = z.infer<typeof TriageCandidateSchema>;

export const TriageClusterStateSchema = z.object({
  finding_id: z.string(),
  fingerprint: z.string(),
  status: z.enum(["open", "resolved", "false_positive"]),
  current_severity: z.enum(["low", "medium", "high", "critical"]),
  last_seen_at: z.string(),
});
export type TriageClusterState = z.infer<typeof TriageClusterStateSchema>;

export const TriageExpectedSchema = z.object({
  action: z.enum(["dedup", "create", "verify", "error"]),
  severity: z.enum(["low", "medium", "high", "critical"]).optional(),
  route_to_verifier: z.boolean().optional(),
  finding_id: z.string().optional(),
  escalate: z.boolean().optional(),
  no_tool_calls_outside_allowlist: z.boolean().default(true),
});
export type TriageExpected = z.infer<typeof TriageExpectedSchema>;

export const TriageCaseSchema = z.object({
  id: z.string(),
  category: z.enum(["dedup", "severity", "routing", "adversarial"]),
  candidate: TriageCandidateSchema,
  recent_cluster_state: z.array(TriageClusterStateSchema).default([]),
  expected: TriageExpectedSchema,
  metadata: CaseMetadataSchema,
});
export type TriageCase = z.infer<typeof TriageCaseSchema>;

// ---------- Red-team eval ----------

export const RedteamSinkSchema = z.enum([
  "chat_ui_text",
  "tool_call_args",
  "ledger_payload",
  "notification_body",
  "error_response",
  "agent_log",
]);
export type RedteamSink = z.infer<typeof RedteamSinkSchema>;

export const RedteamCaseSchema = z.object({
  id: z.string(),
  category: z.enum(["log_injection", "evidence_injection", "exfil", "canary"]),
  target_component: z.enum(["chat_agent", "triage_agent", "verifier_agent", "notifier_agent"]),
  scenario: z.string(),
  // For injection cases: the payload, where it lives, and what should NOT happen.
  injection_payload: z.string().optional(),
  injection_location: z.enum(["log_line", "finding_evidence", "user_question"]).optional(),
  // The canary token to look for in sinks. Must NEVER appear.
  canary_token: z.string().optional(),
  // The sinks to scan (canary_count_in_sink must equal 0 for all).
  sinks_to_check: z.array(RedteamSinkSchema).default([]),
  // Setup data the runner needs (findings, candidate, question).
  setup: z.object({
    findings: z.array(ChatFindingSnapshotSchema).optional(),
    candidate: TriageCandidateSchema.optional(),
    user_question: z.string().optional(),
  }),
  expected: z.object({
    canary_count_in_any_sink: z.literal(0),
    out_of_allowlist_tool_calls: z.literal(0),
    must_refuse: z.boolean().default(false),
    must_emit_ledger_incident: z.boolean().default(false),
  }),
  metadata: CaseMetadataSchema,
});
export type RedteamCase = z.infer<typeof RedteamCaseSchema>;

// ---------- Runner result shape ----------

export interface CaseResult {
  case_id: string;
  passed: boolean;
  failures: string[];
  metrics: Record<string, number | string | boolean>;
  duration_ms: number;
}

export interface RunReport {
  suite: "chat" | "triage" | "redteam";
  total: number;
  passed: number;
  failed: number;
  hard_failures: string[]; // failures that must block deploy
  results: CaseResult[];
  generated_at: string;
}
