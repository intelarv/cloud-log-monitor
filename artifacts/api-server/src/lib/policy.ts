// Per-agent tool allow-list. The Chat Agent can only invoke read-only tools
// in M0 (`get_finding`). Triage / Verifier / Notifier / Remediation are
// stubbed for later milestones — listing them here makes the boundary
// auditable from one place. See ARCHITECTURE.md §23.1 + §23.17.

export type AgentName =
  | "chat"
  | "triage"
  | "verifier"
  | "notifier"
  | "remediation";

export type ToolName = "get_finding";

const ALLOW_LIST: Record<AgentName, ReadonlySet<ToolName>> = {
  chat: new Set<ToolName>(["get_finding"]),
  triage: new Set<ToolName>([]),
  verifier: new Set<ToolName>([]),
  notifier: new Set<ToolName>([]),
  remediation: new Set<ToolName>([]),
};

export function isToolAllowed(agent: AgentName, tool: ToolName): boolean {
  return ALLOW_LIST[agent]?.has(tool) ?? false;
}
