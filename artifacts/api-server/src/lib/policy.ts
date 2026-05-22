// Per-agent tool allow-list + per-call argument revalidation.
//
// Threat model §EoP ("Prompt-injection defense") requires two layers on every
// tool call:
//
//   1. An agent → tool allow-list. The Chat Agent cannot call write tools;
//      Notifier cannot read raw PHI; etc. Enforced by `isToolAllowed`.
//
//   2. A *post-Zod* policy pass on tool arguments — the "tool-arg revalidation"
//      mitigation called out in ARCHITECTURE.md §23.1. Zod proves arguments
//      have the right *shape*; the policy pass proves they don't violate
//      cross-cutting invariants: no canary tokens in args, no PHI in args,
//      args within size cap, identifiers within format whitelist. A
//      compromised/injected agent can produce arguments that Zod-validate
//      but still smuggle data — this layer is what catches that.

import { CANARY_TOKEN } from "@workspace/db";
import { scanForPhi } from "./redact";

export type AgentName =
  | "chat"
  | "triage"
  | "verifier"
  | "notifier"
  | "remediation";

export type ToolName = "get_finding" | "search_findings";

const ALLOW_LIST: Record<AgentName, ReadonlySet<ToolName>> = {
  // Chat agent: read-only retrieval. `search_findings` (M1) lets the agent
  // pull additional candidates by query when the pre-loaded context doesn't
  // cover what the user asked about; `get_finding` reads one row by id.
  chat: new Set<ToolName>(["get_finding", "search_findings"]),
  triage: new Set<ToolName>([]),
  verifier: new Set<ToolName>([]),
  notifier: new Set<ToolName>([]),
  remediation: new Set<ToolName>([]),
};

export function isToolAllowed(agent: AgentName, tool: ToolName): boolean {
  return ALLOW_LIST[agent]?.has(tool) ?? false;
}

// ---------------------------------------------------------------------------
// Tool-arg policy validation
// ---------------------------------------------------------------------------

// Cap on the serialized size of a tool's argument object. A well-behaved tool
// call is a few hundred bytes (a finding id, or a short search query); 8KB
// gives plenty of head-room and turns "agent crammed a megabyte of context
// into a tool arg" into an immediate refusal.
export const MAX_ARGS_SERIALIZED_BYTES = 8 * 1024;

// finding_id is the only identifier we accept from agent-generated args.
// Whitelist its format so a future tool can't be tricked into accepting
// `../../../etc/passwd`-style paths or SQL-injection-shaped strings as ids.
// (RLS + parameterized queries already block these; defense in depth.)
const FINDING_ID_RE = /^[A-Za-z0-9_-]{1,64}$/;

export interface PolicyViolation {
  // Stable enum, suitable for ledger payloads + alerting rules.
  kind:
    | "canary_token_in_args"
    | "phi_in_args"
    | "args_too_large"
    | "bad_finding_id_format";
  message: string;
}

export interface PolicyValidationResult {
  ok: boolean;
  violations: PolicyViolation[];
  /** True iff any violation has kind === "canary_token_in_args". */
  canaryTripped: boolean;
}

/**
 * Walk every string in an arbitrary tool-arg object and run policy checks.
 * Pure function — no I/O, no DB. The caller (chat-agent / tool route) is
 * responsible for emitting the ledger entry + creating the incident finding
 * when violations are returned.
 */
export function validateToolArgs(
  tool: ToolName,
  args: unknown,
): PolicyValidationResult {
  const violations: PolicyViolation[] = [];

  // Size cap. JSON.stringify is bounded by the prior Zod parse already (Zod
  // does not bound serialized size, only individual field maxes), but this
  // is the single check that catches "string of length N times M fields"
  // blow-ups.
  let serialized: string;
  try {
    serialized = JSON.stringify(args);
  } catch {
    serialized = "";
  }
  if (Buffer.byteLength(serialized, "utf8") > MAX_ARGS_SERIALIZED_BYTES) {
    violations.push({
      kind: "args_too_large",
      message: `tool args exceed ${MAX_ARGS_SERIALIZED_BYTES} bytes serialized`,
    });
  }

  // Collect every string leaf for content scans.
  const strings = collectStrings(args);

  // Canary scan. Any appearance of the honeypot canary token in tool args
  // proves prompt injection succeeded — the agent saw the canary in
  // <FINDING_EVIDENCE> tagged as untrusted data and chose to pass it into a
  // tool argument. Critical-severity finding + alert.
  // See ARCHITECTURE.md §23.1 + threat_model.md §EoP "Honeypot canaries".
  const canaryHit = strings.some((s) => s.includes(CANARY_TOKEN));
  if (canaryHit) {
    violations.push({
      kind: "canary_token_in_args",
      message: "honeypot canary token detected in tool argument",
    });
  }

  // PHI scan. The agent only sees redacted text; PHI in a tool arg means
  // either (a) the agent fabricated a value that happens to look like PHI
  // or (b) something upstream leaked raw PHI into the agent's context. Both
  // are findings worth raising.
  for (const s of strings) {
    if (s.length === 0) continue;
    const phi = scanForPhi(s);
    if (phi.length > 0) {
      violations.push({
        kind: "phi_in_args",
        message: `PHI/PII/secret detected in tool argument (${phi
          .map((h) => h.detector)
          .join(",")})`,
      });
      break; // one is enough; don't repeat per-detector
    }
  }

  // Per-tool format invariants. The `message` here intentionally carries NO
  // dynamic value — it's the ledger payload, and threat_model §Repudiation
  // requires that raw arg values never enter the ledger. The `kind` enum is
  // the categorical signal a verifier acts on; the offending value is already
  // captured (and gated) inside the incident-finding fingerprint, not here.
  if (
    tool === "get_finding" &&
    typeof (args as { finding_id?: unknown })?.finding_id === "string"
  ) {
    const id = (args as { finding_id: string }).finding_id;
    if (!FINDING_ID_RE.test(id)) {
      violations.push({
        kind: "bad_finding_id_format",
        message: "finding_id does not match the allowed format",
      });
    }
  }

  return {
    ok: violations.length === 0,
    violations,
    canaryTripped: canaryHit,
  };
}

function collectStrings(value: unknown, out: string[] = []): string[] {
  if (typeof value === "string") {
    out.push(value);
  } else if (Array.isArray(value)) {
    for (const v of value) collectStrings(v, out);
  } else if (value && typeof value === "object") {
    for (const v of Object.values(value)) collectStrings(v, out);
  }
  return out;
}
