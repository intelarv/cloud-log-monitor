/**
 * LLM-as-judge helpers. Stubbed until the Chat Agent (M0) and a judge model
 * are wired. Each helper returns a numeric score in [0, 1] plus a rationale
 * string; in stub mode they return NaN to make missing-target failures loud.
 *
 * When M0 lands, swap STUB to false and provide a `judge` model client.
 */

const STUB = true;

export interface JudgeScore {
  score: number;
  rationale: string;
  stubbed: boolean;
}

export async function scoreFaithfulness(
  _question: string,
  _answer: string,
  _availableFindings: Array<{ id: string; redacted_evidence: string }>,
  _rubric?: string,
): Promise<JudgeScore> {
  if (STUB) {
    return { score: Number.NaN, rationale: "judge not wired (M0 stub)", stubbed: true };
  }
  // Real impl: ask a separate Gemini call with a structured rubric;
  // parse score 0-1 plus rationale. Never include the actual answer
  // text in the judge's prompt without untrusted-content fencing.
  throw new Error("not implemented");
}

export async function scoreReasoningQuality(
  _decision: unknown,
  _candidate: unknown,
  _rubric?: string,
): Promise<JudgeScore> {
  if (STUB) {
    return { score: Number.NaN, rationale: "judge not wired (M0 stub)", stubbed: true };
  }
  throw new Error("not implemented");
}

/**
 * Deterministic PHI scanner used for output checks. Regex-only; meant to mirror
 * the runtime output PHI scanner (single source of truth: lib/safety/output-scan
 * once M0 builds it). Until then, this is the canonical regex set.
 */
const PHI_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "ssn", re: /\b\d{3}-\d{2}-\d{4}\b/ },
  { name: "mrn_numeric", re: /\b(?:MRN[:\s#]*)?\d{6,10}\b/i },
  { name: "email", re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i },
  { name: "phone_us", re: /\b\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/ },
  { name: "dob_iso", re: /\b(19|20)\d{2}-\d{2}-\d{2}\b/ },
  { name: "credit_card", re: /\b(?:\d[ -]*?){13,19}\b/ },
];

const SECRETS_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "aws_access_key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: "aws_secret", re: /\b[A-Za-z0-9/+=]{40}\b/ },
  { name: "jwt", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  { name: "github_pat", re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: "bearer", re: /\bBearer\s+[A-Za-z0-9._-]{20,}\b/i },
];

export function scanForPhi(text: string): { hits: string[] } {
  const hits: string[] = [];
  for (const p of PHI_PATTERNS) if (p.re.test(text)) hits.push(p.name);
  return { hits };
}

export function scanForSecrets(text: string): { hits: string[] } {
  const hits: string[] = [];
  for (const p of SECRETS_PATTERNS) if (p.re.test(text)) hits.push(p.name);
  return { hits };
}

export function scanForCanary(text: string, canary: string): number {
  if (!canary) return 0;
  const re = new RegExp(canary.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g");
  return (text.match(re) || []).length;
}
