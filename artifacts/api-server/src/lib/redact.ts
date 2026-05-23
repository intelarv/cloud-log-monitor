// Output PHI/PII scanner. Runs over every assistant message before it leaves
// the server. Per ARCHITECTURE.md §23.1, PHI detected in agent output is
// itself a *finding about the agent*, not just a leak: caller logs an incident
// to the ledger and substitutes a safe refusal.
//
// The detectors here are the same shape M0 uses for log detectors — regex
// patterns tagged with a classification. Real production replaces these with
// a Stage-1+2 pipeline plus dictionary lookups.

export interface PhiHit {
  classification: "phi" | "secrets" | "pii" | "pii_s";
  detector: string;
  // Match offsets into the original string.
  start: number;
  end: number;
  // The raw matched text — do NOT log this; only used for replacement.
  match: string;
}

interface Detector {
  classification: PhiHit["classification"];
  name: string;
  regex: RegExp;
}

const DETECTORS: Detector[] = [
  // US SSN
  {
    classification: "phi",
    name: "ssn",
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  // Email
  {
    classification: "pii",
    name: "email",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  // Phone (loose North American + intl)
  {
    classification: "pii",
    name: "phone",
    regex: /\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  // 16-digit card-like number (Luhn check would reduce FPs; M0 is permissive
  // because false positives just mean the agent has to be more careful)
  {
    classification: "pii_s",
    name: "credit_card_like",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
  },
  // MRN-like: literal "MRN" followed by digits
  {
    classification: "phi",
    name: "mrn_like",
    regex: /\bMRN[:\s#-]*\d{4,}\b/gi,
  },
  // AWS access key id
  {
    classification: "secrets",
    name: "aws_akid",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // JWT (3 dot-separated base64url segments)
  {
    classification: "secrets",
    name: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
];

export function scanForPhi(text: string): PhiHit[] {
  const hits: PhiHit[] = [];
  for (const det of DETECTORS) {
    det.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = det.regex.exec(text)) !== null) {
      hits.push({
        classification: det.classification,
        detector: det.name,
        start: m.index,
        end: m.index + m[0].length,
        match: m[0],
      });
      // Safety against zero-width matches:
      if (m.index === det.regex.lastIndex) det.regex.lastIndex++;
    }
  }
  return hits;
}

// M3: inline redaction helper used by the ingest pipeline to produce the
// `redacted_evidence` snippet that lands in the searchable hot tier. The
// strategy is "mask" per ARCHITECTURE.md §6 (tokenize-via-KMS is post-M3).
//
// Overlap handling: hits are sorted by start ascending, then by end
// descending so the longer span wins on tie. Any later hit whose start
// falls inside an already-redacted span is skipped — the earlier span's
// `[REDACTED:<detector>]` placeholder already covers the bytes.
//
// Returns the redacted text plus the ordered list of detector names that
// were actually applied (skipped overlapping hits are NOT counted).
export function redactInline(
  text: string,
  hits: PhiHit[],
): { snippet: string; redactions: string[] } {
  if (hits.length === 0) return { snippet: text, redactions: [] };
  const sorted = [...hits].sort(
    (a, b) => a.start - b.start || b.end - a.end,
  );
  const out: string[] = [];
  const redactions: string[] = [];
  let cursor = 0;
  for (const h of sorted) {
    if (h.end <= h.start) continue; // zero/negative-width hit — nothing to mask
    if (h.start < cursor) continue; // overlap — earlier (longer) span covers it
    out.push(text.slice(cursor, h.start));
    out.push(`[REDACTED:${h.detector}]`);
    redactions.push(h.detector);
    cursor = h.end;
  }
  out.push(text.slice(cursor));
  return { snippet: out.join(""), redactions };
}

export const SAFE_REFUSAL =
  "I can't share that. The response I was about to send contained " +
  "values that look like PHI/secrets. The attempt has been logged as a " +
  "finding about my own output. Please rephrase or use the break-glass " +
  "raw-evidence view if you have authorization.";
