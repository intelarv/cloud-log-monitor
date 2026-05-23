// Boundary validator for analyst-provided free-text fields that land in
// immutable storage (DB rows AND ledger payloads): break-glass
// justification, approval notes, step-up reasons.
//
// Threat model §Information Disclosure: "PHI MUST NOT appear in ... LLM
// prompts ... application logs ... embeddings ... [implicit: ledger
// payloads, per §Repudiation's PHI-by-reference-only rule for chat-turn
// ledger entries]". The break-glass ledger payloads existed since M1.6 but
// trusted the analyst not to type PHI into a justification box. The
// architect review on M1.7 flagged this as a real risk: a careless or
// hostile analyst could leak PHI/secrets into the immutable chain.
//
// This validator runs the same `scanForPhi` detectors used on every LLM
// output, plus a canary-token check, against any free-text field before it
// touches the DB or the ledger. On hit, the caller refuses with HTTP 400
// and ledgers the refusal as `policy.text_field_rejected` — the *fact* of
// the refusal lands in the chain, the offending text does not.

import { CANARY_TOKEN } from "@workspace/db";
import { scanForPhi } from "./redact";

export type TextRejectionReason =
  | "phi_or_secret_in_text"
  | "canary_token_in_text";

export interface TextValidationOk {
  ok: true;
}

export interface TextValidationFail {
  ok: false;
  reason: TextRejectionReason;
  // Detector names that matched. The matched substrings themselves are
  // intentionally NOT returned so they cannot accidentally land in a log
  // line or response body. The set of detector names is safe metadata.
  detectors: string[];
}

export type TextValidationResult = TextValidationOk | TextValidationFail;

/**
 * Validate a free-text field that is about to be persisted to a tamper-
 * evident store. Returns `{ ok: false }` if the text contains anything
 * that scans as PHI/PII/secrets or contains the honeypot canary token.
 *
 * The caller is responsible for translating a fail into the right HTTP
 * status + ledger event for the surrounding endpoint.
 */
export function validateLedgerSafeText(text: string): TextValidationResult {
  if (text.includes(CANARY_TOKEN)) {
    return { ok: false, reason: "canary_token_in_text", detectors: ["canary"] };
  }
  const hits = scanForPhi(text);
  if (hits.length > 0) {
    const detectors = Array.from(new Set(hits.map((h) => h.detector)));
    return { ok: false, reason: "phi_or_secret_in_text", detectors };
  }
  return { ok: true };
}
