// Stage-2 NER (named-entity recognition) detector seam.
//
// The deterministic regex/dictionary detectors in redact.ts (Stage-1) are the
// only thing in the offline, credential-free eval gate — a pattern ships only
// if it fires on a labeled fixture WITHOUT tripping the benign-log precision
// controls (see docs/MILESTONES.md M11/M13). That discipline deliberately
// leaves a gap: *un-anchored* person names and free-form postal addresses
// ("Park reviewed the chart", "ship to 42 Larch Lane") cannot be matched by a
// precision-safe regex — they need a statistical model, which is incompatible
// with the offline gate (needs credentials / large model weights).
//
// This module is the seam that closes that gap in PRODUCTION without disturbing
// the gate: an optional, async, default-OFF NER provider that augments the
// Stage-1 hits. The default `NoopNerProvider` returns nothing, so:
//   * `scanForPhi` (Stage-1, sync) is unchanged and still drives the eval gate;
//   * nothing new is imported and no behavior changes unless an operator sets
//     `NER_PROVIDER` (mirrors the embedder / search / raw-evidence seams).
//
// A provider returns spans in the SAME shape as Stage-1 hits (`PhiHit`) so the
// merge in redact.ts (`scanForPhiWithNer`) and the existing redactInline /
// findings pipeline treat them identically. PHI guarantees are unchanged: NER
// runs on the same already-trust-boundaried log payload Stage-1 sees, its spans
// are redacted by the same masker, and the raw text never leaves the detector
// plane.

import type { PhiHit } from "./redact";

/** A Stage-2 NER provider. `detect` is async (cloud NER is a network call) and
 *  returns spans in the Stage-1 `PhiHit` shape so the merge + redaction path is
 *  identical to the deterministic detectors. */
export interface NerProvider {
  readonly name: string;
  detect(text: string): Promise<PhiHit[]>;
}

/** Default provider: detects nothing. Keeps Stage-2 inert unless an operator
 *  explicitly configures a real provider — so the eval gate stays byte-for-byte
 *  identical and no optional SDK is loaded. */
export class NoopNerProvider implements NerProvider {
  readonly name = "noop";
  async detect(_text: string): Promise<PhiHit[]> {
    void _text;
    return [];
  }
}

/** Maps a coarse NER entity category to the `PhiHit` classification + detector
 *  name used downstream. Centralized so every cloud provider classifies the
 *  same entity the same way. Person names + postal addresses are the
 *  un-anchored PII the Stage-1 detectors cannot safely match; secrets/SSN/etc.
 *  are already covered by Stage-1 regex (the merge dedups any overlap). */
export type NerEntityCategory = "person" | "address";

export function nerHit(
  category: NerEntityCategory,
  start: number,
  end: number,
  match: string,
): PhiHit {
  return {
    classification: "pii",
    detector: category === "person" ? "ner_person" : "ner_address",
    start,
    end,
    match,
  };
}
