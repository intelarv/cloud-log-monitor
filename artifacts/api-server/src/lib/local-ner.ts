import type { PhiHit } from "./redact";
import { GIVEN_NAMES, SURNAMES, COLLISION_SURNAMES } from "./redact";
import { type NerProvider, nerHit } from "./ner";

// ---------------------------------------------------------------------------
// Local (offline) gazetteer Stage-2 NER provider.
//
// The cloud (cloud-ner.ts) and Presidio (presidio-ner.ts) providers close the
// open-class name/address gap with a statistical model, but both need an
// external service — a cloud BAA account or an operator-hosted analyzer. This
// provider is the credential-free, NO-service alternative for the *un-anchored
// dictionary-name* slice of that gap: a pure in-process gazetteer lookup over
// the SAME name dictionaries Stage-1 owns (redact.ts GIVEN_NAMES / SURNAMES /
// COLLISION_SURNAMES).
//
// Why this is a Stage-2 provider and NOT a new Stage-1 detector: Stage-1
// deliberately recalls a lone dictionary name ONLY when an anchor disambiguates
// it (honorific, person-context keyword, adjacent name pair) — an un-anchored
// single capitalized "Park"/"Maria"/"Lee" cannot be flagged in the always-on
// path without regressing benign-prose precision (see redact.ts scanNames). By
// living behind the default-OFF `NER_PROVIDER` seam, the un-anchored recall is
// an explicit operator opt-in (`NER_PROVIDER=local`) with a documented
// precision/recall tradeoff, so the offline eval gate stays byte-identical and
// no always-on benign FPs are introduced.
//
// Default-inert posture (mirrors the other NER backends): nothing here runs
// unless `NER_PROVIDER=local`. There is no SDK and no network — it is a
// synchronous Set lookup wrapped in the async `NerProvider.detect` contract —
// so it can never OOM the dev sandbox the way an in-process statistical model
// would, and the credential-free gate never exercises it.
//
// PHI posture is identical to the other providers: it reads the same already-
// trust-boundaried log payload the Stage-1 detectors see, returns spans in the
// `PhiHit` shape, and those spans are masked by the same redactInline path; the
// raw text never leaves the detector plane.
// ---------------------------------------------------------------------------

export interface LocalNerOptions {
  /** Minimum token length to consider. Single/two-letter dictionary collisions
   *  ("li", "le") are too ambiguous to recall un-anchored even on opt-in, so the
   *  default floor of 3 drops them. */
  minTokenLen?: number;
  /** When true, only Capitalized tokens (`^[A-Z][a-z]+$`) are recalled — the
   *  default. Lowercase prose tokens that happen to collide with a name
   *  ("sun", "park") stay silent. Set false to also recall lowercased names
   *  (higher recall, much lower precision — for log corpora that are entirely
   *  lowercased). */
  capitalizedOnly?: boolean;
}

const DEFAULT_MIN_TOKEN_LEN = 3;

/** A token must look like a name candidate: Capitalized single word. */
const CAPITALIZED_RE = /^[A-Z][a-z]+$/;

export class LocalGazetteerNerProvider implements NerProvider {
  readonly name = "local";
  private readonly minTokenLen: number;
  private readonly capitalizedOnly: boolean;

  constructor(opts: LocalNerOptions = {}) {
    this.minTokenLen =
      opts.minTokenLen == null ? DEFAULT_MIN_TOKEN_LEN : opts.minTokenLen;
    this.capitalizedOnly = opts.capitalizedOnly !== false;
  }

  private isGazetteerName(lc: string): boolean {
    return GIVEN_NAMES.has(lc) || SURNAMES.has(lc) || COLLISION_SURNAMES.has(lc);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async detect(text: string): Promise<PhiHit[]> {
    if (text.length === 0) return [];
    const hits: PhiHit[] = [];
    // Same alphabetic tokenizer Stage-1 uses, so offsets are consistent with the
    // deterministic detectors and the merge in scanForPhiWithNer dedups overlap.
    const tokenRe = /[A-Za-z][A-Za-z'-]*/g;
    let m: RegExpExecArray | null;
    while ((m = tokenRe.exec(text)) !== null) {
      const tok = m[0];
      if (tok.length < this.minTokenLen) continue;
      if (this.capitalizedOnly && !CAPITALIZED_RE.test(tok)) continue;
      if (!this.isGazetteerName(tok.toLowerCase())) continue;
      hits.push(nerHit("person", m.index, m.index + tok.length, tok));
    }
    return hits;
  }
}
