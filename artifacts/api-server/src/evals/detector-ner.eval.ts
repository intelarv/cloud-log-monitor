// M13.3 — NER (Stage-2) recall/precision MEASUREMENT.
//
// The deterministic Stage-1 detectors (scanForPhi) deliberately do NOT match
// un-anchored person names: a single surname with no title/anchor, or a name
// token that is also a common English word ("Hope", "Grace", "Park"). A regex
// that flagged those would fire on every sentence-initial capitalized word and
// destroy precision — so the precision-safe Stage-1 layer leaves a recall gap by
// design (docs/ARCHITECTURE.md §11). The optional, default-OFF NER seam
// (ner.ts / ner-config.ts, env `NER_PROVIDER`) exists to close that gap in
// PRODUCTION without disturbing the offline gate.
//
// This suite QUANTIFIES that trade-off. It does not change any detector. It
// measures three numbers against labeled fixtures:
//   1. stage1_recall  — how many un-anchored names Stage-1 alone recovers
//                        (expected ~0; this is the documented gap).
//   2. ner_recall     — recall once optional NER spans are merged in
//                        (expected 1.0; the seam recovers them).
//   3. benign_fp      — false positives the merged pipeline adds on benign
//                        operational text (expected 0; precision holds).
// The recorded `score` is ner_recall (recall AFTER the seam); `recall_gain`
// (ner_recall − stage1_recall) is the headline of the measurement.
//
// OPT-IN by design (EVAL_NER=1). When the flag is unset the suite is skipped and
// writes NO result file, so `pnpm run eval` / `eval:gate` stay byte-identical to
// the credential-free baseline (mirrors the EVAL_LLM gating of the live suites).
// The stand-in provider is a deterministic, credential-free fake that matches a
// fixed name lexicon at a case-sensitive word boundary — no cloud SDK, no
// network — so the measurement is reproducible offline; a real cloud provider
// (aws-comprehend / gcp-dlp / azure-language) plugs into the same merge path.

import { afterAll, describe, expect, it } from "vitest";
import { nerHit, type NerProvider } from "../lib/ner";
import { scanForPhi, scanForPhiWithNer, type PhiHit } from "../lib/redact";
import {
  EvalResult,
  overlaps,
  recordEvalResult,
  round4,
  spanOf,
} from "./harness";
import { BENIGN_FIXTURES, NER_PHI_FIXTURES } from "./fixtures/phi";

/** Opt-in flag: the NER measurement is excluded from the default offline gate
 *  exactly like the EVAL_LLM live suites, so the credential-free baseline never
 *  sees it. */
const EVAL_NER = process.env["EVAL_NER"] === "1";

/** Deterministic, credential-free stand-in for a cloud NER provider. Matches a
 *  fixed person-name lexicon at a case-sensitive word boundary (so "Park" the
 *  surname matches but "park" / "parked" do not) and emits spans in the exact
 *  Stage-1 `PhiHit` shape, so the merge path is identical to a real provider. */
class FixtureNerProvider implements NerProvider {
  readonly name = "fixture-ner";
  private readonly patterns: { name: string; re: RegExp }[];
  constructor(names: string[]) {
    this.patterns = [...new Set(names)].map((name) => ({
      name,
      re: new RegExp(`(?<![A-Za-z])${name}(?![A-Za-z])`, "g"),
    }));
  }
  async detect(text: string): Promise<PhiHit[]> {
    const hits: PhiHit[] = [];
    for (const { name, re } of this.patterns) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(text)) !== null) {
        hits.push(nerHit("person", m.index, m.index + name.length, name));
        if (m.index === re.lastIndex) re.lastIndex++;
      }
    }
    return hits;
  }
}

describe.skipIf(!EVAL_NER)("eval: detector-ner (opt-in, EVAL_NER=1)", () => {
  let result: EvalResult;

  it("quantifies the Stage-1 un-anchored-name recall gap and the NER recovery", async () => {
    const provider = new FixtureNerProvider(NER_PHI_FIXTURES.map((f) => f.name));

    const total = NER_PHI_FIXTURES.length;
    let stage1Hit = 0;
    let nerHitCount = 0;

    for (const fx of NER_PHI_FIXTURES) {
      const span = spanOf(fx.text, fx.name);

      // Stage-1 alone — the documented gap (expected to miss).
      const s1 = scanForPhi(fx.text).map((h) => ({ start: h.start, end: h.end }));
      if (s1.some((h) => overlaps(h, span))) stage1Hit += 1;

      // Stage-1 ∪ optional NER — the seam recovers the name.
      const merged = (await scanForPhiWithNer(fx.text, provider)).map((h) => ({
        start: h.start,
        end: h.end,
      }));
      if (merged.some((h) => overlaps(h, span))) nerHitCount += 1;
    }

    // Precision-hold leg: the merged pipeline must add NO false positives on
    // benign operational text (no person names present at a word boundary).
    let benignFp = 0;
    for (const fx of BENIGN_FIXTURES) {
      const merged = await scanForPhiWithNer(fx.text, provider);
      benignFp += merged.length; // benign lines are labeled ZERO-PHI
    }

    const stage1Recall = total === 0 ? 1 : stage1Hit / total;
    const nerRecall = total === 0 ? 1 : nerHitCount / total;
    const recallGain = nerRecall - stage1Recall;

    result = {
      suite: "detector-ner",
      score: round4(nerRecall),
      breakdown: {
        stage1_recall: round4(stage1Recall),
        ner_recall: round4(nerRecall),
        recall_gain: round4(recallGain),
        benign_fp: benignFp,
        fixtures: total,
      },
      meta: {
        word_collision_fixtures: NER_PHI_FIXTURES.filter((f) => f.wordCollision)
          .length,
      },
    };

    // The gap is real: Stage-1 alone recovers essentially none of these.
    expect(stage1Recall).toBeLessThanOrEqual(0.1);
    // The seam closes it: every labeled name is recovered once NER is merged.
    expect(nerRecall).toBe(1);
    // Recall strictly improves...
    expect(recallGain).toBeGreaterThan(0);
    // ...without costing precision on benign operational text.
    expect(benignFp).toBe(0);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
