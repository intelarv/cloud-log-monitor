// M11.2 — Detector eval: PHI/PII precision & recall across HIPAA Safe Harbor
// identifier classes. Measures the deterministic detector (scanForPhi) against
// labeled fixtures; does NOT change it. The recorded F1 is the gated score.
//
// The fixture corpus has two cohorts (see fixtures/phi.ts): short CLEAN lines
// and realistic PRODUCTION-SHAPED lines (JSON, key=value, stack traces,
// multi-identifier prose). The production cohort exists to surface accuracy
// gaps the clean set hides; `meta.per_class_recall` and `meta.per_shape` report
// where recall holds up and where it does not. Spans flagged `knownGap` in the
// fixtures are accepted, documented misses (e.g. ISO dates) and are reported
// separately so they don't read as silent regressions.

import { afterAll, describe, expect, it } from "vitest";
import { scanForPhi } from "../lib/redact";
import {
  EvalResult,
  overlaps,
  prf,
  recordEvalResult,
  round4,
  spanOf,
} from "./harness";
import { BENIGN_FIXTURES, PHI_FIXTURES } from "./fixtures/phi";

describe("eval: detector-phi", () => {
  let result: EvalResult;

  it("scores PHI detection precision/recall over labeled fixtures", () => {
    let tp = 0;
    let fp = 0;
    let fn = 0;

    // Per-class recall accounting.
    const classTotal: Record<string, number> = {};
    const classHit: Record<string, number> = {};

    // Per-shape recall accounting (clean vs json/kv/stacktrace/prose).
    const shapeTotal: Record<string, number> = {};
    const shapeHit: Record<string, number> = {};

    // Accepted, documented misses (knownGap) reported separately so they don't
    // masquerade as a regression in the headline number.
    let knownGapTotal = 0;
    let knownGapStillMissed = 0;

    for (const fx of PHI_FIXTURES) {
      const labeled = fx.phi.map((p) => ({ ...p, span: spanOf(fx.text, p.sub) }));
      const hits = scanForPhi(fx.text).map((h) => ({ start: h.start, end: h.end }));

      // Recall: each labeled span counts once; recalled iff a hit overlaps it.
      for (const l of labeled) {
        classTotal[l.identifier] = (classTotal[l.identifier] ?? 0) + 1;
        shapeTotal[fx.shape] = (shapeTotal[fx.shape] ?? 0) + 1;
        const recalled = hits.some((h) => overlaps(h, l.span));
        if (l.knownGap) knownGapTotal += 1;
        if (recalled) {
          tp += 1;
          classHit[l.identifier] = (classHit[l.identifier] ?? 0) + 1;
          shapeHit[fx.shape] = (shapeHit[fx.shape] ?? 0) + 1;
        } else {
          fn += 1;
          if (l.knownGap) knownGapStillMissed += 1;
        }
      }

      // Precision: a hit that overlaps no labeled span is a false positive.
      for (const h of hits) {
        if (!labeled.some((l) => overlaps(h, l.span))) fp += 1;
      }
    }

    // Benign lines must yield no hits; every hit here is a false positive.
    for (const fx of BENIGN_FIXTURES) {
      fp += scanForPhi(fx.text).length;
    }

    const { precision, recall, f1 } = prf(tp, fp, fn);

    const perClassRecall: Record<string, number> = {};
    for (const cls of Object.keys(classTotal)) {
      perClassRecall[cls] = round4((classHit[cls] ?? 0) / classTotal[cls]!);
    }
    const perShapeRecall: Record<string, number> = {};
    for (const shape of Object.keys(shapeTotal)) {
      perShapeRecall[shape] = round4((shapeHit[shape] ?? 0) / shapeTotal[shape]!);
    }

    result = {
      suite: "detector-phi",
      score: round4(f1),
      breakdown: {
        precision: round4(precision),
        recall: round4(recall),
        f1: round4(f1),
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn,
        known_gap_spans: knownGapTotal,
        known_gap_missed: knownGapStillMissed,
      },
      meta: {
        per_class_recall: perClassRecall,
        per_shape_recall: perShapeRecall,
      },
    };

    // Guard rails (not the gated metric): precision must stay high — the
    // detector must not start firing on benign operational text.
    expect(precision).toBeGreaterThanOrEqual(0.8);
    expect(f1).toBeGreaterThan(0);
    // Every false negative must be an ACCEPTED, documented gap (knownGap). A new
    // miss with no recorded justification fails the suite loudly.
    expect(fn).toBe(knownGapStillMissed);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
