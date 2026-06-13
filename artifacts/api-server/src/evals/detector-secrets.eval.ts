// M11.2 / M13 — Detector eval: secrets-in-logs precision & recall. Secrets are
// a higher-severity class than PHI (threat_model Assets). The gated score is the
// F1 over labeled secret spans, so a precision regression (a detector that
// starts firing on benign hex blobs / slugs) fails the gate just as a recall
// regression does — recall alone could be gamed by flagging everything.
//
// The corpus (fixtures/secrets.ts) has positive cases across realistic log
// SHAPES (clean / json / kv / stacktrace / connstring) plus a BENIGN cohort of
// credential-shaped near-misses that must yield zero secrets-classified hits.
// `meta.per_kind_detected` / `meta.per_shape_recall` show where coverage holds.
// Spans flagged `knownGap` (e.g. HTTP Basic-auth blobs) are accepted, documented
// misses: excluded from the gated F1 and reported as `known_gap_missed` so they
// don't read as silent regressions.

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
import { BENIGN_SECRET_FIXTURES, SECRET_FIXTURES } from "./fixtures/secrets";

describe("eval: detector-secrets", () => {
  let result: EvalResult;

  it("scores secret detection precision/recall over labeled fixtures", () => {
    let tp = 0;
    let fp = 0;
    let fn = 0;

    let knownGapTotal = 0;
    let knownGapMissed = 0;

    const perKind: Record<string, number> = {};
    const shapeTotal: Record<string, number> = {};
    const shapeHit: Record<string, number> = {};

    for (const fx of SECRET_FIXTURES) {
      const span = spanOf(fx.text, fx.secret);
      const shape = fx.shape ?? "clean";
      const hits = scanForPhi(fx.text);

      // A secret counts as recalled only if a detector CLASSIFIED AS "secrets"
      // overlaps the labeled span. An incidental overlap from a PII detector
      // (phone clipping a Slack token, email clipping a DB-URL password)
      // misclassifies the finding and risks partial redaction, so it must not
      // count as secret coverage.
      const recalled = hits.some(
        (h) =>
          h.classification === "secrets" &&
          overlaps({ start: h.start, end: h.end }, span),
      );

      if (fx.knownGap) {
        // Accepted, documented miss: kept out of the gated tp/fn accounting.
        knownGapTotal += 1;
        if (!recalled) knownGapMissed += 1;
      } else {
        shapeTotal[shape] = (shapeTotal[shape] ?? 0) + 1;
        // per-kind = 1 only if EVERY fixture of that kind was recalled.
        perKind[fx.kind] = (perKind[fx.kind] ?? 1) === 1 && recalled ? 1 : 0;
        if (recalled) {
          tp += 1;
          shapeHit[shape] = (shapeHit[shape] ?? 0) + 1;
        } else {
          fn += 1;
        }
      }

      // Precision: any secrets-classified hit that overlaps no labeled secret
      // span on this line is a false positive (a detector firing on something
      // that isn't the labeled credential).
      for (const h of hits) {
        if (
          h.classification === "secrets" &&
          !overlaps({ start: h.start, end: h.end }, span)
        ) {
          fp += 1;
        }
      }
    }

    // Benign near-misses must yield no secrets-classified hits; every such hit
    // is a false positive.
    for (const fx of BENIGN_SECRET_FIXTURES) {
      for (const h of scanForPhi(fx.text)) {
        if (h.classification === "secrets") fp += 1;
      }
    }

    const { precision, recall, f1 } = prf(tp, fp, fn);

    const perShapeRecall: Record<string, number> = {};
    for (const shape of Object.keys(shapeTotal)) {
      perShapeRecall[shape] = round4((shapeHit[shape] ?? 0) / shapeTotal[shape]!);
    }

    result = {
      suite: "detector-secrets",
      score: round4(f1),
      breakdown: {
        precision: round4(precision),
        recall: round4(recall),
        f1: round4(f1),
        true_positives: tp,
        false_positives: fp,
        false_negatives: fn,
        known_gap_spans: knownGapTotal,
        known_gap_missed: knownGapMissed,
        benign_controls: BENIGN_SECRET_FIXTURES.length,
      },
      meta: {
        per_kind_detected: perKind,
        per_shape_recall: perShapeRecall,
      },
    };

    // Guard rails (not the gated metric):
    // every non-knownGap secret must be recalled — a new, undocumented miss
    // fails loudly rather than silently lowering the headline number.
    expect(fn).toBe(0);
    // precision must stay high — detectors must not fire on benign ids/slugs.
    expect(precision).toBeGreaterThanOrEqual(0.8);
    // sanity: the suite must actually be exercising detectors.
    expect(tp).toBeGreaterThan(0);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
