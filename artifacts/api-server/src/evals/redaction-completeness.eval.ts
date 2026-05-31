// M11.2 — Redaction eval: completeness of redactInline.
//
// Two metrics:
//   - redactor_correctness (the gated score): of the PHI spans the detector
//     DID catch, what fraction are fully removed from the redacted snippet?
//     This isolates the redactor's own correctness from detector coverage and
//     must stay at 1.0 — a detected span that survives redaction is a leak.
//   - overall_no_leak (breakdown): fraction of ALL labeled PHI spans absent
//     from the snippet. Bounded by detector recall, so lower by design.

import { afterAll, describe, expect, it } from "vitest";
import { redactInline, scanForPhi } from "../lib/redact";
import {
  EvalResult,
  overlaps,
  recordEvalResult,
  round4,
  spanOf,
} from "./harness";
import { PHI_FIXTURES } from "./fixtures/phi";

describe("eval: redaction-completeness", () => {
  let result: EvalResult;

  it("scores redaction completeness over detected PHI spans", () => {
    let detectedSpans = 0;
    let detectedRemoved = 0;
    let totalSpans = 0;
    let totalAbsent = 0;

    for (const fx of PHI_FIXTURES) {
      const hits = scanForPhi(fx.text);
      const hitSpans = hits.map((h) => ({ start: h.start, end: h.end }));
      const { snippet } = redactInline(fx.text, hits);

      for (const { sub } of fx.phi) {
        totalSpans += 1;
        const span = spanOf(fx.text, sub);
        const absent = !snippet.includes(sub);
        if (absent) totalAbsent += 1;

        const wasDetected = hitSpans.some((h) => overlaps(h, span));
        if (wasDetected) {
          detectedSpans += 1;
          if (absent) detectedRemoved += 1;
        }
      }
    }

    const redactorCorrectness = detectedSpans === 0 ? 1 : detectedRemoved / detectedSpans;
    const overallNoLeak = totalSpans === 0 ? 1 : totalAbsent / totalSpans;

    result = {
      suite: "redaction-completeness",
      score: round4(redactorCorrectness),
      breakdown: {
        redactor_correctness: round4(redactorCorrectness),
        overall_no_leak: round4(overallNoLeak),
        detected_spans: detectedSpans,
        detected_removed: detectedRemoved,
        total_spans: totalSpans,
      },
    };

    // Hard invariant: every PHI span the detector caught MUST be removed.
    expect(redactorCorrectness).toBe(1);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
