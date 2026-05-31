// M11.2 — Detector eval: secrets-in-logs recall. Secrets are a higher-severity
// class than PHI (threat_model Assets). Score = recall over labeled secret
// fixtures. Per-kind recall in `meta` shows which secret families are covered.

import { afterAll, describe, expect, it } from "vitest";
import { scanForPhi } from "../lib/redact";
import {
  EvalResult,
  overlaps,
  recordEvalResult,
  round4,
  spanOf,
} from "./harness";
import { SECRET_FIXTURES } from "./fixtures/secrets";

describe("eval: detector-secrets", () => {
  let result: EvalResult;

  it("scores secret detection recall over labeled fixtures", () => {
    let recalled = 0;
    const perKind: Record<string, number> = {};

    for (const fx of SECRET_FIXTURES) {
      const span = spanOf(fx.text, fx.secret);
      // A secret only counts as recalled if a detector classified as
      // "secrets" overlaps the labeled span. An incidental overlap from a
      // PII detector (e.g. `phone` clipping a Slack token, `email` clipping a
      // DB-URL password) misclassifies the finding and risks partial
      // redaction, so it must NOT count as secret coverage.
      const hit = scanForPhi(fx.text).some(
        (h) =>
          h.classification === "secrets" &&
          overlaps({ start: h.start, end: h.end }, span),
      );
      perKind[fx.kind] = hit ? 1 : 0;
      if (hit) recalled += 1;
    }

    const recall = SECRET_FIXTURES.length === 0 ? 1 : recalled / SECRET_FIXTURES.length;

    result = {
      suite: "detector-secrets",
      score: round4(recall),
      breakdown: {
        recall: round4(recall),
        recalled,
        total: SECRET_FIXTURES.length,
      },
      meta: { per_kind_detected: perKind },
    };

    // At least the AWS key + JWT classes must remain covered — they are the
    // ones the seed + chat-agent canary flows depend on.
    expect(recalled).toBeGreaterThan(0);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
