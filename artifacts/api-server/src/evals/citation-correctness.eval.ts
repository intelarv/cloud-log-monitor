// M11.3 — Agent eval: chat citation correctness.
//
// Deterministic suite (always runs): exercises the real `extractCitations`
// parser against authored agent answers and checks (a) it pulls exactly the
// referenced ids and (b) ids outside the seeded finding set are correctly
// flagged as hallucinated. Gated score = per-fixture pass rate.
//
// Live suite (EVAL_LLM=1 only): runs `runChatTurn` against the seeded DB and
// asserts every emitted citation resolves to a real finding id. Skipped by
// default so the baseline stays deterministic and credential-free.

import { afterAll, describe, expect, it } from "vitest";
import { extractCitations, runChatTurn } from "../lib/chat-agent";
import { findingsTable, findingSafeColumns } from "@workspace/db";
import { eq } from "drizzle-orm";
import { withTenant } from "../lib/db-context";
import {
  EvalResult,
  EVAL_LLM,
  recordEvalResult,
  round4,
} from "./harness";
import { CITATION_FIXTURES, SEEDED_FINDING_IDS } from "./fixtures/citations";

function sameSet(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  const sb = new Set(b);
  return a.every((x) => sb.has(x));
}

describe("eval: citation-correctness (deterministic parser)", () => {
  let result: EvalResult;

  it("scores citation extraction + hallucination flagging", () => {
    const valid = new Set(SEEDED_FINDING_IDS);
    let passed = 0;

    for (const fx of CITATION_FIXTURES) {
      const cited = extractCitations(fx.text);
      const extractionOk = sameSet(cited, fx.expectedCited);
      const hallucinated = cited.filter((id) => !valid.has(id));
      const hallucinationOk = sameSet(hallucinated, fx.expectedHallucinated);
      if (extractionOk && hallucinationOk) passed += 1;
    }

    const rate = CITATION_FIXTURES.length === 0 ? 1 : passed / CITATION_FIXTURES.length;
    result = {
      suite: "citation-correctness",
      score: round4(rate),
      breakdown: {
        pass_rate: round4(rate),
        passed,
        total: CITATION_FIXTURES.length,
      },
    };

    // The parser must be exact — citation handling is a correctness primitive.
    expect(rate).toBe(1);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});

// --- Live suite: real LLM + DB. Off unless EVAL_LLM=1. ----------------------
describe.skipIf(!EVAL_LLM)("eval: citation-live (LLM + DB)", () => {
  const TENANT = "default";
  const QUESTIONS = [
    "What are the most critical findings?",
    "Summarize any findings about secrets in logs.",
    "Are there PHI findings I should know about?",
  ];
  let result: EvalResult;

  it("asserts every chat citation resolves to a real finding", async () => {
    const rows = await withTenant(TENANT, async (tx) =>
      tx.select(findingSafeColumns).from(findingsTable).where(eq(findingsTable.tenantId, TENANT)),
    );
    const realIds = new Set(rows.map((r) => r.id));
    expect(realIds.size).toBeGreaterThan(0);

    let turnsCited = 0;
    let totalCitations = 0;
    let resolvedCitations = 0;

    for (const q of QUESTIONS) {
      const turn = await runChatTurn({ tenantId: TENANT, userId: "eval", userQuestion: q });
      let allResolve = turn.citations.length > 0; // emitting nothing is NOT a pass
      for (const c of turn.citations) {
        totalCitations += 1;
        if (realIds.has(c)) resolvedCitations += 1;
        else allResolve = false;
      }
      // A "good" turn cites at least one finding AND every citation resolves —
      // so a model that dodges by emitting zero citations cannot score perfect.
      if (allResolve) turnsCited += 1;
    }

    const goodTurnRate = turnsCited / QUESTIONS.length;
    const citationResolveRate = totalCitations === 0 ? 0 : resolvedCitations / totalCitations;

    result = {
      suite: "citation-live",
      score: round4(goodTurnRate),
      breakdown: {
        good_turn_rate: round4(goodTurnRate),
        citation_resolve_rate: round4(citationResolveRate),
        total_citations: totalCitations,
        questions: QUESTIONS.length,
      },
    };

    // Every emitted citation must resolve AND each question must produce ≥1.
    expect(citationResolveRate).toBe(1);
    expect(goodTurnRate).toBe(1);
  });

  afterAll(() => {
    if (result) recordEvalResult(result);
  });
});
