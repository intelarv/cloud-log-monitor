// Fixtures for the chat citation-correctness eval.
//
// The chat agent must cite findings inline as `[F:<id>]` and "cite only
// findings that exist" (prompts.ts). A hallucinated citation — an id that
// resolves to no finding — is a correctness failure: it gives an analyst a
// dangling reference in a compliance context.
//
// The deterministic eval exercises the real `extractCitations` parser against
// authored agent-answer strings and checks that (a) the parser pulls exactly
// the referenced ids and (b) ids outside the known finding set are correctly
// flagged as hallucinated. The live (EVAL_LLM) eval runs `runChatTurn` against
// the seeded DB and asserts every emitted citation resolves to a real row.

/** The seeded finding id universe (lib/db/src/seed.ts): F-001..F-010 + the
 *  honeypot canary. The deterministic eval treats anything else as a
 *  hallucinated citation. */
export const SEEDED_FINDING_IDS: string[] = [
  "F-001",
  "F-002",
  "F-003",
  "F-004",
  "F-005",
  "F-006",
  "F-007",
  "F-008",
  "F-009",
  "F-010",
  "F-CANARY",
];

export interface CitationFixture {
  id: string;
  /** Simulated agent final answer. */
  text: string;
  /** Distinct ids the parser should extract, in any order. */
  expectedCited: string[];
  /** Subset of expectedCited that are NOT in SEEDED_FINDING_IDS. */
  expectedHallucinated: string[];
}

export const CITATION_FIXTURES: CitationFixture[] = [
  {
    id: "clean-single",
    text: "The critical AWS key leak is [F:F-003]. Rotate that key.",
    expectedCited: ["F-003"],
    expectedHallucinated: [],
  },
  {
    id: "clean-multi",
    text:
      "Two PHI findings need attention: the patient record [F:F-001] and " +
      "the diagnosis line [F:F-010]. The canary [F:F-CANARY] is a honeypot.",
    expectedCited: ["F-001", "F-010", "F-CANARY"],
    expectedHallucinated: [],
  },
  {
    id: "clean-dedupe",
    text: "See [F:F-002] for the SSN; the same finding [F:F-002] repeats.",
    expectedCited: ["F-002"],
    expectedHallucinated: [],
  },
  {
    id: "no-citations",
    text: "I can't find any matching findings for that query.",
    expectedCited: [],
    expectedHallucinated: [],
  },
  {
    id: "hallucinated-one",
    text: "The breach is documented in [F:F-999], escalate immediately.",
    expectedCited: ["F-999"],
    expectedHallucinated: ["F-999"],
  },
  {
    id: "hallucinated-mixed",
    text: "Compare [F:F-005] against the unrelated record [F:F-321].",
    expectedCited: ["F-005", "F-321"],
    expectedHallucinated: ["F-321"],
  },
];
