import { describe, expect, it } from "vitest";
import { rrfFuse, type RetrievalHit, type RetrieverSource } from "./search";

function ranking(...ids: string[]): RetrievalHit[] {
  return ids.map((id, i) => ({ finding_id: id, rank: i + 1 }));
}

describe("rrfFuse", () => {
  it("returns the same list when only one retriever has hits", () => {
    const fused = rrfFuse(
      new Map<RetrieverSource, RetrievalHit[]>([
        ["bm25", ranking("A", "B", "C")],
        ["vector", []],
      ]),
    );
    expect(fused.map((f) => f.finding_id)).toEqual(["A", "B", "C"]);
    for (const f of fused) expect(f.sources).toEqual(["bm25"]);
  });

  it("uses the standard RRF formula score(d) = sum(1/(k+rank))", () => {
    // With k=60: A appears at rank 1 in both retrievers → 2/(60+1) = 0.032786…
    const fused = rrfFuse(
      new Map<RetrieverSource, RetrievalHit[]>([
        ["bm25", ranking("A", "B")],
        ["vector", ranking("A", "C")],
      ]),
    );
    const a = fused.find((f) => f.finding_id === "A")!;
    expect(a.score).toBeCloseTo(2 / 61, 9);
    // B: only bm25 rank 2 → 1/62
    const b = fused.find((f) => f.finding_id === "B")!;
    expect(b.score).toBeCloseTo(1 / 62, 9);
    // C: only vector rank 2 → 1/62
    const c = fused.find((f) => f.finding_id === "C")!;
    expect(c.score).toBeCloseTo(1 / 62, 9);
  });

  it("ranks documents appearing in both retrievers above either alone", () => {
    const fused = rrfFuse(
      new Map<RetrieverSource, RetrievalHit[]>([
        ["bm25", ranking("X", "Y", "Z")],
        ["vector", ranking("Y", "W", "V")],
      ]),
    );
    expect(fused[0]!.finding_id).toBe("Y");
    expect(fused[0]!.sources).toEqual(["bm25", "vector"]);
    // The lone-source winners (X@bm25 rank1, then ties at rank2/3) follow.
    expect(fused.map((f) => f.finding_id).slice(0, 3)).toContain("X");
  });

  it("breaks score ties deterministically (by finding_id)", () => {
    const fused = rrfFuse(
      new Map<RetrieverSource, RetrievalHit[]>([
        ["bm25", ranking("B", "A")],
        ["vector", ranking("A", "B")],
      ]),
    );
    // Both score 1/61 + 1/62; ties broken alphabetically.
    expect(fused[0]!.finding_id).toBe("A");
    expect(fused[1]!.finding_id).toBe("B");
  });

  it("respects a custom k", () => {
    const fused = rrfFuse(
      new Map<RetrieverSource, RetrievalHit[]>([
        ["bm25", ranking("A")],
      ]),
      0,
    );
    expect(fused[0]!.score).toBeCloseTo(1, 9);
  });

  it("returns an empty list when no retriever has hits", () => {
    expect(
      rrfFuse(
        new Map<RetrieverSource, RetrievalHit[]>([
          ["bm25", []],
          ["vector", []],
        ]),
      ),
    ).toEqual([]);
  });
});
