import { describe, expect, it } from "vitest";
import {
  FeatureHashEmbedder,
  PhiGuardEmbedder,
  toPgVectorLiteral,
} from "./embeddings";

function cosine(a: readonly number[], b: readonly number[]): number {
  let dot = 0;
  for (let i = 0; i < a.length; i++) dot += a[i]! * b[i]!;
  return dot;
}

function l2(v: readonly number[]): number {
  let s = 0;
  for (const x of v) s += x * x;
  return Math.sqrt(s);
}

describe("FeatureHashEmbedder", () => {
  const e = new FeatureHashEmbedder();

  it("declares a positive dim", () => {
    expect(e.dim).toBeGreaterThan(0);
  });

  it("returns vectors of the declared dim", async () => {
    const v = await e.embed("hello world");
    expect(v).toHaveLength(e.dim);
  });

  it("is deterministic across calls and across instance boundaries", async () => {
    const e2 = new FeatureHashEmbedder();
    const a = await e.embed("AWS_ACCESS_KEY_ID rotated");
    const b = await e.embed("AWS_ACCESS_KEY_ID rotated");
    const c = await e2.embed("AWS_ACCESS_KEY_ID rotated");
    expect(a).toEqual(b);
    expect(a).toEqual(c);
  });

  it("normalizes to unit length (except for empty input)", async () => {
    const v = await e.embed("patient record ssn redacted");
    expect(l2(v)).toBeCloseTo(1, 6);
  });

  it("returns a zero vector for empty input (no NaN from divide-by-zero)", async () => {
    const v = await e.embed("");
    expect(v).toHaveLength(e.dim);
    expect(v.every((x) => x === 0)).toBe(true);
  });

  it("self-similarity is 1, similar text scores higher than unrelated text", async () => {
    const query = await e.embed("aws access key leaked in auth service");
    const same = await e.embed("aws access key leaked in auth service");
    const related = await e.embed("AWS_ACCESS_KEY_ID exposed by auth-svc");
    const unrelated = await e.embed(
      "patient diagnosis recorded in encounter notes",
    );

    expect(cosine(query, same)).toBeCloseTo(1, 6);
    expect(cosine(query, related)).toBeGreaterThan(cosine(query, unrelated));
  });

  it("is case-insensitive at the token level", async () => {
    const a = await e.embed("Billing Service Error");
    const b = await e.embed("billing service error");
    expect(cosine(a, b)).toBeCloseTo(1, 6);
  });
});

describe("PhiGuardEmbedder", () => {
  const inner = new FeatureHashEmbedder();
  const guard = new PhiGuardEmbedder(inner);

  it("delegates to inner for benign text", async () => {
    const a = await guard.embed("redacted finding evidence");
    const b = await inner.embed("redacted finding evidence");
    expect(a).toEqual(b);
  });

  it("inherits dim and tags version", () => {
    expect(guard.dim).toBe(inner.dim);
    expect(guard.version).toContain(inner.version);
    expect(guard.version).toContain("phi-guard");
  });

  it("refuses to embed text containing PHI (SSN)", async () => {
    await expect(guard.embed("patient ssn 123-45-6789")).rejects.toThrow(
      /refusing to embed/i,
    );
  });

  it("refuses to embed text containing secrets (AWS AKID)", async () => {
    await expect(
      guard.embed("creds AKIAIOSFODNN7EXAMPLE leaked"),
    ).rejects.toThrow(/refusing to embed/i);
  });

  it("refuses to embed text containing PII (email)", async () => {
    await expect(guard.embed("contact alice@example.com")).rejects.toThrow(
      /refusing to embed/i,
    );
  });
});

describe("toPgVectorLiteral", () => {
  it("formats a vector as a bracketed CSV", () => {
    expect(toPgVectorLiteral([0, 1, -0.5])).toBe("[0.000000,1.000000,-0.500000]");
  });

  it("coerces non-finite values to 0 rather than emitting NaN/Infinity", () => {
    expect(toPgVectorLiteral([Number.NaN, Number.POSITIVE_INFINITY, 1])).toBe(
      "[0,0,1.000000]",
    );
  });
});
