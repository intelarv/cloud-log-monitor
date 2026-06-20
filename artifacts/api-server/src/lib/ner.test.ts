import { describe, it, expect, afterEach } from "vitest";
import { NoopNerProvider, nerHit, type NerProvider } from "./ner";
import { scanForPhi, scanForPhiWithNer, mergePhiHits, type PhiHit } from "./redact";
import {
  loadNerProviderConfigFromEnv,
  createNerProvider,
  initNerProviderFromEnv,
  getNerProviderOrNull,
  setNerProvider,
  resetNerProviderForTests,
} from "./ner-config";
import { PresidioNerProvider, type FetchLike } from "./presidio-ner";
import { LocalGazetteerNerProvider } from "./local-ner";

// A deterministic fake NER provider for offline tests — no cloud SDK, no
// network. It "detects" whole-word person names from a small fixed lexicon so
// the merge/dedup behavior can be asserted precisely.
class FakeNerProvider implements NerProvider {
  readonly name = "fake";
  constructor(private readonly names: string[]) {}
  async detect(text: string): Promise<PhiHit[]> {
    const hits: PhiHit[] = [];
    for (const n of this.names) {
      let idx = text.indexOf(n);
      while (idx !== -1) {
        hits.push(nerHit("person", idx, idx + n.length, n));
        idx = text.indexOf(n, idx + n.length);
      }
    }
    return hits;
  }
}

afterEach(() => {
  resetNerProviderForTests();
});

describe("NoopNerProvider", () => {
  it("detects nothing", async () => {
    const p = new NoopNerProvider();
    expect(p.name).toBe("noop");
    expect(await p.detect("Park reviewed the chart for patient 12345")).toEqual(
      [],
    );
  });
});

describe("nerHit", () => {
  it("classifies person and address with stable detector names", () => {
    expect(nerHit("person", 0, 4, "Park")).toMatchObject({
      classification: "pii",
      detector: "ner_person",
      start: 0,
      end: 4,
      match: "Park",
    });
    expect(nerHit("address", 5, 20, "42 Larch Lane").detector).toBe(
      "ner_address",
    );
  });
});

describe("mergePhiHits", () => {
  it("returns base unchanged when there are no extra spans", () => {
    const base: PhiHit[] = [
      { classification: "phi", detector: "ssn", start: 0, end: 11, match: "x" },
    ];
    expect(mergePhiHits(base, [])).toBe(base);
  });

  it("drops NER spans fully covered by a Stage-1 span", () => {
    const base: PhiHit[] = [
      { classification: "phi", detector: "mrn", start: 0, end: 20, match: "x" },
    ];
    const extra = [nerHit("person", 5, 10, "inner")];
    expect(mergePhiHits(base, extra)).toEqual(base);
  });

  it("keeps partial / disjoint NER spans", () => {
    const base: PhiHit[] = [
      { classification: "phi", detector: "mrn", start: 0, end: 10, match: "x" },
    ];
    const disjoint = nerHit("person", 20, 24, "Park");
    const partial = nerHit("address", 8, 18, "overlapping");
    const merged = mergePhiHits(base, [disjoint, partial]);
    expect(merged).toContain(base[0]);
    expect(merged).toContainEqual(disjoint);
    expect(merged).toContainEqual(partial);
  });

  it("ignores zero/negative-length spans", () => {
    const base: PhiHit[] = [];
    expect(mergePhiHits(base, [nerHit("person", 5, 5, "")])).toEqual([]);
  });
});

describe("scanForPhiWithNer", () => {
  it("equals scanForPhi when no provider is supplied", async () => {
    const text = "user ssn 123-45-6789 logged in";
    expect(await scanForPhiWithNer(text)).toEqual(scanForPhi(text));
    expect(await scanForPhiWithNer(text, null)).toEqual(scanForPhi(text));
  });

  it("augments Stage-1 with NER spans the regex layer cannot match", async () => {
    // "Park reviewed the chart" — the un-anchored-name M13.3 gap. Stage-1 stays
    // silent; the NER provider supplies the span.
    const text = "Park reviewed the chart";
    const base = scanForPhi(text);
    const augmented = await scanForPhiWithNer(text, new FakeNerProvider(["Park"]));
    expect(augmented.length).toBe(base.length + 1);
    expect(augmented).toContainEqual(
      expect.objectContaining({ detector: "ner_person", match: "Park" }),
    );
  });
});

describe("ner-config env parsing", () => {
  it("defaults to none", () => {
    expect(loadNerProviderConfigFromEnv({}).provider).toBe("none");
  });

  it("parses an explicit provider case-insensitively", () => {
    expect(
      loadNerProviderConfigFromEnv({ NER_PROVIDER: "AWS-Comprehend" }).provider,
    ).toBe("aws-comprehend");
  });

  it("throws on an unknown provider rather than silently disabling", () => {
    expect(() =>
      loadNerProviderConfigFromEnv({ NER_PROVIDER: "bogus" }),
    ).toThrow(/not a known provider/);
  });

  it("builds a NoopNerProvider for none", () => {
    const p = createNerProvider({ provider: "none" }, {});
    expect(p.name).toBe("noop");
  });

  it("requires region for aws-comprehend", () => {
    expect(() =>
      createNerProvider({ provider: "aws-comprehend" }, {}),
    ).toThrow(/NER_AWS_REGION/);
  });

  it("requires project id for gcp-dlp", () => {
    expect(() => createNerProvider({ provider: "gcp-dlp" }, {})).toThrow(
      /NER_GCP_PROJECT_ID/,
    );
  });

  it("requires endpoint + key for azure-language", () => {
    expect(() =>
      createNerProvider(
        { provider: "azure-language" },
        { NER_AZURE_ENDPOINT: "https://x" },
      ),
    ).toThrow(/NER_AZURE_API_KEY/);
  });

  it("parses presidio case-insensitively", () => {
    expect(
      loadNerProviderConfigFromEnv({ NER_PROVIDER: "Presidio" }).provider,
    ).toBe("presidio");
  });

  it("requires endpoint for presidio", () => {
    expect(() => createNerProvider({ provider: "presidio" }, {})).toThrow(
      /NER_PRESIDIO_ENDPOINT/,
    );
  });

  it("builds a presidio provider when its endpoint is set", () => {
    const p = createNerProvider(
      { provider: "presidio" },
      { NER_PRESIDIO_ENDPOINT: "http://presidio:3000" },
    );
    expect(p.name).toBe("presidio");
  });

  it("rejects a non-numeric / out-of-range presidio score threshold", () => {
    for (const bad of ["abc", "-0.1", "1.5"]) {
      expect(() =>
        createNerProvider(
          { provider: "presidio" },
          {
            NER_PRESIDIO_ENDPOINT: "http://presidio:3000",
            NER_PRESIDIO_SCORE_THRESHOLD: bad,
          },
        ),
      ).toThrow(/NER_PRESIDIO_SCORE_THRESHOLD/);
    }
  });
});

describe("PresidioNerProvider.detect", () => {
  // Build an injectable fetch that returns a canned analyzer response and
  // records the request body, so the provider can be exercised with no network.
  function fakeFetch(
    results: unknown,
    opts: { ok?: boolean; status?: number; capture?: (body: unknown) => void } = {},
  ): FetchLike {
    return async (_url, init) => {
      if (opts.capture && init?.body) opts.capture(JSON.parse(init.body));
      return {
        ok: opts.ok ?? true,
        status: opts.status ?? 200,
        json: async () => results,
        text: async () => JSON.stringify(results),
      };
    };
  }

  it("maps PERSON→person and LOCATION→address with correct offsets", async () => {
    const text = "Park lives at 42 Larch Lane";
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000/",
      fetchImpl: fakeFetch([
        { entity_type: "PERSON", start: 0, end: 4, score: 0.99 },
        { entity_type: "LOCATION", start: 14, end: 27, score: 0.85 },
      ]),
    });
    const hits = await provider.detect(text);
    expect(hits).toContainEqual(
      expect.objectContaining({ detector: "ner_person", match: "Park" }),
    );
    expect(hits).toContainEqual(
      expect.objectContaining({
        detector: "ner_address",
        match: "42 Larch Lane",
      }),
    );
  });

  it("drops entity types outside person/address and sub-threshold scores", async () => {
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      scoreThreshold: 0.6,
      fetchImpl: fakeFetch([
        { entity_type: "PERSON", start: 0, end: 4, score: 0.3 }, // below threshold
        { entity_type: "EMAIL_ADDRESS", start: 5, end: 20, score: 0.99 }, // unmapped
      ]),
    });
    expect(await provider.detect("Park x@example.com")).toEqual([]);
  });

  it("requests only the person/address entity types and the configured threshold", async () => {
    let body: unknown;
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      scoreThreshold: 0.7,
      language: "es",
      fetchImpl: fakeFetch([], { capture: (b) => (body = b) }),
    });
    await provider.detect("hola");
    expect(body).toMatchObject({
      text: "hola",
      language: "es",
      entities: ["PERSON", "LOCATION"],
      score_threshold: 0.7,
    });
  });

  it("converts Presidio codepoint offsets to UTF-16 indices past astral chars", async () => {
    // The 🏥 emoji is one codepoint but two UTF-16 units. Presidio reports the
    // name starting at codepoint index 2 ("🏥 " = 2 codepoints); the JS slice
    // must account for the surrogate pair so the masked span is exact.
    const text = "🏥 Okafor reviewed it";
    const cpStart = Array.from("🏥 ").length; // 2 codepoints
    const cpEnd = cpStart + "Okafor".length;
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      fetchImpl: fakeFetch([
        { entity_type: "PERSON", start: cpStart, end: cpEnd, score: 0.95 },
      ]),
    });
    const hits = await provider.detect(text);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.match).toBe("Okafor");
  });

  it("throws a loud error on a non-OK analyzer response (no silent fallback)", async () => {
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      fetchImpl: fakeFetch({ error: "boom" }, { ok: false, status: 500 }),
    });
    await expect(provider.detect("Park reviewed it")).rejects.toThrow(
      /HTTP 500/,
    );
  });

  it("never echoes the analyzer response body into the thrown error (no PHI to logs)", async () => {
    // An analyzer error page that echoes the (possibly-PHI) request text must
    // not leak into the error message — the ingest path logs `err` and the
    // ledger must stay metadata-only.
    const phi = "patient Jane Doe SSN 123-45-6789";
    let bodyRead = false;
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      fetchImpl: async () => ({
        ok: false,
        status: 400,
        json: async () => ({}),
        text: async () => {
          bodyRead = true;
          return `bad request: ${phi}`;
        },
      }),
    });
    const err = await provider.detect(phi).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).not.toContain("Jane Doe");
    expect(err!.message).not.toContain("123-45-6789");
    expect(err!.message).toMatch(/HTTP 400/);
    // The provider must not even read the response body (defense in depth).
    expect(bodyRead).toBe(false);
  });

  it("returns nothing for empty text without calling fetch", async () => {
    let called = false;
    const provider = new PresidioNerProvider({
      endpoint: "http://presidio:3000",
      fetchImpl: async () => {
        called = true;
        return { ok: true, status: 200, json: async () => [], text: async () => "[]" };
      },
    });
    expect(await provider.detect("")).toEqual([]);
    expect(called).toBe(false);
  });
});

describe("LocalGazetteerNerProvider.detect", () => {
  it("recalls an un-anchored capitalized collision surname Stage-1 omits", async () => {
    // "Park reviewed the chart" — the un-anchored-name gap. Stage-1 stays
    // silent; the local gazetteer recalls it on opt-in.
    const text = "Park reviewed the chart";
    expect(scanForPhi(text)).toEqual([]);
    const hits = await new LocalGazetteerNerProvider().detect(text);
    expect(hits).toContainEqual(
      expect.objectContaining({ detector: "ner_person", match: "Park" }),
    );
  });

  it("recalls an un-anchored capitalized given name", async () => {
    const hits = await new LocalGazetteerNerProvider().detect(
      "Maria submitted the request",
    );
    expect(hits.map((h) => h.match)).toContain("Maria");
  });

  it("stays silent on lowercased collision words by default (capitalizedOnly)", async () => {
    const hits = await new LocalGazetteerNerProvider().detect(
      "the sun set while members park their cars",
    );
    expect(hits).toEqual([]);
  });

  it("recalls lowercased names when capitalizedOnly is disabled", async () => {
    const hits = await new LocalGazetteerNerProvider({
      capitalizedOnly: false,
    }).detect("contact maria for details");
    expect(hits.map((h) => h.match)).toContain("maria");
  });

  it("drops tokens below the minimum length (ambiguous short collisions)", async () => {
    // "Li" / "Le" are dictionary collision tokens but too short to recall
    // un-anchored even on opt-in; the default floor of 3 drops them.
    const hits = await new LocalGazetteerNerProvider().detect("Li and Le met");
    expect(hits).toEqual([]);
    const lower = await new LocalGazetteerNerProvider({ minTokenLen: 2 }).detect(
      "Li met",
    );
    expect(lower.map((h) => h.match)).toContain("Li");
  });

  it("returns nothing for empty text", async () => {
    expect(await new LocalGazetteerNerProvider().detect("")).toEqual([]);
  });

  it("merges into scanForPhiWithNer alongside Stage-1 hits", async () => {
    const text = "Park reviewed the chart";
    const augmented = await scanForPhiWithNer(
      text,
      new LocalGazetteerNerProvider(),
    );
    expect(augmented).toContainEqual(
      expect.objectContaining({ detector: "ner_person", match: "Park" }),
    );
  });
});

describe("ner-config local provider", () => {
  it("parses local case-insensitively", () => {
    expect(loadNerProviderConfigFromEnv({ NER_PROVIDER: "Local" }).provider).toBe(
      "local",
    );
  });

  it("builds a local provider with no extra env", () => {
    const p = createNerProvider({ provider: "local" }, {});
    expect(p.name).toBe("local");
  });

  it("treats a configured local provider as active (non-null)", () => {
    initNerProviderFromEnv({ NER_PROVIDER: "local" });
    expect(getNerProviderOrNull()?.name).toBe("local");
  });

  it("rejects a non-integer / non-positive min token length", () => {
    for (const bad of ["abc", "0", "-1", "2.5"]) {
      expect(() =>
        createNerProvider(
          { provider: "local" },
          { NER_LOCAL_MIN_TOKEN_LEN: bad },
        ),
      ).toThrow(/NER_LOCAL_MIN_TOKEN_LEN/);
    }
  });
});

describe("ner-config registry", () => {
  it("treats none/noop as inert (getNerProviderOrNull returns null)", () => {
    initNerProviderFromEnv({});
    expect(getNerProviderOrNull()).toBeNull();
  });

  it("returns a configured non-noop provider", () => {
    setNerProvider(new FakeNerProvider(["Park"]));
    expect(getNerProviderOrNull()?.name).toBe("fake");
  });

  it("resets to null for tests", () => {
    setNerProvider(new FakeNerProvider([]));
    resetNerProviderForTests();
    expect(getNerProviderOrNull()).toBeNull();
  });
});
