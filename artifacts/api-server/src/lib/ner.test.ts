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
