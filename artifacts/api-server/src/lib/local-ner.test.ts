// Unit tests for the local (offline) gazetteer Stage-2 NER provider.
//
// The contract under test is the precision/recall tradeoff the provider exists
// to make explicit: it recovers the *un-anchored dictionary-name* slice that the
// always-on Stage-1 detector (scanForPhi) deliberately leaves silent for
// precision, WITHOUT a service or SDK — and it stays precision-bounded
// (capitalized-only, min token length) so an operator opt-in does not turn into
// a benign-prose false-positive cannon.

import { describe, it, expect } from "vitest";
import { LocalGazetteerNerProvider } from "./local-ner";
import { scanForPhi } from "./redact";

describe("LocalGazetteerNerProvider", () => {
  const provider = new LocalGazetteerNerProvider();

  it("recovers an un-anchored capitalized collision surname that Stage-1 misses", async () => {
    // "Park" is a COLLISION_SURNAMES entry: a real surname that is also a common
    // English word. Stage-1 (scanForPhi) leaves it silent un-anchored by design.
    const text = "Approved by Park during the incident review.";

    const stage1 = scanForPhi(text);
    expect(stage1).toHaveLength(0); // the documented Stage-1 gap

    const hits = await provider.detect(text);
    expect(hits).toHaveLength(1);
    expect(hits[0].detector).toBe("ner_person");
    expect(text.slice(hits[0].start, hits[0].end)).toBe("Park");
  });

  it("recovers multiple un-anchored gazetteer names in one line", async () => {
    const text = "Owners: Park, Moon, and Song signed off.";
    const hits = await provider.detect(text);
    expect(hits.map((h) => text.slice(h.start, h.end)).sort()).toEqual([
      "Moon",
      "Park",
      "Song",
    ]);
  });

  it("stays silent on benign operational prose (precision holds)", async () => {
    const text =
      "The load balancer returned a 500 error after the retention sweep.";
    expect(await provider.detect(text)).toHaveLength(0);
  });

  it("does not recall lowercase word-collision tokens by default (capitalizedOnly)", async () => {
    // "park" / "sun" lowercased are ordinary words, not name candidates.
    const text = "users walk in the park under the sun";
    expect(await provider.detect(text)).toHaveLength(0);
  });

  it("recalls lowercase names when capitalizedOnly is disabled", async () => {
    const lower = new LocalGazetteerNerProvider({ capitalizedOnly: false });
    const text = "signed off by park";
    const hits = await lower.detect(text);
    expect(hits).toHaveLength(1);
    expect(text.slice(hits[0].start, hits[0].end)).toBe("park");
  });

  it("drops sub-minimum-length collision tokens (li/le) at the default floor", async () => {
    // "Li"/"Le" are real surnames but too ambiguous to recall un-anchored even
    // on opt-in; the default minTokenLen of 3 drops them.
    const text = "Reviewed by Li and Le before merge.";
    expect(await provider.detect(text)).toHaveLength(0);

    // Lowering the floor recalls them (operator's explicit choice).
    const loose = new LocalGazetteerNerProvider({ minTokenLen: 2 });
    const hits = await loose.detect(text);
    expect(hits.map((h) => text.slice(h.start, h.end)).sort()).toEqual([
      "Le",
      "Li",
    ]);
  });

  it("returns no hits on empty input", async () => {
    expect(await provider.detect("")).toHaveLength(0);
  });
});
