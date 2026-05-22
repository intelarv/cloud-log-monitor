import { describe, expect, it } from "vitest";
import { SAFE_REFUSAL, scanForPhi } from "./redact";

describe("scanForPhi", () => {
  it("returns no hits for benign text", () => {
    expect(scanForPhi("There are 3 critical findings open.")).toEqual([]);
    expect(scanForPhi("")).toEqual([]);
  });

  describe("PHI detectors", () => {
    it("detects a valid US SSN", () => {
      const hits = scanForPhi("patient ssn 123-45-6789 today");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({
        classification: "phi",
        detector: "ssn",
        match: "123-45-6789",
      });
    });

    it("rejects SSNs in invalid number ranges", () => {
      // 000-xx-xxxx, 666-xx-xxxx, 9xx-xx-xxxx are not assigned by SSA
      expect(scanForPhi("000-12-3456")).toEqual([]);
      expect(scanForPhi("666-12-3456")).toEqual([]);
      expect(scanForPhi("900-12-3456")).toEqual([]);
      // group=00 and serial=0000 are also invalid
      expect(scanForPhi("123-00-4567")).toEqual([]);
      expect(scanForPhi("123-45-0000")).toEqual([]);
    });

    it("detects MRN-style identifiers", () => {
      const samples = [
        "MRN: 1234567",
        "mrn#998877",
        "MRN-456789",
      ];
      for (const s of samples) {
        const hits = scanForPhi(s);
        expect(hits, s).toHaveLength(1);
        expect(hits[0]!.detector).toBe("mrn_like");
        expect(hits[0]!.classification).toBe("phi");
      }
    });
  });

  describe("PII detectors", () => {
    it("detects emails", () => {
      const hits = scanForPhi("contact me at alice@example.com please");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.detector).toBe("email");
      expect(hits[0]!.classification).toBe("pii");
      expect(hits[0]!.match).toBe("alice@example.com");
    });

    it("detects phone numbers in several formats", () => {
      // Formats the M0 regex detector supports today. The leading `\b` anchor
      // means a `(415) …` style with no preceding word character is NOT
      // matched — that's a known M0 limitation, covered by its own test
      // below so the gap is visible if anyone tightens the detector.
      const cases = [
        "+1 415-555-1212",
        "415.555.1212",
        "4155551212",
        "call 415-555-1212 tomorrow",
      ];
      for (const c of cases) {
        const hits = scanForPhi(c).filter((h) => h.detector === "phone");
        expect(hits.length, c).toBeGreaterThanOrEqual(1);
      }
    });

    it("documents known M0 phone-detector gap: parenthesized area code", () => {
      // If someone tightens the phone detector to handle this, flip the
      // assertion — this test exists so the gap is loud.
      expect(scanForPhi("(415) 555-1212")).toEqual([]);
    });

    it("detects credit-card-like sequences", () => {
      const hits = scanForPhi("card 4111 1111 1111 1111 charged");
      const cc = hits.filter((h) => h.detector === "credit_card_like");
      expect(cc).toHaveLength(1);
      expect(cc[0]!.classification).toBe("pii_s");
    });
  });

  describe("secrets detectors", () => {
    it("detects an AWS access key id", () => {
      const hits = scanForPhi("creds=AKIAIOSFODNN7EXAMPLE leaked");
      expect(hits).toHaveLength(1);
      expect(hits[0]).toMatchObject({
        classification: "secrets",
        detector: "aws_akid",
        match: "AKIAIOSFODNN7EXAMPLE",
      });
    });

    it("detects an ASIA temporary access key id", () => {
      const hits = scanForPhi("token=ASIAABCDEFGHIJKLMNOP");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.detector).toBe("aws_akid");
    });

    it("detects a JWT-shaped token", () => {
      const jwt =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ" +
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
      const hits = scanForPhi(`bearer ${jwt}`);
      expect(hits).toHaveLength(1);
      expect(hits[0]!.detector).toBe("jwt");
      expect(hits[0]!.classification).toBe("secrets");
    });
  });

  describe("multiple and overlapping detectors", () => {
    it("returns all hits when text contains several distinct kinds", () => {
      const text =
        "Patient MRN: 1234567 email alice@example.com ssn 123-45-6789";
      const hits = scanForPhi(text);
      const detectors = hits.map((h) => h.detector).sort();
      expect(detectors).toEqual(["email", "mrn_like", "ssn"]);
    });

    it("returns multiple hits when the same detector matches twice", () => {
      const hits = scanForPhi("a@b.co and c@d.co");
      expect(hits.filter((h) => h.detector === "email")).toHaveLength(2);
    });

    it("reports offsets that index back into the original string", () => {
      const text = "x x alice@example.com y";
      const [hit] = scanForPhi(text);
      expect(hit).toBeDefined();
      expect(text.slice(hit!.start, hit!.end)).toBe(hit!.match);
    });
  });

  it("is deterministic across repeated calls (regex lastIndex reset)", () => {
    const text = "ssn 123-45-6789 email alice@example.com";
    const a = scanForPhi(text);
    const b = scanForPhi(text);
    expect(a).toEqual(b);
  });
});

describe("SAFE_REFUSAL", () => {
  it("is a non-empty user-facing string", () => {
    expect(typeof SAFE_REFUSAL).toBe("string");
    expect(SAFE_REFUSAL.length).toBeGreaterThan(0);
  });

  it("does not itself contain any PHI/secret patterns", () => {
    expect(scanForPhi(SAFE_REFUSAL)).toEqual([]);
  });
});
