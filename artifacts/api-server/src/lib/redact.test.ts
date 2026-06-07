import { describe, expect, it } from "vitest";
import { SAFE_REFUSAL, scanForPhi } from "./redact";
import { BENIGN_FIXTURES } from "../evals/fixtures/phi";

describe("scanForPhi", () => {
  it("returns no hits for benign text", () => {
    expect(scanForPhi("There are 3 critical findings open.")).toEqual([]);
    expect(scanForPhi("")).toEqual([]);
  });

  // Precision control set: realistic operational log lines that look
  // numeric/structured/proper-noun-like but contain no PHI. This shares the
  // exact corpus used by the on-demand detector eval (BENIGN_FIXTURES) so a
  // future regex tweak that re-introduces a false positive fails fast in the
  // normal `pnpm test` run, not just in the eval gate.
  describe("benign precision corpus (shared with detector eval)", () => {
    it.each(BENIGN_FIXTURES)(
      "produces zero detector hits for $id: $text",
      ({ text }) => {
        expect(scanForPhi(text)).toEqual([]);
      },
    );
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
      // `token=` also trips high_entropy_secret (defense-in-depth overlap), so
      // assert the specific detector rather than the total hit count.
      const hits = scanForPhi("token=ASIAABCDEFGHIJKLMNOP").filter(
        (h) => h.detector === "aws_akid",
      );
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

  // M13.1 — date of birth (non-slash, birth-context anchored).
  describe("M13.1 dob_date detector", () => {
    it("detects ISO/textual/dash DOBs only in birth context", () => {
      for (const s of [
        '{"dob":"1981-03-14"}',
        "date of birth March 14, 1981 confirmed",
        "dob=03-14-1981",
        "born 14 March 1981",
      ]) {
        const hits = scanForPhi(s).filter((h) => h.detector === "dob_date");
        expect(hits).toHaveLength(1);
        expect(hits[0]!.classification).toBe("phi");
      }
    });

    it("does NOT flag routine ISO timestamps with no birth context", () => {
      expect(scanForPhi("ts=2025-02-01T00:00:00Z level=warn")).toEqual([]);
      expect(scanForPhi("deployed 2025-02-01 at 12:00")).toEqual([]);
    });
  });

  // M13.2 — IPv6, license plate, passport, DEA.
  describe("M13.2 identifiers", () => {
    it("detects full and compressed IPv6 addresses", () => {
      for (const ip of [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1ff:fe23:4567:890a",
        "2001:db8::8a2e:370:7334",
      ]) {
        const hits = scanForPhi(`client_ip=${ip} ok`).filter(
          (h) => h.detector === "ipv6",
        );
        expect(hits).toHaveLength(1);
        expect(hits[0]!.match).toBe(ip);
      }
    });

    it("does NOT flag host:port or file:line:col colon noise as IPv6", () => {
      for (const s of [
        "endpoint=internal.svc.local:8443 ready",
        "at server.js:1024:17 in handler",
        "node:internal/process/task_queues.js:95:5",
      ]) {
        expect(scanForPhi(s).filter((h) => h.detector === "ipv6")).toEqual([]);
      }
    });

    it("detects context-anchored license plate and passport", () => {
      const plate = scanForPhi("license plate 7XYZ123 on file").filter(
        (h) => h.detector === "license_plate",
      );
      expect(plate).toHaveLength(1);
      expect(plate[0]!.match).toBe("7XYZ123");

      const passport = scanForPhi("passport=X1234567 verified").filter(
        (h) => h.detector === "passport",
      );
      expect(passport).toHaveLength(1);
      expect(passport[0]!.match).toBe("X1234567");
    });

    it("detects checksum-valid DEA numbers and rejects bad checksums", () => {
      const ok = scanForPhi("prescriber DEA AB1234563 refill").filter(
        (h) => h.detector === "dea",
      );
      expect(ok).toHaveLength(1);
      expect(ok[0]!.match).toBe("AB1234563");
      // Same shape, wrong check digit → rejected.
      expect(scanForPhi("DEA AB1234560").filter((h) => h.detector === "dea")).toEqual(
        [],
      );
    });
  });

  // M13.3 (partial) — context-anchored word-collision surnames.
  describe("M13.3 context-anchored word-collision surnames", () => {
    const names = (text: string) =>
      scanForPhi(text)
        .filter((h) => h.detector === "name")
        .map((h) => h.match);

    it("recalls a collision surname when a context keyword anchors it", () => {
      expect(names("Lab results for patient Sun were filed.")).toContain("Sun");
      expect(names("Follow-up assigned to member Li today.")).toContain("Li");
      // Colon separator after the context keyword.
      expect(names("Returned by enrollee: Park before noon.")).toContain("Park");
    });

    it("does NOT fire on the ordinary-word use of a collision token", () => {
      // Lowercase prose word, no context keyword.
      expect(names("The sun set over region us-west-2.")).toEqual([]);
      // Context keyword present but the collision token is lowercase prose.
      expect(names("Members park their idle sessions.")).toEqual([]);
      // Capitalized, context keyword present, but across a SENTENCE boundary.
      expect(names("Notified the patient. Sun exposure guidance updated.")).toEqual(
        [],
      );
      // Token must match exactly: "parking" is not the surname "park".
      expect(names("Patient parking validation completed.")).toEqual([]);
      // "An" is intentionally excluded as too-common a word.
      expect(names("Notified patient An before the appointment.")).toEqual([]);
      // Capitalization is the discriminator: lowercase prose stays silent even
      // with a context keyword present ("patient sun exposure", not a name).
      expect(names("Reviewed patient sun exposure guidance.")).toEqual([]);
    });

    it("treats a Capitalized collision token after a context keyword as a name (PHI-safe over-redaction)", () => {
      // No sentence boundary + Capitalized + context keyword → flagged. This is
      // the accepted precision edge documented in redact.ts pass 5: we redact
      // rather than risk leaking a real surname "Sun".
      expect(names("Reviewed patient Sun exposure guidance.")).toContain("Sun");
    });
  });

  // M13.4 — additional secret classes.
  describe("M13.4 secret classes", () => {
    it("detects prefix-anchored provider secrets", () => {
      const cases: [string, string, string][] = [
        ["k1 sk_live_4eC39HqLyjWDarjtT1zdp7dc", "stripe_key", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"],
        ["k2 ACa1b2c3d4e5f6071829304a5b6c7d8e9f", "twilio_sid", "ACa1b2c3d4e5f6071829304a5b6c7d8e9f"],
        ["k3 sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv", "llm_api_key", "sk-ant-api03-abcdefGHIJKL1234567890mnopqrstuv"],
        ["k4 npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm_token", "npm_abcdefghijklmnopqrstuvwxyz0123456789"],
        ["k5 hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789", "vault_token", "hvs.CAESIabcdefghijklmnopqrstuvwxyz0123456789"],
      ];
      for (const [text, detector, match] of cases) {
        const hit = scanForPhi(text).find((h) => h.detector === detector);
        expect(hit, `${detector} should fire`).toBeDefined();
        expect(hit!.classification).toBe("secrets");
        expect(hit!.match).toBe(match);
      }
    });

    it("detects context-anchored AWS secret access key", () => {
      const hits = scanForPhi(
        "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      ).filter((h) => h.detector === "aws_secret_key");
      expect(hits).toHaveLength(1);
      expect(hits[0]!.match).toBe("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
    });
  });

  // M13.5 — generic high-entropy secret.
  describe("M13.5 high_entropy_secret detector", () => {
    it("flags a high-entropy value on a secret-shaped key", () => {
      const hits = scanForPhi("api_key=9f8e7d6c5b4a3210ffeeddccbbaa9988").filter(
        (h) => h.detector === "high_entropy_secret",
      );
      expect(hits).toHaveLength(1);
      expect(hits[0]!.classification).toBe("secrets");
      expect(hits[0]!.match).toBe("9f8e7d6c5b4a3210ffeeddccbbaa9988");
    });

    it("does NOT flag short or low-entropy values", () => {
      expect(scanForPhi("token=ok")).toEqual([]);
      expect(scanForPhi("api_key=aaaaaaaaaaaaaaaaaaaaaaaa")).toEqual([]);
      expect(scanForPhi("account=disabled subscriber=none")).toEqual([]);
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
