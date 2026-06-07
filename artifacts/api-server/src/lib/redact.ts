// Output PHI/PII scanner. Runs over every assistant message before it leaves
// the server. Per ARCHITECTURE.md §23.1, PHI detected in agent output is
// itself a *finding about the agent*, not just a leak: caller logs an incident
// to the ledger and substitutes a safe refusal.
//
// The detectors here are the same shape M0 uses for log detectors — regex
// patterns tagged with a classification. Real production replaces these with
// a Stage-1+2 pipeline plus dictionary lookups.

import type { NerProvider } from "./ner";

export interface PhiHit {
  classification: "phi" | "secrets" | "pii" | "pii_s";
  detector: string;
  // Match offsets into the original string.
  start: number;
  end: number;
  // The raw matched text — do NOT log this; only used for replacement.
  match: string;
}

interface Detector {
  classification: PhiHit["classification"];
  name: string;
  // Regex-driven detector. Optional because some detectors (e.g. `name`) need
  // dictionary lookups / multi-token context that a single regex can't express
  // and supply a `scan` instead.
  regex?: RegExp;
  // Optional post-match predicate. A regex match is only reported when this
  // returns true — used to apply a checksum (Luhn) on top of the shape match.
  validate?: (match: string) => boolean;
  // Optional fully-custom scanner for detectors that go beyond a single regex.
  // Returns half-open spans into `text`.
  scan?: (text: string) => { start: number; end: number; match: string }[];
}

// Luhn (mod-10) checksum. Strips spaces/dashes, requires a plausible PAN
// length (13–19 digits), and rejects sequences that fail the checksum so
// arbitrary long digit runs (order numbers, request/trace ids) are not
// flagged as card numbers.
function luhnValid(raw: string): boolean {
  const digits = raw.replace(/[^0-9]/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// DEA registration number checksum. A DEA number is two letters followed by
// seven digits; the 7th digit is a check digit: ((d1+d3+d5) + 2*(d2+d4+d6))
// mod 10 must equal d7. The checksum (not just the shape) is what keeps this
// detector off arbitrary "2 letters + 7 digits" tokens, mirroring how the
// card detector leans on Luhn rather than length alone.
function deaValid(match: string): boolean {
  const digits = match.slice(-7);
  if (!/^\d{7}$/.test(digits)) return false;
  const d = digits.split("").map((c) => c.charCodeAt(0) - 48);
  const check = d[0]! + d[2]! + d[4]! + 2 * (d[1]! + d[3]! + d[5]!);
  return check % 10 === d[6]!;
}

// Shannon entropy in bits/char. Used by the generic high-entropy secret
// detector to tell a real credential ("9f8e7d6c…") from an ordinary slug
// ("service-mesh-cluster") assigned to the same key.
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let h = 0;
  for (const k of Object.keys(freq)) {
    const p = freq[k]! / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

// Generic high-entropy secret (M13.5, last-resort). Fires on a value assigned
// to a secret-shaped key (api_key / secret / token / client_secret / ...) ONLY
// when the value is long AND high-entropy — so `token=ok`, `account=disabled`,
// and ordinary slugs do not match, while opaque base64/hex credentials without
// a recognizable provider prefix still get caught. The two conditions
// (key context + entropy) together are what hold precision.
const HIGH_ENTROPY_KEY_RE =
  /\b(?:api[_-]?key|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|auth[_-]?token|token|apikey)\b["']?\s*[:=]\s*["']?([A-Za-z0-9_./+-]{20,})/gi;
function scanHighEntropySecret(
  text: string,
): { start: number; end: number; match: string }[] {
  const spans: { start: number; end: number; match: string }[] = [];
  HIGH_ENTROPY_KEY_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = HIGH_ENTROPY_KEY_RE.exec(text)) !== null) {
    const value = m[1]!;
    if (shannonEntropy(value) >= 3.5) {
      const start = m.index + m[0].length - value.length;
      spans.push({ start, end: start + value.length, match: value });
    }
    if (m.index === HIGH_ENTROPY_KEY_RE.lastIndex) HIGH_ENTROPY_KEY_RE.lastIndex++;
  }
  return spans;
}

// Lightweight name dictionaries (lowercased). A curated list of common
// given names and surnames provides an NER-style signal so names that the
// capitalized "First [M] Last" heuristic misses — lowercase names, or a
// single surname after a title/context word — are still detected, without
// firing on the benign operational text the precision controls cover.
// Word-like names (Mark, Will, May, Rose, Bill, …) are deliberately omitted
// to keep the dictionary from matching ordinary prose.
//
// Recall on a diverse patient population (task: "catch a wider range of
// patient names, including non-Western ones"). Decision — **broader
// multicultural gazetteer over a runtime NER model**:
//   - A real NER model (Presidio / spaCy / clinical-BERT, see
//     ARCHITECTURE.md §11) means a heavyweight dependency + downloaded model
//     weights, which is incompatible with the deterministic, credential-free,
//     offline eval gate (`evals/gate.mjs`) that runs on every change. NER is
//     the documented production path (per-deployment, behind the same
//     detector interface), but the dev/default detector stays gazetteer-based.
//   - So the curated lists below are extended with common given names and
//     surnames from South Asian, East Asian (Chinese/Japanese/Korean),
//     Arabic/Persian/Turkish, African, Slavic, Vietnamese, and Greek naming
//     traditions. Combined with the case-insensitive adjacent-pair pass and
//     the title/context single-name passes, this lifts recall on non-Western,
//     lowercase, and single-token-with-context names while the
//     "dictionary-membership required" rule keeps precision high (benign
//     operational text never matches). Recall/precision is measured by the
//     `detector-phi` eval over the diverse fixtures in `evals/fixtures/phi.ts`.
//   - Tokens that collide with ordinary English words (e.g. Tang, Dang, Sun,
//     Park, An, Li, Le) are deliberately omitted; recall on those few is a
//     known, documented limitation that the production NER path closes.
const GIVEN_NAMES = new Set<string>(
  (
    "james john robert michael david richard joseph thomas charles christopher " +
    "daniel matthew anthony donald steven andrew joshua kenneth kevin brian " +
    "george timothy ronald jason edward jeffrey ryan jacob gary nicholas eric " +
    "jonathan stephen larry justin scott brandon benjamin samuel gregory " +
    "alexander patrick jack dennis jerry tyler aaron jose henry adam douglas " +
    "nathan peter zachary walter carl arthur gerald keith samuel lawrence " +
    "sean christian ethan austin joe albert jesse bryan bruce noah jordan " +
    "dylan ralph roy eugene alan juan luis carlos miguel angel oscar mary " +
    "patricia jennifer linda elizabeth barbara susan jessica sarah karen " +
    "nancy lisa margaret betty sandra ashley dorothy kimberly emily donna " +
    "michelle carol amanda melissa deborah stephanie rebecca laura sharon " +
    "cynthia kathleen amy angela shirley anna brenda pamela nicole ruth " +
    "katherine samantha christine emma catherine debra rachel carolyn janet " +
    "maria heather diane julie joyce victoria kelly christina joan evelyn " +
    "olivia sophia isabella ava charlotte amelia harper abigail jane alice " +
    "rosa ana sofia juana carmen " +
    // South Asian
    "aarav arjun aditya rohan vihaan ishaan reyansh arnav kabir advik " +
    "priya ananya saanvi aanya aadhya kavya anika ishita riya navya myra " +
    "deepak rajesh sanjay anil vijay sunil ravi suresh " +
    // East Asian (Chinese / Japanese / Korean given names)
    "wei ming jing hao yan mei xiang haruto yuto sakura yuki hina haruki " +
    "kenji akira hiroshi kaito sora jisoo jiho minjun seojun hyun " +
    // Arabic / Persian / Turkish
    "mohammed muhammad ahmed ali omar fatima aisha hassan hussein ibrahim " +
    "yusuf khalid layla zainab mariam nour amir reza mehmet emre zeynep abdullah " +
    // African
    "kwame kofi ngozi amara thabo sipho zola amani jabari folake adanna chinwe chidi " +
    // Slavic
    "ivan dmitri natasha olga vladimir anastasia yuri sergei nikolai tatiana"
  ).split(/\s+/),
);
const SURNAMES = new Set<string>(
  (
    "smith johnson williams brown jones garcia miller davis rodriguez martinez " +
    "hernandez lopez gonzalez wilson anderson thomas taylor moore jackson " +
    "martin lee perez thompson white harris sanchez clark ramirez lewis " +
    "robinson walker young allen king wright scott torres nguyen hill flores " +
    "green adams nelson baker hall rivera campbell mitchell carter roberts " +
    "gomez phillips evans turner diaz parker cruz edwards collins reyes " +
    "stewart morris morales murphy cook rogers gutierrez ortiz morgan cooper " +
    "peterson bailey reed kelly howard ramos kim cox ward richardson watson " +
    "brooks chavez wood bennett gray mendoza ruiz hughes price alvarez " +
    "castillo sanders patel myers ross foster jimenez powell jenkins perry " +
    "russell sullivan bell coleman butler henderson barnes gonzales fisher " +
    "vasquez simmons romero jordan patterson alexander hamilton graham " +
    "reynolds griffin wallace west cole hayes bryant herrera gibson ellis " +
    "tran medina aguilar stevens murray ford castro marshall owens harrison " +
    "fernandez mcdonald woods washington kennedy wells vargas henry freeman " +
    "smithfield " +
    // South Asian
    "sharma gupta reddy nair iyer singh kumar rao desai mehta banerjee bose " +
    "chatterjee joshi kapoor malhotra agarwal verma chauhan chowdhury das " +
    // Chinese
    "chen wang zhang zhao wu zhou xu huang lin yang zheng deng feng " +
    // Korean
    "choi jung kang yoon jang lim shin " +
    // Japanese
    "tanaka suzuki sato takahashi watanabe ito yamamoto nakamura kobayashi " +
    "kato yoshida yamada sasaki matsumoto inoue " +
    // Arabic / Persian
    "khan saleh haddad nasser farah rahman abadi " +
    // African
    "okonkwo okafor adeyemi mensah nkosi dlamini mwangi achebe okeke eze " +
    "adebayo balogun " +
    // Slavic
    "ivanov petrov volkov sokolov nowak kowalski novak kuznetsov popov wojcik " +
    // Vietnamese / Greek
    "pham bui papadopoulos"
  ).split(/\s+/),
);
// Personal titles that, immediately preceding a single dictionary name, are a
// strong enough signal to flag that lone name ("Dr. Patel"). Kept narrow to
// avoid colliding with log units like "ms".
const NAME_TITLES = new Set<string>(["mr", "mrs", "miss", "dr", "doctor"]);
// Patient-context keywords that, immediately preceding a single dictionary
// name, are a strong enough signal to flag that lone name ("patient Ngozi",
// "member Garcia"). This recalls single-token non-Western names the casing
// heuristic misses (it needs ≥2 capitalized tokens). The following token must
// still be a dictionary name, so benign phrases ("patient portal", "member
// services") never match.
const NAME_CONTEXT = new Set<string>([
  "patient",
  "member",
  "resident",
  "enrollee",
  "subscriber",
  "beneficiary",
  "claimant",
]);

// M13.3 (partial) — context-anchored word-collision surnames. Real, common
// surnames (especially East/South-East Asian) that ALSO collide with ordinary
// English words: "Park", "Sun", "Tang", "Li", "Le", "Song", "Moon", "Long".
// They are deliberately kept OUT of GIVEN_NAMES/SURNAMES because the bare
// adjacent-pair and casing passes would then fire on ordinary prose ("the sun
// set", "members park their sessions"). They are recalled ONLY when ALL of:
//   (a) an immediately-preceding person-context keyword anchors them
//       ("patient Sun", "member Li") — the honorific case ("Dr. Park") is
//       already covered by the honorific arm of NAME_CASING_RE;
//   (b) the token is Capitalized (a lowercase collision word in prose stays
//       unmatched); and
//   (c) the separator is NOT a sentence-ending period, so a clause boundary
//       ("patient. Sun exposure guidance …") does not anchor a collision word.
// These three conditions together make a benign operational-log match
// implausible while catching the single-token collision-surname-with-context
// case the dictionary passes miss. The remaining *un-anchored* word-collision
// case ("Park reviewed the chart") cannot be closed deterministically without
// regressing precision and stays deferred to the production NER path (M13.3 /
// ARCHITECTURE.md §11). "An" is intentionally excluded even here — it is too
// common a word for a context anchor alone to disambiguate safely.
const COLLISION_SURNAMES = new Set<string>(
  "park sun tang dang li le song moon long".split(/\s+/),
);
const isCapitalizedName = (w: string): boolean => /^[A-Z][a-z]+$/.test(w);

// Precision-tightened name-casing heuristic. A bare capitalized-word-pair
// regex over-matches ordinary TitleCase operational text ("Load Balancer",
// "Internal Server Error", "Patient Portal", "Type A Record"), so pass 1 fires
// only on two strongly name-shaped forms:
//   1. Honorific-prefixed ("Dr. Marcus Chen") — an unambiguous person signal
//      that does not appear in ops-log compounds, and catches names not in the
//      dictionaries below.
//   2. Person-keyword-anchored with a required middle initial ("Patient
//      Jonathan Q Smithfield") — the single-letter middle token is the
//      discriminator that operational compounds like "Member Service Account"
//      lack.
// Broader capitalized names without these signals are left to the dictionary
// passes (and future NER work) so benign capitalized prose is not flagged.
// The person-keyword separator class includes JSON quotes (`"` / `'`) and `=`
// in addition to `.`/`:`/whitespace so the keyword still anchors when the name
// is a JSON value (`"patient":"Jonathan Q Smithfield"`) or a logfmt field
// (`patient=...`) — the required middle-initial token keeps benign TitleCase
// compounds ("Patient Portal Settings") from matching regardless of separator.
const NAME_CASING_RE =
  /(?:(?<=\b(?:Dr|Mr|Mrs|Ms|Miss|Prof)\.?\s+)[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?|(?<=\b(?:[Pp]atient|[Mm]ember|[Ss]ubscriber|[Bb]eneficiary|[Gg]uarantor|[Ii]nsured|[Dd]ependent|[Ee]nrollee|[Rr]esident)[.:\s"'=]+)[A-Z][a-z]+\s+(?:[A-Z]\.?\s+)+[A-Z][a-z]+)/g;

// Combined name detector: the casing heuristic plus dictionary-driven signals
// (adjacent given/surname tokens regardless of case, and title + single name).
function scanNames(
  text: string,
): { start: number; end: number; match: string }[] {
  const spans: { start: number; end: number; match: string }[] = [];

  // 1) Casing heuristic.
  NAME_CASING_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = NAME_CASING_RE.exec(text)) !== null) {
    spans.push({ start: m.index, end: m.index + m[0].length, match: m[0] });
    if (m.index === NAME_CASING_RE.lastIndex) NAME_CASING_RE.lastIndex++;
  }

  // Tokenize alphabetic words with positions for the dictionary passes.
  const tokenRe = /[A-Za-z][A-Za-z'-]*/g;
  const tokens: { t: string; start: number; end: number }[] = [];
  while ((m = tokenRe.exec(text)) !== null) {
    tokens.push({ t: m[0], start: m.index, end: m.index + m[0].length });
  }
  const isName = (w: string): boolean => {
    const lc = w.toLowerCase();
    return GIVEN_NAMES.has(lc) || SURNAMES.has(lc);
  };
  // Whitespace-only gap between two tokens (so "jane.doe" / "a@b" aren't pairs).
  const spaceGap = (a: { end: number }, b: { start: number }): boolean =>
    /^[ \t]+$/.test(text.slice(a.end, b.start));
  // Title gap allows a trailing period ("Dr." / "Dr").
  const titleGap = (a: { end: number }, b: { start: number }): boolean =>
    /^\.?[ \t]+$/.test(text.slice(a.end, b.start));
  // Context gap for collision surnames: whitespace or a single colon, but NOT a
  // sentence-ending period — so "patient: Sun" / "member Li" anchor, while
  // "patient. Sun exposure …" (new clause) does not.
  const contextGapNoPeriod = (a: { end: number }, b: { start: number }): boolean =>
    /^[ \t]*:?[ \t]+$/.test(text.slice(a.end, b.start));

  for (let i = 0; i + 1 < tokens.length; i++) {
    const a = tokens[i]!;
    const b = tokens[i + 1]!;
    // 2) Two adjacent dictionary name tokens ("maria gonzalez", any case).
    if (isName(a.t) && isName(b.t) && spaceGap(a, b)) {
      spans.push({ start: a.start, end: b.end, match: text.slice(a.start, b.end) });
      continue;
    }
    // 3) Title + single dictionary name ("Dr. Patel").
    if (NAME_TITLES.has(a.t.toLowerCase()) && isName(b.t) && titleGap(a, b)) {
      spans.push({ start: b.start, end: b.end, match: b.t });
      continue;
    }
    // 4) Patient-context keyword + single dictionary name ("patient Ngozi").
    // titleGap also covers a "patient: Ngozi" colon separator.
    if (NAME_CONTEXT.has(a.t.toLowerCase()) && isName(b.t) && titleGap(a, b)) {
      spans.push({ start: b.start, end: b.end, match: b.t });
      continue;
    }
    // 5) Patient-context keyword + Capitalized word-collision surname
    // ("patient Sun", "member Li"). Stricter than pass 4: the surname is NOT in
    // the dictionary (collision words are deliberately excluded), so it must be
    // Capitalized and the separator must not be a sentence-ending period. See
    // COLLISION_SURNAMES for the precision rationale.
    //
    // Capitalization is the deliberate discriminator: lowercase prose
    // ("patient sun exposure guidance") stays silent, while a mid-clause
    // Capitalized collision token right after a person-context keyword
    // ("patient Sun exposure") IS flagged. That last case favors PHI-safe
    // over-redaction over leaking a real surname — an accepted precision edge of
    // this anchored slice (the un-anchored case stays deferred to NER).
    if (
      NAME_CONTEXT.has(a.t.toLowerCase()) &&
      COLLISION_SURNAMES.has(b.t.toLowerCase()) &&
      isCapitalizedName(b.t) &&
      contextGapNoPeriod(a, b)
    ) {
      spans.push({ start: b.start, end: b.end, match: b.t });
    }
  }
  return spans;
}

const DETECTORS: Detector[] = [
  // US SSN
  {
    classification: "phi",
    name: "ssn",
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  // Email
  {
    classification: "pii",
    name: "email",
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
  },
  // Phone (loose North American + intl)
  {
    classification: "pii",
    name: "phone",
    regex: /\b(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
  },
  // Card-like number: a 13–19 digit run (optionally space/dash grouped) that
  // ALSO passes a Luhn checksum, so arbitrary long digit sequences (order
  // numbers, request/trace ids) are not flagged as card numbers.
  {
    classification: "pii_s",
    name: "credit_card_like",
    regex: /\b(?:\d[ -]?){13,19}\b/g,
    validate: luhnValid,
  },
  // MRN-like: literal "MRN" followed by digits. The separator class accepts
  // JSON quotes (`"`/`'`) and `=` in addition to `:`/`#`/`-`/space so the
  // detector still fires when the MRN is a JSON value (`"mrn":"4456789"`) or a
  // logfmt field (`mrn=4456789`), not just the prose `MRN: 4456789` form.
  {
    classification: "phi",
    name: "mrn_like",
    regex: /\bMRN["'=:\s#-]*\d{4,}\b/gi,
  },
  // AWS access key id
  {
    classification: "secrets",
    name: "aws_akid",
    regex: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  // JWT (3 dot-separated base64url segments)
  {
    classification: "secrets",
    name: "jwt",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },

  // ---------------------------------------------------------------------------
  // M11 follow-up: close the HIPAA Safe-Harbor coverage gaps the eval suite
  // measured (detector-phi recall 0.37 → ~1.0). Each pattern is written to fire
  // ONLY on a clearly-PHI-shaped token so benign operational log text (the
  // eval's precision controls) stays unmatched.
  // ---------------------------------------------------------------------------

  // Personal name: precision-tightened casing heuristic (honorific- or
  // person-keyword-anchored, see NAME_CASING_RE) PLUS dictionary signals
  // (adjacent given/surname tokens in any case, and title + single name). See
  // `scanNames` — the dictionary passes recall lowercase / unusual names the
  // casing pass misses ("maria gonzalez", "Dr. Patel") while the tightened
  // casing pass keeps benign capitalized prose ("Load Balancer", "Type A
  // Record") from firing.
  {
    classification: "phi",
    name: "name",
    scan: scanNames,
  },
  // Street address: house number + a capitalized street-name word + a
  // street-type suffix ("4471 Maplewood Avenue"). At least one street-name word
  // between the number and the suffix is REQUIRED: a bare "number + suffix"
  // shape matched ordinary log phrases like "3 Way handshake", "5 Highway
  // patrol", and "12 Drive slots" because the suffix list contains common
  // English words. The suffix list is case-sensitive to avoid lowercase prose.
  {
    classification: "phi",
    name: "street_address",
    regex:
      /\b\d{1,6}\s+(?:[A-Z][A-Za-z0-9.'-]*\s+){1,4}(?:Avenue|Ave|Street|St|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Highway|Hwy|Parkway|Pkwy|Square|Sq|Trail|Trl)\b\.?/g,
  },
  // ZIP code: 5 digits (optionally ZIP+4) in the "City, ST 62704" form. The
  // bare "<2 caps> <5 digits>" shape also matched ordinary log tokens like
  // "Cluster ID 88421" (ID = identifier, not Idaho), so the comma before the
  // state code is required — it is what distinguishes a postal address from an
  // uppercase label followed by a number.
  {
    classification: "phi",
    name: "zip_code",
    regex: /(?<=,\s[A-Z]{2}\s)\d{5}(?:-\d{4})?\b/g,
  },
  // Date: slash-delimited calendar date ("03/14/1981"). Restricted to the
  // slash form so it does not fire on version strings or ISO timestamps that
  // are routine in operational logs.
  {
    classification: "phi",
    name: "date",
    regex: /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g,
  },
  // Vehicle identification number: 17 chars from the VIN alphabet (excludes
  // I/O/Q) containing at least one letter and one digit.
  {
    classification: "phi",
    name: "vin",
    regex:
      /\b(?=[0-9A-HJ-NPR-Z]*[A-Z])(?=[0-9A-HJ-NPR-Z]*\d)[0-9A-HJ-NPR-Z]{17}\b/g,
  },
  // URL.
  {
    classification: "pii",
    name: "url",
    regex: /\bhttps?:\/\/\S+/gi,
  },
  // IPv4 address with per-octet 0-255 validation (so "1.2.3" version strings
  // do not match — they have only three octets anyway).
  {
    classification: "pii",
    name: "ip_address",
    regex:
      /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  },
  // ICD-10 diagnosis code ("E11.9"): a letter, two digits, a decimal, and 1-2
  // more chars. The required decimal keeps it off plain letter+number tokens.
  {
    classification: "phi",
    name: "icd10",
    regex: /\b[A-Z]\d{2}\.\d{1,2}\b/g,
  },
  // Context-tagged identifier: an alphanumeric code (with ≥1 digit, ≥5 chars)
  // immediately following a labeling keyword. Covers health-plan beneficiary,
  // account, license/certificate, and device-serial numbers in one pass while
  // the keyword context prevents matching unrelated numbers. The separator
  // between keyword and value accepts JSON (`"account":"..."`) and logfmt
  // (`account=...`) forms in addition to prose ("account 884201337"); the
  // required digit in the value keeps it off keyword=word flags ("account=ok").
  {
    classification: "phi",
    name: "labeled_identifier",
    regex:
      /(?<=\b(?:account|licen[sc]e|beneficiary|subscriber|certificate|serial)["']?\s*(?:(?:number|num|no\.?|id)["']?\s*)?[:=#]?\s*["']?)(?=[A-Za-z0-9-]*\d)[A-Za-z0-9][A-Za-z0-9-]{3,}[A-Za-z0-9]\b/gi,
  },

  // ---------------------------------------------------------------------------
  // Secrets coverage gaps (detector-secrets recall 0.56 → ~1.0).
  // ---------------------------------------------------------------------------

  // GitHub personal access / app tokens (ghp_, gho_, ghu_, ghs_, ghr_).
  {
    classification: "secrets",
    name: "github_pat",
    regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
  },
  // Google API key.
  {
    classification: "secrets",
    name: "google_api_key",
    regex: /\bAIza[A-Za-z0-9_-]{20,}\b/g,
  },
  // PEM private-key header (matches the BEGIN marker; redaction masks it).
  {
    classification: "secrets",
    name: "private_key_pem",
    regex: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----/g,
  },
  // Generic password assignment ("password=...", "pwd: ..."). Lookbehind keeps
  // the masked span to the value only.
  {
    classification: "secrets",
    name: "generic_password",
    regex: /(?<=\b(?:password|passwd|pwd)\s*[=:]\s*)\S+/gi,
  },
  // Slack token (xoxb/xoxp/xoxa/xoxr/xoxs/xapp). Matched explicitly as a
  // secret so it is not merely caught incidentally by the numeric `phone`
  // detector (which would misclassify it as PII and only mask part of it).
  {
    classification: "secrets",
    name: "slack_token",
    regex: /\b(?:xox[baprs]|xapp)-[A-Za-z0-9-]{10,}\b/g,
  },
  // Database connection-URL password ("scheme://user:PASSWORD@host"). Captures
  // the credential between the user colon and the `@` so it is classified as a
  // secret rather than being swept up only by the `email` detector.
  {
    classification: "secrets",
    name: "db_url_password",
    regex: /(?<=:\/\/[^/\s:@]+:)[^/\s:@]+(?=@)/g,
  },

  // --- M13.1: date of birth (non-slash). The `date` detector above is
  // slash-only by design so it never fires on the ISO timestamps that saturate
  // ops logs. Birth dates appear as ISO (`1981-03-14`), dash-MDY, or textual
  // ("March 14, 1981") forms; this detector catches those ONLY when anchored to
  // a birth-context keyword, so `ts=2025-02-01` / `timestamp:` stay unmatched.
  {
    classification: "phi",
    name: "dob_date",
    regex:
      /(?<=\b(?:dob|d\.o\.b\.?|date of birth|birth\s*date|birthday|born)["']?\s*[:=]?\s*["']?)(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{4}|(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t)?(?:ember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?\s+\d{1,2}(?:st|nd|rd|th)?,?\s+\d{4}|\d{1,2}(?:st|nd|rd|th)?\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:t)?(?:ember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\.?,?\s+\d{4})/gi,
  },

  // --- M13.2: remaining HIPAA Safe Harbor identifiers.
  // IPv6 (the ip_address detector above is IPv4-only). Matches the full
  // 8-group form and the `::`-compressed forms; the per-alternative group
  // counts keep it off ordinary `host:port` / `file.js:line:col` colon noise.
  {
    classification: "pii",
    // Boundaries are negative lookarounds (no adjacent hex/colon), NOT `\b`:
    // ordered alternation with `\b` lets the `::`-trailing alt win early (e.g.
    // matching only `fe80::`). Forbidding a hex/colon char on either side forces
    // the engine to backtrack to the alternative that consumes the full address.
    name: "ipv6",
    regex:
      /(?<![0-9A-Fa-f:])(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,5}(?::[0-9A-Fa-f]{1,4}){1,2}|(?:[0-9A-Fa-f]{1,4}:){1,4}(?::[0-9A-Fa-f]{1,4}){1,3}|(?:[0-9A-Fa-f]{1,4}:){1,3}(?::[0-9A-Fa-f]{1,4}){1,4}|(?:[0-9A-Fa-f]{1,4}:){1,2}(?::[0-9A-Fa-f]{1,4}){1,5}|[0-9A-Fa-f]{1,4}:(?::[0-9A-Fa-f]{1,4}){1,6})(?![0-9A-Fa-f:])/g,
  },
  // License plate — open-format, so context-anchored on `plate`/`license plate`
  // and required to carry at least one digit to stay off plain words.
  {
    classification: "phi",
    name: "license_plate",
    regex:
      /(?<=\b(?:license[\s_]?plate|plate)["']?\s*(?:number|no\.?|#)?["']?\s*[:=#]?\s*["']?)(?=[A-Z0-9-]*\d)[A-Z0-9](?:[A-Z0-9-]{3,7})\b/gi,
  },
  // Passport number — context-anchored on `passport`; 6–9 alphanumerics with at
  // least one digit.
  {
    classification: "phi",
    name: "passport",
    regex:
      /(?<=\bpassport["']?\s*(?:number|no\.?|#|id)?["']?\s*[:=#]?\s*["']?)(?=[A-Z0-9]*\d)[A-Z0-9]{6,9}\b/gi,
  },
  // DEA registration number — two letters + seven digits with a checksum (see
  // deaValid). NPI is recalled incidentally by the 10-digit phone detector;
  // DEA was not covered at all. Context-anchored on a `dea` keyword AND
  // checksum-gated: the bare two-letter+7-digit shape collides with ordinary
  // enterprise IDs (order/employee numbers) and ~10% of those pass the checksum
  // by chance, so anchoring is required to hold zero benign false positives.
  {
    classification: "phi",
    name: "dea",
    regex:
      /(?<=\bdea(?:[\s_]?(?:registration|number|reg|no\.?|#|id))?["']?\s*[:=#]?\s*["']?)[A-Za-z][A-Za-z9]\d{7}\b/gi,
    validate: deaValid,
  },

  // --- M13.4: additional secret classes (prefix- or context-anchored).
  // AWS secret access key — the 40-char secret (only the access-key ID was
  // covered before). Context-anchored: a bare 40-char base64 blob is too common
  // to flag on shape alone.
  {
    classification: "secrets",
    name: "aws_secret_key",
    regex:
      /(?<=\b(?:aws_secret_access_key|secret_access_key|aws[._]?secret[._]?(?:access[._]?)?key)["']?\s*[:=]\s*["']?)[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/gi,
  },
  // Stripe live/test keys (secret, restricted, publishable).
  {
    classification: "secrets",
    name: "stripe_key",
    regex: /\b[srp]k_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
  },
  // Twilio Account SID / API key SID — fixed "AC"/"SK" prefix + 32 hex.
  {
    classification: "secrets",
    name: "twilio_sid",
    regex: /\b(?:AC|SK)[0-9a-fA-F]{32}\b/g,
  },
  // SendGrid API key — `SG.<22+>.<22+>`.
  {
    classification: "secrets",
    name: "sendgrid_key",
    regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
  },
  // OpenAI / Anthropic API keys. The structured `sk-proj-…` / `sk-ant-…`
  // prefixes are distinctive enough to match on shape; a *bare* `sk-…` is only
  // flagged when it is a long all-alphanumeric blob (≥40, OpenAI legacy length)
  // so kebab-case service labels like `sk-prod-us-east-webhook` don't trip it.
  {
    classification: "secrets",
    name: "llm_api_key",
    regex: /\b(?:sk-(?:proj|ant)[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{40,})\b/g,
  },
  // npm automation/access token — `npm_` + 36 chars.
  {
    classification: "secrets",
    name: "npm_token",
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
  },
  // HashiCorp Vault service token — `hvs.<opaque>`.
  {
    classification: "secrets",
    name: "vault_token",
    regex: /\bhvs\.[A-Za-z0-9_-]{20,}\b/g,
  },
  // Azure storage account key — context-anchored `AccountKey=<86 base64>==`.
  // (GCP service-account JSON private keys are already covered by the
  // private_key_pem detector, which matches the PEM the key field contains.)
  {
    classification: "secrets",
    name: "azure_storage_key",
    regex: /(?<=AccountKey=)[A-Za-z0-9/+]{86}==/g,
  },

  // --- M13.5: generic high-entropy secret (last-resort). Custom scanner so it
  // can apply the entropy threshold on top of the key-context match.
  {
    classification: "secrets",
    name: "high_entropy_secret",
    scan: scanHighEntropySecret,
  },
];

export function scanForPhi(text: string): PhiHit[] {
  const hits: PhiHit[] = [];
  for (const det of DETECTORS) {
    // Custom scanner (dictionary / multi-token detectors).
    if (det.scan) {
      for (const s of det.scan(text)) {
        hits.push({
          classification: det.classification,
          detector: det.name,
          start: s.start,
          end: s.end,
          match: s.match,
        });
      }
      continue;
    }
    if (!det.regex) continue;
    det.regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = det.regex.exec(text)) !== null) {
      // Optional checksum / predicate gate (e.g. Luhn on card numbers).
      if (!det.validate || det.validate(m[0])) {
        hits.push({
          classification: det.classification,
          detector: det.name,
          start: m.index,
          end: m.index + m[0].length,
          match: m[0],
        });
      }
      // Safety against zero-width matches:
      if (m.index === det.regex.lastIndex) det.regex.lastIndex++;
    }
  }
  return hits;
}

// Stage-2 augmentation: merge optional NER spans into the deterministic
// Stage-1 hits. An NER span fully covered by a Stage-1 span is dropped (the
// regex/dictionary detector already masks those bytes); partial/disjoint spans
// are kept. `redactInline` is robust to any residual overlap. The sync
// `scanForPhi` (Stage-1) is unchanged and still drives the offline eval gate;
// this async wrapper is only used on the live ingest path when a provider is
// configured (see ner-config.ts).
export function mergePhiHits(base: PhiHit[], extra: PhiHit[]): PhiHit[] {
  if (extra.length === 0) return base;
  const merged = [...base];
  for (const e of extra) {
    if (e.end <= e.start) continue;
    const covered = base.some((b) => e.start >= b.start && e.end <= b.end);
    if (!covered) merged.push(e);
  }
  return merged;
}

/** Stage-1 (`scanForPhi`) ∪ optional Stage-2 NER spans. When `ner` is
 *  undefined/null the result is exactly `scanForPhi(text)` — so the default
 *  ingest path and the eval gate are unaffected. */
export async function scanForPhiWithNer(
  text: string,
  ner?: NerProvider | null,
): Promise<PhiHit[]> {
  const base = scanForPhi(text);
  if (!ner) return base;
  const nerHits = await ner.detect(text);
  return mergePhiHits(base, nerHits);
}

// M3: inline redaction helper used by the ingest pipeline to produce the
// `redacted_evidence` snippet that lands in the searchable hot tier. The
// strategy is "mask" per ARCHITECTURE.md §6 (tokenize-via-KMS is post-M3).
//
// Overlap handling: hits are sorted by start ascending, then by end
// descending so the longer span wins on tie. Any later hit whose start
// falls inside an already-redacted span is skipped — the earlier span's
// `[REDACTED:<detector>]` placeholder already covers the bytes.
//
// Returns the redacted text plus the ordered list of detector names that
// were actually applied (skipped overlapping hits are NOT counted).
export function redactInline(
  text: string,
  hits: PhiHit[],
): { snippet: string; redactions: string[] } {
  if (hits.length === 0) return { snippet: text, redactions: [] };
  const sorted = [...hits].sort(
    (a, b) => a.start - b.start || b.end - a.end,
  );
  const out: string[] = [];
  const redactions: string[] = [];
  let cursor = 0;
  for (const h of sorted) {
    if (h.end <= h.start) continue; // zero/negative-width hit — nothing to mask
    if (h.start < cursor) continue; // overlap — earlier (longer) span covers it
    out.push(text.slice(cursor, h.start));
    out.push(`[REDACTED:${h.detector}]`);
    redactions.push(h.detector);
    cursor = h.end;
  }
  out.push(text.slice(cursor));
  return { snippet: out.join(""), redactions };
}

export const SAFE_REFUSAL =
  "I can't share that. The response I was about to send contained " +
  "values that look like PHI/secrets. The attempt has been logged as a " +
  "finding about my own output. Please rephrase or use the break-glass " +
  "raw-evidence view if you have authorization.";
