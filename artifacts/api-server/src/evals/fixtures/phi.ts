// Labeled PHI/PII fixtures spanning the HIPAA Safe Harbor identifier classes
// (45 CFR §164.514(b)(2)). Each labeled span names the identifier class and the
// exact substring that constitutes PHI, so the detector eval can compute
// per-class recall.
//
// IMPORTANT: these are SYNTHETIC values. No real PHI is permitted in dev
// (threat_model "Dev ↔ Production"). Names/numbers are invented; SSNs use the
// SSA-invalid / example ranges where possible.
//
// Two cohorts:
//   1. CLEAN fixtures (`shape: "clean"`): short, single-sentence lines — the
//      original M11 corpus, useful as a readable smoke set.
//   2. PRODUCTION-SHAPED fixtures (`shape: json|kv|stacktrace|prose`): realistic
//      messy cloud-log lines — JSON envelopes, key=value pairs, stack traces,
//      and multi-identifier prose. Real logs embed identifiers inside structured
//      wrappers; a corpus of only clean single-sentence lines over-states the
//      detector's true precision/recall. This cohort exists to surface the
//      accuracy gaps the tiny clean set hides (see detector-phi.eval.ts).
//
// Per-span identifier labels (rather than one class per fixture) let a single
// messy line carry several distinct PHI classes and still attribute each span
// to the right class in the eval's per-class recall accounting.

/** Shape of the surrounding log line a span is embedded in. */
export type LogShape = "clean" | "json" | "kv" | "stacktrace" | "prose";

/** A single labeled PHI/PII span: the substring plus its Safe Harbor class. */
export interface PhiSpan {
  /** Substring that is PHI/PII in the fixture text. Must be unique in `text`. */
  sub: string;
  /** HIPAA Safe Harbor identifier class this span exercises. */
  identifier: string;
  /**
   * Set when the detector is KNOWN to miss this span by design and the miss is
   * an accepted trade-off (recorded, not fixed). Lets the eval report the gap
   * honestly without it reading as an unexplained regression.
   */
  knownGap?: string;
}

export interface PhiFixture {
  id: string;
  shape: LogShape;
  text: string;
  phi: PhiSpan[];
}

export const PHI_FIXTURES: PhiFixture[] = [
  // ---------------------------------------------------------------------------
  // CLEAN cohort — short single-sentence lines (original M11 corpus).
  // ---------------------------------------------------------------------------
  {
    id: "name-1",
    shape: "clean",
    text: "Patient Jonathan Q Smithfield was admitted Tuesday.",
    phi: [{ sub: "Jonathan Q Smithfield", identifier: "name" }],
  },
  {
    // Lowercase full name — misses the capitalized "First Last" heuristic, so
    // only the dictionary signal can recall it.
    id: "name-2",
    shape: "clean",
    text: "Reviewer maria gonzalez signed off on the chart.",
    phi: [{ sub: "maria gonzalez", identifier: "name" }],
  },
  {
    // Single surname after a title — recalled via the title + dictionary pass.
    id: "name-3",
    shape: "clean",
    text: "Attending physician Dr. Patel reviewed the labs.",
    phi: [{ sub: "Patel", identifier: "name" }],
  },
  // ---------------------------------------------------------------------------
  // Diverse / non-Western names. These exercise the multicultural gazetteer +
  // the title/context single-name passes (recall on names the capitalized
  // "First Last" casing heuristic misses: lowercase names, single non-Western
  // surnames after a title, and single-token names with strong context).
  // ---------------------------------------------------------------------------
  {
    // Lowercase South Asian full name — casing heuristic misses; dictionary
    // adjacent-pair pass recalls it.
    id: "name-4",
    shape: "clean",
    text: "Reviewer aarav sharma approved the order.",
    phi: [{ sub: "aarav sharma", identifier: "name" }],
  },
  {
    // Lowercase East Asian full name — dictionary adjacent-pair pass.
    id: "name-5",
    shape: "clean",
    text: "Nurse mei chen recorded the vitals.",
    phi: [{ sub: "mei chen", identifier: "name" }],
  },
  {
    // Single non-Western (African) surname after a title — title pass.
    id: "name-6",
    shape: "clean",
    text: "Consult signed by Dr. Okonkwo overnight.",
    phi: [{ sub: "Okonkwo", identifier: "name" }],
  },
  {
    // Single Arabic name after a title — title pass.
    id: "name-7",
    shape: "clean",
    text: "Follow-up assigned to Dr. Hassan today.",
    phi: [{ sub: "Hassan", identifier: "name" }],
  },
  {
    // Single-token African name with a lowercase context keyword — the casing
    // heuristic needs two capitalized tokens, so only the context pass recalls.
    id: "name-8",
    shape: "clean",
    text: "Lab results for patient Ngozi were filed.",
    phi: [{ sub: "Ngozi", identifier: "name" }],
  },
  {
    // Lowercase Slavic full name — dictionary adjacent-pair pass.
    id: "name-9",
    shape: "clean",
    text: "Auditor dmitri volkov closed the case.",
    phi: [{ sub: "dmitri volkov", identifier: "name" }],
  },
  // ---------------------------------------------------------------------------
  // M13.3 (partial) — context-anchored word-collision surnames. These collide
  // with ordinary English words ("Sun", "Li", "Park") and are deliberately kept
  // out of the gazetteer, so they are recalled ONLY when a person-context
  // keyword anchors them, the token is Capitalized, and the separator is not a
  // sentence-ending period. The bare un-anchored case still needs NER (deferred,
  // see COLLISION_SURNAMES in redact.ts). The benign-collision-* controls below
  // prove these conditions hold precision on ordinary operational text.
  {
    // Context keyword + collision surname ("Sun"). The casing pass needs a
    // middle initial for the context shape, and "sun" is not a dictionary name,
    // so only the M13.3 collision pass recalls it.
    id: "name-10",
    shape: "clean",
    text: "Lab results for patient Sun were filed overnight.",
    phi: [{ sub: "Sun", identifier: "name" }],
  },
  {
    // Context keyword + two-letter collision surname ("Li").
    id: "name-11",
    shape: "clean",
    text: "Follow-up assigned to member Li this morning.",
    phi: [{ sub: "Li", identifier: "name" }],
  },
  {
    // Colon separator after the context keyword ("enrollee: Park").
    id: "name-12",
    shape: "clean",
    text: "Questionnaire returned by enrollee: Park before noon.",
    phi: [{ sub: "Park", identifier: "name" }],
  },
  {
    id: "address-1",
    shape: "clean",
    text: "Member resides at 4471 Maplewood Avenue, Apt 12.",
    phi: [{ sub: "4471 Maplewood Avenue", identifier: "geo_address" }],
  },
  {
    id: "zip-1",
    shape: "clean",
    text: "Service location Springfield, IL 62704 reported.",
    phi: [{ sub: "62704", identifier: "geo_zip" }],
  },
  {
    id: "date-1",
    shape: "clean",
    text: "DOB 03/14/1981 with admit date 2025-02-01 noted.",
    phi: [{ sub: "03/14/1981", identifier: "date" }],
  },
  {
    id: "phone-1",
    shape: "clean",
    text: "Callback number on file is 415-555-1212 for the member.",
    phi: [{ sub: "415-555-1212", identifier: "phone" }],
  },
  {
    id: "fax-1",
    shape: "clean",
    text: "Records faxed to provider line 212-555-0199 overnight.",
    phi: [{ sub: "212-555-0199", identifier: "fax" }],
  },
  {
    id: "email-1",
    shape: "clean",
    text: "Notification sent to jane.doe@examplehealth.org earlier.",
    phi: [{ sub: "jane.doe@examplehealth.org", identifier: "email" }],
  },
  {
    id: "ssn-1",
    shape: "clean",
    text: "Applicant ssn 123-45-6789 verified against records.",
    phi: [{ sub: "123-45-6789", identifier: "ssn" }],
  },
  {
    id: "mrn-1",
    shape: "clean",
    text: "Chart pulled for MRN: 4456789 in the EHR.",
    phi: [{ sub: "MRN: 4456789", identifier: "medical_record_number" }],
  },
  {
    id: "beneficiary-1",
    shape: "clean",
    text: "Health plan beneficiary id HPB-99887766 on the claim.",
    phi: [{ sub: "HPB-99887766", identifier: "health_plan_beneficiary" }],
  },
  {
    id: "account-1",
    shape: "clean",
    text: "Billing account 884201337 flagged for review.",
    phi: [{ sub: "884201337", identifier: "account_number" }],
  },
  {
    id: "license-1",
    shape: "clean",
    text: "Provider license number D1234567 on the order.",
    phi: [{ sub: "D1234567", identifier: "certificate_license_number" }],
  },
  {
    id: "vin-1",
    shape: "clean",
    text: "Transport vehicle VIN 1HGCM82633A004352 logged.",
    phi: [{ sub: "1HGCM82633A004352", identifier: "vehicle_identifier" }],
  },
  {
    id: "device-1",
    shape: "clean",
    text: "Infusion pump device serial SNX-AB123456 paired.",
    phi: [{ sub: "SNX-AB123456", identifier: "device_identifier" }],
  },
  {
    id: "url-1",
    shape: "clean",
    text: "Portal link https://portal.examplehealth.org/patient/9981 shared.",
    phi: [
      {
        sub: "https://portal.examplehealth.org/patient/9981",
        identifier: "url",
      },
    ],
  },
  {
    // Member-identifying URL in a logfmt access line: the `member_id` query
    // param is the signal; the URL is flagged even though the host is benign.
    id: "url-2",
    shape: "kv",
    text: "audit access url=https://portal.examplehealth.org/eligibility?member_id=998877 actor=svc",
    phi: [
      {
        sub: "https://portal.examplehealth.org/eligibility?member_id=998877",
        identifier: "url",
      },
    ],
  },
  {
    // MRN query param inside a JSON event — patient-identifying URL.
    id: "url-3",
    shape: "json",
    text: '{"event":"chart_open","link":"https://portal.examplehealth.org/v1/records?mrn=A1234567"}',
    phi: [
      {
        sub: "https://portal.examplehealth.org/v1/records?mrn=A1234567",
        identifier: "url",
      },
    ],
  },
  {
    id: "ip-1",
    shape: "clean",
    text: "Session originated from 192.168.10.24 inside the VPN.",
    phi: [{ sub: "192.168.10.24", identifier: "ip_address" }],
  },
  {
    id: "creditcard-1",
    shape: "clean",
    text: "Copay charged to card 4111 1111 1111 1111 today.",
    phi: [{ sub: "4111 1111 1111 1111", identifier: "account_number_card" }],
  },
  {
    // Dash-grouped card number — must still pass Luhn and be recalled.
    id: "creditcard-2",
    shape: "clean",
    text: "Refund issued to card 5500-0000-0000-0004 by billing.",
    phi: [{ sub: "5500-0000-0000-0004", identifier: "account_number_card" }],
  },
  {
    id: "npi-1",
    shape: "clean",
    text: "Rendering provider NPI 1234567893 attached.",
    phi: [{ sub: "1234567893", identifier: "other_unique_id_npi" }],
  },
  {
    id: "icd-1",
    shape: "clean",
    text: "Encounter diagnosis dx E11.9 captured by sync.",
    phi: [{ sub: "E11.9", identifier: "other_unique_id_diagnosis" }],
  },

  // ---------------------------------------------------------------------------
  // PRODUCTION-SHAPED cohort — JSON envelopes.
  // ---------------------------------------------------------------------------
  {
    // Structured error log with PHI nested in fields. SSN/email inside quotes
    // must still be recalled; the ISO `ts` must NOT be flagged as a date.
    id: "json-1",
    shape: "json",
    text: '{"level":"error","ts":"2025-02-01T12:00:00Z","msg":"claim sync failed","ssn":"123-45-6789","email":"jane.doe@examplehealth.org"}',
    phi: [
      { sub: "123-45-6789", identifier: "ssn" },
      { sub: "jane.doe@examplehealth.org", identifier: "email" },
    ],
  },
  {
    // MRN + phone nested in a member object. `"mrn":"..."` needs the detector to
    // accept JSON quote/colon separators, not just "MRN: ".
    id: "json-2",
    shape: "json",
    text: '{"member":{"mrn":"4456789","phone":"415-555-1212"},"action":"lookup"}',
    phi: [
      { sub: "4456789", identifier: "medical_record_number" },
      { sub: "415-555-1212", identifier: "phone" },
    ],
  },
  {
    // Payment event: card number (with spaces, inside quotes) + client IP. The
    // numeric `"amount":42` must not be mistaken for an identifier.
    id: "json-3",
    shape: "json",
    text: '{"event":"payment","card":"4111 1111 1111 1111","client_ip":"192.168.10.24","amount":42}',
    phi: [
      { sub: "4111 1111 1111 1111", identifier: "account_number_card" },
      { sub: "192.168.10.24", identifier: "ip_address" },
    ],
  },
  {
    // Name with middle initial + account number + slash-date DOB, all in JSON.
    // The account number needs JSON-separator support in the labeled-id detector.
    id: "json-4",
    shape: "json",
    text: '{"patient":"Jonathan Q Smithfield","account":"884201337","dob":"03/14/1981"}',
    phi: [
      { sub: "Jonathan Q Smithfield", identifier: "name" },
      { sub: "884201337", identifier: "account_number" },
      { sub: "03/14/1981", identifier: "date" },
    ],
  },
  {
    // ICD-10 + 10-digit NPI in JSON. NPI is recalled incidentally via the phone
    // detector (any 10-digit run); the eval credits the span by overlap.
    id: "json-5",
    shape: "json",
    text: '{"encounter":"E11.9","provider_npi":"1234567893","status":"closed"}',
    phi: [
      { sub: "E11.9", identifier: "other_unique_id_diagnosis" },
      { sub: "1234567893", identifier: "other_unique_id_npi" },
    ],
  },
  {
    // ISO-8601 date in a `dob` field. Caught by the M13.1 dob_date detector,
    // which fires on ISO/textual dates only when birth-context-anchored, so the
    // ISO `ts=` timestamps that saturate ops logs (benign-kv-1) stay unmatched.
    id: "json-6",
    shape: "json",
    text: '{"member_id":"M-2231","dob":"1981-03-14","plan":"gold"}',
    phi: [{ sub: "1981-03-14", identifier: "date_of_birth" }],
  },
  {
    // Textual DOB in prose, birth-context anchored.
    id: "dob-1",
    shape: "clean",
    text: "Patient date of birth March 14, 1981 confirmed at intake.",
    phi: [{ sub: "March 14, 1981", identifier: "date_of_birth" }],
  },
  {
    // logfmt dash-MDY DOB.
    id: "dob-2",
    shape: "kv",
    text: "enrollment member=M-77 dob=03-14-1981 plan=silver",
    phi: [{ sub: "03-14-1981", identifier: "date_of_birth" }],
  },
  {
    // IPv6 (full 8-group form). The ip_address detector is IPv4-only.
    id: "ipv6-1",
    shape: "kv",
    text: "session client_ip=2001:0db8:85a3:0000:0000:8a2e:0370:7334 established",
    phi: [
      { sub: "2001:0db8:85a3:0000:0000:8a2e:0370:7334", identifier: "ip_address" },
    ],
  },
  {
    // IPv6 (`::`-compressed form).
    id: "ipv6-2",
    shape: "clean",
    text: "Connection from fe80::1ff:fe23:4567:890a was logged.",
    phi: [{ sub: "fe80::1ff:fe23:4567:890a", identifier: "ip_address" }],
  },
  {
    // License plate, context-anchored.
    id: "plate-1",
    shape: "clean",
    text: "Vehicle on file has license plate 7XYZ123 per the report.",
    phi: [{ sub: "7XYZ123", identifier: "license_plate" }],
  },
  {
    // Passport number, context-anchored.
    id: "passport-1",
    shape: "kv",
    text: "traveler record passport=X1234567 country=US verified",
    phi: [{ sub: "X1234567", identifier: "passport_number" }],
  },
  {
    // DEA registration number — checksum-valid (AB1234563).
    id: "dea-1",
    shape: "clean",
    text: "Prescriber DEA AB1234563 authorized the refill.",
    phi: [{ sub: "AB1234563", identifier: "dea_number" }],
  },

  // ---------------------------------------------------------------------------
  // PRODUCTION-SHAPED cohort — key=value (logfmt) lines.
  // ---------------------------------------------------------------------------
  {
    // logfmt line: ISO `ts=` (must not flag) alongside ssn=, slash dob=, email=.
    id: "kv-1",
    shape: "kv",
    text: "ts=2025-02-01 level=info caller=member-svc ssn=123-45-6789 dob=03/14/1981 email=jane.doe@examplehealth.org",
    phi: [
      { sub: "123-45-6789", identifier: "ssn" },
      { sub: "03/14/1981", identifier: "date" },
      { sub: "jane.doe@examplehealth.org", identifier: "email" },
    ],
  },
  {
    // logfmt with account= and mrn= — both need `=` accepted as a separator.
    id: "kv-2",
    shape: "kv",
    text: "audit user=svc-billing action=lookup account=884201337 mrn=4456789 result=ok",
    phi: [
      { sub: "884201337", identifier: "account_number" },
      { sub: "4456789", identifier: "medical_record_number" },
    ],
  },

  // ---------------------------------------------------------------------------
  // PRODUCTION-SHAPED cohort — stack traces.
  // ---------------------------------------------------------------------------
  {
    // PHI leaked into an exception message. The Java frame (file:line, package
    // path, CamelCase class) must NOT produce any false positives.
    id: "stacktrace-1",
    shape: "stacktrace",
    text: "java.lang.RuntimeException: failed to persist patient record ssn=123-45-6789 at com.examplehealth.billing.MemberRepo.save(MemberRepo.java:142)",
    phi: [{ sub: "123-45-6789", identifier: "ssn" }],
  },

  // ---------------------------------------------------------------------------
  // PRODUCTION-SHAPED cohort — multi-identifier prose.
  // ---------------------------------------------------------------------------
  {
    // Long prose line mixing a name, address, phone and portal URL.
    id: "prose-1",
    shape: "prose",
    text: "During the afternoon review the analyst confirmed member maria gonzalez updated her file; new mailing address 4471 Maplewood Avenue, Apt 12, callback 212-555-0199, portal https://portal.examplehealth.org/patient/9981 for follow-up.",
    phi: [
      { sub: "maria gonzalez", identifier: "name" },
      { sub: "4471 Maplewood Avenue", identifier: "geo_address" },
      { sub: "212-555-0199", identifier: "phone" },
      {
        sub: "https://portal.examplehealth.org/patient/9981",
        identifier: "url",
      },
    ],
  },
  {
    // Dense single line with five distinct identifier classes back to back.
    id: "prose-2",
    shape: "prose",
    text: "Patient Jonathan Q Smithfield (MRN: 4456789) — SSN 123-45-6789, ph 415-555-1212, mail jane.doe@examplehealth.org for the appeal.",
    phi: [
      { sub: "Jonathan Q Smithfield", identifier: "name" },
      { sub: "MRN: 4456789", identifier: "medical_record_number" },
      { sub: "123-45-6789", identifier: "ssn" },
      { sub: "415-555-1212", identifier: "phone" },
      { sub: "jane.doe@examplehealth.org", identifier: "email" },
    ],
  },
];

// Benign lines that should produce ZERO detector hits. Used to measure
// detector precision / false-positive rate against realistic operational log
// text that looks numeric/structured but contains no PHI.
export const BENIGN_FIXTURES: { id: string; shape: LogShape; text: string }[] = [
  { id: "benign-1", shape: "clean", text: "There are 3 critical findings open today." },
  { id: "benign-2", shape: "clean", text: "Log group app-billing has no KMS key configured." },
  { id: "benign-3", shape: "clean", text: "Deployment succeeded in region us-east-1 at 12:00." },
  { id: "benign-4", shape: "clean", text: "Retention policy set to 90 days for 5 log groups." },
  { id: "benign-5", shape: "clean", text: "Order 12345 shipped to warehouse 7 this morning." },
  { id: "benign-6", shape: "clean", text: "Version 1.2.3 released; build 4567 passed CI." },
  { id: "benign-7", shape: "clean", text: "CPU at 75% and memory at 60% over 30 minutes." },
  { id: "benign-8", shape: "clean", text: "Queue depth 42 with 8 active consumer workers." },
  // 16-digit request/trace id — looks card-shaped but fails Luhn, so the
  // card detector must NOT flag it.
  { id: "benign-9", shape: "clean", text: "Request id 9921830477112345 logged for trace." },
  // 16-digit order number that fails Luhn — also must not be flagged.
  { id: "benign-10", shape: "clean", text: "Order number 1234567890123456 was reconciled." },

  // Capitalized product/service-name compounds — these read like proper nouns
  // but are ordinary infrastructure components, the main false-positive trap
  // for a naive capitalized-word-pair name detector.
  { id: "benign-11", shape: "clean", text: "Lambda Function billing-processor timed out after 30s." },
  { id: "benign-12", shape: "clean", text: "Load Balancer health check failed for target group web-tier." },
  { id: "benign-13", shape: "clean", text: "Auto Scaling group web-tier scaled out to 5 instances." },
  { id: "benign-14", shape: "clean", text: "Circuit Breaker opened for the downstream Payment Service." },
  { id: "benign-15", shape: "clean", text: "Dead Letter Queue depth reached 128 messages." },
  { id: "benign-16", shape: "clean", text: "Elastic Beanstalk environment Production was updated." },
  { id: "benign-17", shape: "clean", text: "Secret Manager rotation completed for database credentials." },

  // Two-word proper-noun-like phrases in prose, incl. error strings.
  { id: "benign-18", shape: "clean", text: "Access Denied when calling the GetObject operation on bucket logs." },
  { id: "benign-19", shape: "clean", text: "Request a1b2c3 returned 500 Internal Server Error." },
  { id: "benign-20", shape: "clean", text: "Health Check passed for region us-west-2 across all nodes." },

  // Person-record keyword followed by an ordinary capitalized compound (no
  // middle initial) — must NOT be read as a personal name.
  { id: "benign-21", shape: "clean", text: "Patient Portal Settings synced across all regions." },
  { id: "benign-22", shape: "clean", text: "Member Service Account Manager restarted cleanly." },

  // Single-letter-middle technical phrases ("First X Last" shape) that are not
  // names: DNS record types, network classes, service tiers.
  { id: "benign-23", shape: "clean", text: "Type A Record updated for the internal DNS zone." },
  { id: "benign-24", shape: "clean", text: "Class C Network range assigned to the staging VPC." },

  // Numbered IDs and two-uppercase-letter labels followed by digits — the ZIP
  // trap ("ID 88421" is an identifier, not a Springfield postal code).
  { id: "benign-25", shape: "clean", text: "Cluster ID 88421 finished its rolling upgrade window." },
  { id: "benign-26", shape: "clean", text: "Pull Request 1234 merged into the main branch by CI." },

  // Version and region strings.
  { id: "benign-27", shape: "clean", text: "Deployed Version 2 of the API Gateway to us-east-2." },
  { id: "benign-28", shape: "clean", text: "Build 4567 promoted from staging to region eu-west-1." },

  // Number + street-suffix-like English word — not a street address because no
  // street name sits between the number and the suffix word.
  { id: "benign-29", shape: "clean", text: "3 Way handshake completed in 5 milliseconds." },
  { id: "benign-30", shape: "clean", text: "Scaled to 2 Way replication across availability zones." },
  { id: "benign-31", shape: "clean", text: "Allocated 12 Drive slots in the storage pool." },

  // Context keyword + non-name word — the single-name context pass must NOT
  // fire because the following token is not a dictionary name.
  { id: "benign-32", shape: "clean", text: "Patient portal maintenance completed at 02:00." },
  { id: "benign-33", shape: "clean", text: "Member services resolved 14 tickets today." },
  { id: "benign-34", shape: "clean", text: "Resident memory climbed to 92 percent overnight." },

  // Word-collision surname precision controls (M13.3 partial). The collision
  // pass must stay silent on ordinary operational prose where the collision word
  // is NOT a context-anchored, capitalized name.
  // Collision word as an ordinary lowercase word, no context keyword.
  { id: "benign-collision-1", shape: "clean", text: "The sun set over region us-west-2 at 18:00." },
  // Context keyword present, but the collision word is lowercase prose.
  { id: "benign-collision-2", shape: "clean", text: "Members park their idle sessions in the pool." },
  // Capitalized collision word after a context keyword but across a SENTENCE
  // boundary (period) — the no-period separator rule must keep this silent.
  { id: "benign-collision-3", shape: "clean", text: "Notified the patient. Sun exposure guidance was updated." },
  // Context keyword + a longer word that merely starts with a collision token
  // ("park" vs "parking") — token equality must hold, so this must not fire.
  { id: "benign-collision-4", shape: "clean", text: "Patient parking validation completed cleanly." },

  // ---------------------------------------------------------------------------
  // PRODUCTION-SHAPED benign controls — the harder precision traps that only
  // appear once logs are JSON/logfmt/stack-trace shaped.
  // ---------------------------------------------------------------------------

  // JSON envelope full of numeric/structured noise: status code, latency, a
  // 16-digit request id (fails Luhn), region. No PHI.
  {
    id: "benign-json-1",
    shape: "json",
    text: '{"level":"info","status":200,"latency_ms":42,"region":"us-east-1","request_id":"9921830477112345"}',
  },
  // JSON deploy event: semver (not a date), short build number, hex commit.
  {
    id: "benign-json-2",
    shape: "json",
    text: '{"event":"deploy","version":"1.2.3","build":4567,"commit":"a1b2c3d4"}',
  },
  // JSON with keyword-like fields whose values carry NO digits, so the
  // labeled-identifier detector (which requires a digit) must not fire.
  {
    id: "benign-json-3",
    shape: "json",
    text: '{"account":"disabled","subscriber":"none","serial":"PENDING"}',
  },
  // logfmt with an ISO timestamp, an account flag with no digits, and a
  // dash-grouped host token that is not a dotted IPv4.
  {
    id: "benign-kv-1",
    shape: "kv",
    text: "ts=2025-02-01T00:00:00Z level=warn account=disabled retries=3 host=ip-10-0-0-5",
  },
  // logfmt error line: an error code, counters, and a host:port endpoint with
  // no scheme (so the URL detector must not fire).
  {
    id: "benign-kv-2",
    shape: "kv",
    text: "level=error code=ECONNRESET attempt=2 max=5 backoff_ms=200 endpoint=internal.svc.local:8443",
  },
  // Java stack trace: file:line offsets, package path, CamelCase class names —
  // a dense false-positive trap for naive name/number detectors.
  {
    id: "benign-stacktrace-1",
    shape: "stacktrace",
    text: "java.lang.NullPointerException: cannot read field id at com.example.svc.OrderProcessor.handle(OrderProcessor.java:88)",
  },
  // Node stack trace with internal module frames and numeric offsets.
  {
    id: "benign-stacktrace-2",
    shape: "stacktrace",
    text: "TypeError: undefined is not a function at /app/dist/server.js:1024:17 at processTicksAndRejections (node:internal/process/task_queues.js:95:5)",
  },
  // Mixed metrics prose with a TitleCase phrase and account flag (no digits).
  {
    id: "benign-prose-1",
    shape: "prose",
    text: "Health Check passed: region=us-west-2 nodes=12 cpu=75% mem=60% account=service-mesh stable.",
  },

  // ---------------------------------------------------------------------------
  // Benign infrastructure URLs (M-URL precision controls). The URL detector now
  // suppresses plain infra URLs and fires only on patient/member-identifying
  // ones — these controls lock that in. None carries a PHI signal in its
  // path/query, so the suite must report ZERO hits across all of them.
  // ---------------------------------------------------------------------------

  // Service-to-service health check — path is /healthz, no identifying signal.
  {
    id: "benign-url-1",
    shape: "clean",
    text: "Health check GET https://billing-svc.internal:8080/healthz returned 200.",
  },
  // Asset CDN fetch — hashed static asset path, no signal.
  {
    id: "benign-url-2",
    shape: "clean",
    text: "Fetched asset https://assets.cdn.examplehealth.org/static/app.4f3a2b9c.js from edge.",
  },
  // The key host-vs-path trap: the HOST contains "patient" (a service name) but
  // the path (/livez) carries no identifying signal — must NOT be flagged.
  {
    id: "benign-url-3",
    shape: "kv",
    text: "upstream url=https://patient-records-svc.internal/livez status=ok latency=12ms",
  },
  // OAuth token endpoint — grant_type is not an identifying param.
  {
    id: "benign-url-4",
    shape: "clean",
    text: "Token endpoint https://auth.examplehealth.org/oauth2/token?grant_type=client_credentials reached.",
  },
  // Paginated list API in JSON — limit/cursor params carry no identity.
  {
    id: "benign-url-5",
    shape: "json",
    text: '{"msg":"page fetch","url":"https://api.examplehealth.org/v1/findings?limit=50&cursor=ab12cd"}',
  },
  // "remember_token" contains the substring "member" but is not preceded by a
  // query/path separator, so the member-id signal must NOT fire.
  {
    id: "benign-url-6",
    shape: "clean",
    text: "Webhook https://hooks.examplehealth.org/notify?remember_token=true&channel=ops delivered.",
  },
];

// ---------------------------------------------------------------------------
// NER (Stage-2) recall fixtures — DELIBERATELY SEPARATE from PHI_FIXTURES.
//
// These are the *un-anchored person names* the deterministic Stage-1 detectors
// (scanForPhi) cannot match without destroying precision: a single surname with
// no title/anchor ("Reyes finalized the discharge note"), or a name token that
// is ALSO a common English word ("Hope", "Grace", "Will", "Mark", "May",
// "Park") — the precision trap that blocks any regex-only fix, since flagging
// capitalized words would fire on sentence-initial common words.
//
// They live in their OWN export, never in PHI_FIXTURES, on purpose: folding them
// into the gated detector-phi corpus would create unexplained false negatives
// (they are not `knownGap` spans against a *deterministic* detector — they are
// the explicit reason the optional NER seam exists) and would regress the gated
// recall score. The measurement that consumes them (detector-ner.eval.ts) is
// OPT-IN (EVAL_NER=1) and never writes a baselined result, so the credential-
// free offline gate stays byte-identical. Verified misses: every `name` below
// returns no overlapping Stage-1 hit (see detector-ner.eval.ts, "stage-1 recall
// gap" leg). The benign precision-hold leg reuses BENIGN_FIXTURES, whose
// operational text contains none of these name tokens at a case-sensitive word
// boundary — so a real NER (and the deterministic fake that stands in for it
// offline) adds no false positives there.
// ---------------------------------------------------------------------------

/** A labeled un-anchored person name that Stage-1 misses and a Stage-2 NER
 *  provider is expected to recover. */
export interface NerNameFixture {
  id: string;
  text: string;
  /** The person-name substring. Must be unique in `text` and match at a
   *  case-sensitive word boundary (the fake provider matches whole words). */
  name: string;
  /** True when `name` is also a common English word — the precision trap that
   *  makes a precision-safe regex fix impossible (only a model has the context
   *  to disambiguate "Hope examined the chart" from "Hope this helps"). */
  wordCollision?: boolean;
}

export const NER_PHI_FIXTURES: NerNameFixture[] = [
  // Word-collision names: the token is also an ordinary English word.
  { id: "ner-name-1", text: "Park reviewed the chart before rounds.", name: "Park", wordCollision: true },
  { id: "ner-name-2", text: "Hope examined the results yesterday.", name: "Hope", wordCollision: true },
  { id: "ner-name-3", text: "Grace signed the consent form.", name: "Grace", wordCollision: true },
  { id: "ner-name-4", text: "Mark closed the incident at noon.", name: "Mark", wordCollision: true },
  { id: "ner-name-5", text: "May returned the labs to the ward.", name: "May", wordCollision: true },
  // Plain un-anchored surnames: no title, no "First Last" casing pair, so the
  // Stage-1 dictionary/context passes stay silent.
  { id: "ner-name-6", text: "The consult was completed by Reyes.", name: "Reyes" },
  { id: "ner-name-7", text: "Approval came from Cho late Friday.", name: "Cho" },
  { id: "ner-name-8", text: "Okafor approved the transfer overnight.", name: "Okafor" },
  { id: "ner-name-9", text: "Nguyen finalized the discharge note.", name: "Nguyen" },
];
