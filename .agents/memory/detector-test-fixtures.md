---
name: Detector test fixtures need valid SSNs
description: Why some SSN-shaped strings produce no finding in tests.
---

# Use VALID SSNs in detector/ingest test fixtures

The PHI detector follows SSA allocation rules, so SSN-shaped strings that are
never-allocated are correctly NOT flagged and produce NO finding.

Invalid (won't be detected): area number `000`, `666`, or `900`–`999`; group
`00`; serial `0000`. E.g. `666-66-6666` yields `findingsCreated: 0`.

**Why:** a test that ingests such a string and asserts a finding was created
(or that inline raw_evidence is present) fails with a confusing `expected 0 to
be 1` at the ingest step, not where the test intent lies.

**How to apply:** in ingest/tiering/redaction tests, pick a valid SSN like
`601-23-4567` / `321-54-9876` when you need a real PHI hit.
