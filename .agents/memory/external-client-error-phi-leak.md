---
name: External-client error messages can leak PHI to logs
description: Errors thrown from an external-service client must never include the response body — it can echo request-derived PHI into application logs.
---

# External-client error messages can leak PHI to logs

When a client for an external service (NER analyzer, search backend, object
store, LLM, etc.) throws on a non-OK response, the thrown `Error.message` MUST
carry only metadata (endpoint + HTTP status + a static reason) — **never the
response body text**.

**Why:** the service's error page can echo request-derived content, and in this
codebase the request payload is raw, possibly-PHI log text. These errors are
caught and logged with `logger.error({ err })` (e.g. the ingest detection path),
so echoing the body writes PHI to application logs — a direct violation of
threat_model §Information Disclosure ("PHI MUST NOT appear in application
logs"). An architect review caught exactly this in the Presidio NER client.

**How to apply:** any new external-service client in `artifacts/api-server`
(provider behind a seam: NER, search, raw-evidence, LLM, channel adapter) — when
building a thrown/logged error, include status/code only; do not call
`res.text()`/`res.json()` to enrich the message. Prefer not even reading the
body. Cover it with a regression test that feeds a PHI-bearing fake error body
and asserts the thrown message excludes it (see the Presidio test in
`ner.test.ts`).
