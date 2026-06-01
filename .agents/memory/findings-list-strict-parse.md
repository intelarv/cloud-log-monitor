---
name: Findings list strict parse
description: Why the dashboard findings list can 500 on a single malformed finding row
---
`artifacts/api-server/src/routes/findings.ts` GET /findings does `rows.map(toApi).map(r => FindingSchema.parse(r))`. The zod parse is strict and all-or-nothing: a single finding whose `redacted_evidence` lacks a required field (notably `truncated`) throws and fails the *entire* list response with a 500, so the dashboard findings page shows nothing.

**Why:** seed findings always set `truncated: false`, but the ingest/replay path can produce rows without it, so the bug only surfaces in dev DBs that have replayed fixtures, not from a fresh seed.

**How to apply:** if the findings page is blank/erroring in dev, check the api-server log for a ZodError on `redacted_evidence.truncated` before assuming a UI bug. Real fix belongs in ingest (always populate the field) or by making the list tolerant of a bad row instead of failing the whole batch.
