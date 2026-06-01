---
name: Route-level HTTP test harness (api-server)
description: How to write HTTP/route-level tests for the Express api-server — no supertest is installed.
---

# Route-level HTTP tests for api-server

There is **no supertest** dependency. To exercise an Express route end-to-end
(cookies, middleware, auth, ledger side effects), drive the real app over HTTP:

- `import app from "../app"` and `createServer(app).listen(0, "127.0.0.1")`; read
  the assigned port from `server.address()`.
- Use `fetch` with a tiny manual cookie jar — `fetch` does NOT persist
  `Set-Cookie`. Read responses with `res.headers.getSetCookie()` (Node 24) and
  replay them via the `cookie` request header.
- Real auth flow: `POST /api/auth/login` (sets `phia_sess`) then
  `POST /api/auth/step-up` (token defaults to `dev-stepup`, sets `phia_stepup`).

**Why:** these are the only HTTP-level tests in the suite; everything else is
unit/integration against libs. Future route coverage should reuse this pattern
instead of reaching for supertest.

**How to apply:** same DB-pollution discipline as other DB tests — scope ledger
reads to just-created rows (`gt(seq, before)` + `subjectId`), since the shared
dev ledger is noisy. Module-level singletons read at request time (e.g. the
raw-evidence store via `getRawEvidenceStoreOrNull()`) must be set per-test with
`setRawEvidenceStore()` and reset in `afterEach` — safe because
`fileParallelism` is off and tests in a file run sequentially.
