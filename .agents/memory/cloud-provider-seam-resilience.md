---
name: Cloud-provider seam resilience
description: Convention for pluggable external-backend providers (search, embedder, LLM, log source) — degrade, don't fail.
---

# Cloud-provider seam resilience

When a pluggable provider's backend is a **separate failure domain** from Postgres
(e.g. OpenSearch lexical search, a cloud embedder, a cloud LLM), its failures MUST
degrade, never hard-fail the request or block boot:

- **Request path:** if the external leg throws, fall back to the local/DB leg and
  log a warn — don't reject the whole operation. (e.g. `hybridSearchFindings`
  catches the lexical leg and returns vector-only results.)
- **Boot path:** any boot-time reconcile/backfill against an external backend must
  be wrapped best-effort (try/catch, continue) so the process still comes up and
  serves traffic when the backend is down.
- **Ingest path:** best-effort external index/mirror writes go in try/catch AFTER
  the row is committed to Postgres; an outage must never fail ingest. A boot
  reconcile is the backstop that re-converges a stale/empty external index.

**Why:** code review (architect) failed M10.1's first pass because the docs already
*claimed* "degrades to the vector leg / boot reconcile is the backstop" but the code
awaited the reconcile unguarded and `Promise.all`'d the lexical leg, so an OpenSearch
outage took down both startup and every search. Documented resilience must be
implemented, not just described.

**How to apply:** any new provider behind the embedder/LLM/search/log-source factory
pattern that talks to a non-Postgres backend — wire the three degradation points
above and add a unit test that injects a throwing provider/client (mock
`./db-context` `withTenant` to test the request-path fallback without a live DB).
