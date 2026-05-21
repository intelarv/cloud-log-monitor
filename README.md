# PHI/PII Log Audit Agent — M0 Walking Skeleton

A cloud-agnostic, agentic system that ingests cloud-provider logs, detects PII/PHI, maintains a **tamper-evident audit ledger**, and exposes a **chat-over-audit dashboard** for healthcare compliance analysts.

This repo contains the **M0 walking skeleton** per [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §24 — the smallest end-to-end slice that proves the security model works before any of the production-scale pieces (Temporal, Kafka, Bedrock/Vertex agents, OpenSearch, etc.) are wired in.

---

## What's in M0

The skeleton is intentionally small but covers every security invariant from [`threat_model.md`](threat_model.md):

| Concern | M0 implementation |
|---|---|
| **API** | Express 5 (TypeScript), OpenAPI-first, Zod-validated, AG-UI SSE for chat |
| **DB** | PostgreSQL + Drizzle ORM, RLS FORCEd on tenant tables, `findings_redacted` view |
| **Auth** | HMAC signed-cookie session, `HttpOnly` / `Secure` / `SameSite=Lax`, `requireSession` on every sensitive route |
| **Tamper-evident ledger** | Hash-chained `prev_hash → hash`, single writer under a Postgres advisory lock, startup chain verification (process exits 2 on corruption) |
| **Agent plane** | `ToolRegistry` (MCP-shaped) with per-agent allow-list and Zod-validated tool args |
| **Chat agent** | Gemini via the Replit AI integration, sealed system prompt, source-tagged context (`trust="untrusted"`), 1-shot tool loop, `[F:id]` citations |
| **PHI containment** | Input PHI scan **before** the LLM call (refuse + ledger `chat.input_phi_refused`); output PHI scan **before** anything reaches the client (buffered, not streamed); `SAFE_REFUSAL` replacement + finding about the agent's own output |
| **DoS guardrails** | Per-IP rate limits on `/auth/login`, `/chat`, `/tools` |
| **UI** | 3-pane embedded React dashboard at `/api/` — findings list, chat, ledger viewer with on-demand chain verification |

10 seeded findings + 1 honeypot canary boot into every fresh DB; each `finding.created` is its own ledger entry, so the chain has real content before the first user request.

---

## Stack

- **pnpm workspaces**, Node.js 24, TypeScript 5.9
- **API:** Express 5
- **DB:** PostgreSQL + Drizzle ORM (`drizzle-zod`)
- **Validation:** Zod (`zod/v4`)
- **API codegen:** Orval from `lib/api-spec/openapi.yaml`
- **LLM:** Gemini via `@workspace/integrations-gemini-ai` (Replit AI integration — no key needed)
- **Build:** esbuild (single bundle per artifact)

---

## Run it

The Replit workflow already runs the API server. To run by hand:

```bash
pnpm install
pnpm --filter @workspace/api-server run dev   # port 8080 → proxied at /api
```

Open the **API Server** artifact in the preview pane (or visit `/api/` on the dev domain) and log in:

| Username | Tenant | Notes |
|---|---|---|
| `alice` | `default` | Has access to the seeded findings |
| `bob` | `default` | Same tenant, separate user — useful for testing per-user RLS |
| `carol` | `other` | Different tenant — should see *no* findings (RLS proof) |

### Things to try

1. **Tool call:** *"Show me the details of F-001"* — the SSE stream emits `tool_call` then `tool_result` for `get_finding`.
2. **Input PHI guard:** *"my ssn is 123-45-6789"* — refused before Gemini is called; new `F-INPUT-PHI-*` finding appears and a `chat.input_phi_refused` ledger entry is written.
3. **RLS:** Log out, log back in as `carol` — findings list is empty.
4. **Ledger:** Open the ledger tab and hit **Verify** — re-walks the full chain.
5. **Unauthenticated access:** `curl /api/ledger` → `401`.

---

## Repo layout

```
artifacts/
  api-server/             # Express API + embedded React dashboard
    src/
      app.ts              # Express setup, rate limits, session middleware
      index.ts            # bootstrap → seed → verifyChain → listen
      lib/
        auth.ts           # signed-cookie sessions, requireSession
        chat-agent.ts     # Gemini call loop, tool dispatch, citation extraction
        db-context.ts     # withTenant(): per-request RLS GUC
        ledger.ts         # appendLedger + verifyChain
        policy.ts         # per-agent tool allow-list
        prompts.ts        # sealed system prompt + prompt_hash
        redact.ts         # PHI/PII/secrets detectors + SAFE_REFUSAL
        sse.ts            # AG-UI SSE envelope + heartbeats
        tools.ts          # ToolRegistry, get_finding handler
      routes/             # auth, findings, chat, ledger, tools, ui
  mockup-sandbox/         # canvas component preview (dev-only)

lib/
  api-spec/               # OpenAPI source of truth
  api-zod/                # generated Zod schemas + React Query hooks
  db/
    src/
      schema/             # findings, ledger, chat
      setup-sql.ts        # RLS policies, FORCE RLS, views
      bootstrap.ts        # idempotent setup + seed-if-empty
      seed.ts             # 10 findings + canary
      chain.ts            # hash-chain helpers
      db.ts               # pool + drizzle singleton

docs/
  ARCHITECTURE.md         # full design (M0 is §24)
  DESIGN_OPTION_D.md      # multi-agent supervisor deep-dive
  PROMPTS.md, EVALS.md, CAPACITY.md, GLOSSARY.md, DIAGRAMS.md

threat_model.md           # STRIDE-style threat model
replit.md                 # operator quick-reference for this repo
```

---

## Common commands

```bash
pnpm run typecheck                              # full typecheck across all packages
pnpm run build                                  # typecheck + build
pnpm --filter @workspace/api-spec run codegen   # regenerate Zod + RQ hooks from openapi.yaml
pnpm --filter @workspace/db run push            # apply schema changes (dev only)
pnpm --filter @workspace/db run seed            # re-seed findings (idempotent)
pnpm --filter @workspace/api-server run dev     # run the API + UI on port 8080
```

Required env: `DATABASE_URL`, `SESSION_SECRET` (both are wired up automatically in Replit).

---

## Security invariants (and where they live)

Every one of these is verifiable from the code or by interacting with the running app:

1. **PHI never reaches LLM prompts** — `scanForPhi` runs on `parsed.data.content` in `routes/chat.ts` before `runChatTurn` is invoked. PHI input ⇒ `SAFE_REFUSAL` + ledgered finding.
2. **PHI never reaches the client** — `runChatTurn` is called with `onDelta: undefined`; the full agent text is buffered, scanned, and only the post-scan result is emitted as a single SSE delta.
3. **Ledger is tamper-evident** — `appendLedger` takes a `pg_advisory_xact_lock`, reads the head row, computes `sha256(prev_hash || canonical_payload)`, and inserts in one transaction. Boot calls `verifyChain` and `process.exit(2)` on any mismatch.
4. **RLS enforced at the DB** — `setup-sql.ts` runs `ALTER TABLE … ENABLE ROW LEVEL SECURITY` and `… FORCE ROW LEVEL SECURITY`; every request binds `app.tenant_id` for the transaction via `withTenant`.
5. **Per-agent tool allow-list** — `policy.ts` whitelists tools per agent name; `ToolRegistry.call` revalidates args against the tool's Zod schema before invoking the handler.
6. **No anonymous endpoints** — `requireSession` is mounted on every route except `/api/healthz` and `/api/auth/login`.
7. **Rate limits** — `app.ts` applies per-IP `express-rate-limit` to login (10/min), chat (30/min), tools (60/min).
8. **Errors don't leak internals** — the SSE error path emits the literal string `"agent_error"`; the full error is logged server-side only.

---