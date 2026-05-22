# PHI/PII Log Audit Agent

A cloud-agnostic, agentic system that ingests cloud-provider logs, detects PII/PHI, maintains a **tamper-evident audit ledger**, and exposes a **chat-over-audit dashboard** for healthcare compliance analysts.

This repo is the demo-scale slice of the design in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — small enough to run on Replit, but every security invariant from [`threat_model.md`](threat_model.md) is wired end-to-end. Production-scale pieces (Temporal, Kafka, Bedrock/Vertex agent runtimes, OpenSearch, WORM tiering, notarization to a separate cloud account) are deferred; the abstractions they plug into are present.

Current state: **M1.6 complete** — hybrid retrieval, cloud-aware embedders, tool-arg revalidation, per-user rate limiting, step-up auth + per-finding break-glass raw-PHI view. See `replit.md` for the operator quick-reference.

---

## What's shipped

| Concern | Implementation |
|---|---|
| **API** | Express 5 (TypeScript), OpenAPI-first, Zod-validated, AG-UI SSE for chat |
| **DB** | PostgreSQL + Drizzle ORM, RLS FORCEd on tenant tables, `pgvector` 0.8, generated `tsvector` for FTS |
| **Auth** | HMAC signed-cookie session + independently-signed (domain-separated) step-up cookie; `HttpOnly` / `Secure` / `SameSite=Lax`; `requireSession` on every sensitive route |
| **Tamper-evident ledger** | Hash-chained `prev_hash → hash`, single writer under a Postgres advisory lock, `ENABLE ALWAYS` triggers refusing UPDATE/DELETE even from the owner role, boot-time chain verification (process exits 2 on corruption) |
| **Agent plane** | `ToolRegistry` (MCP-shaped) with per-agent allow-list, Zod arg validation, **and** post-Zod policy revalidation (canary scan, PHI scan, 8KB cap, finding-id whitelist) |
| **Chat agent** | Gemini 2.5 Flash via the Replit AI integration, sealed system prompt, source-tagged context (`trust="untrusted"`), bounded tool loop (`MAX_TOOL_CALLS=2`), `[F:id]` citations |
| **Hybrid retrieval** | BM25 (Postgres FTS) ∪ vector (pgvector cosine, `ivfflat`) fused with RRF (k=60); agent context = top-K hybrid ∪ recent critical/high open findings |
| **Embedder** | Pluggable `Embedder` interface; dev = 256-dim feature-hash; prod = Bedrock Titan v2 / Vertex `text-embedding-005` / Azure OpenAI `text-embedding-3-small` / self-hosted TEI. Cloud SDKs lazy-loaded. `PhiGuardEmbedder` refuses any input that trips `scanForPhi`. |
| **PHI containment** | Input PHI scan **before** the LLM call (refuse + ledger `chat.input_phi_refused`); output PHI scan **before** anything reaches the client (buffered, not streamed); `SAFE_REFUSAL` replacement + finding about the agent's own output |
| **Raw-evidence containment** | `findings.raw_evidence` excluded from `findingSafeColumns`; every non-admin read is typed `FindingSafe = Omit<Finding,'rawEvidence'>` (compile-time gate); only `GET /api/admin/findings/:id/raw` (session + per-finding grant) returns the full row, ledgered on every access |
| **Step-up + break-glass** | `POST /api/auth/step-up` (5-min TTL, separate HMAC); `POST /api/admin/break-glass/grants` (requires session + step-up; ≤15-min, per-finding, ≥10-char justification); `GET /api/admin/findings/:id/raw` (grant IS the gate) |
| **DoS guardrails** | Per-user rate limits on `/chat`, `/tools`, `/admin/break-glass/grants`; per-IP on `/auth/login` and `/auth/step-up` (anti-brute-force: step-up capped 5/min) |
| **UI** | 3-pane embedded React dashboard at `/api/` — findings list, chat, ledger viewer with on-demand chain verification |

10 seeded findings + 1 honeypot canary (with raw payload) boot into every fresh DB; each `finding.created` is its own ledger entry, so the chain has real content before the first user request.

---

## Stack

- **pnpm workspaces**, Node.js 24, TypeScript 5.9
- **API:** Express 5
- **DB:** PostgreSQL + Drizzle ORM (`drizzle-zod`) + pgvector 0.8
- **Validation:** Zod (`zod/v4`)
- **API codegen:** Orval from `lib/api-spec/openapi.yaml`
- **LLM:** Gemini 2.5 Flash via `@workspace/integrations-gemini-ai` (Replit AI integration — no key needed)
- **Build:** esbuild (single bundle per artifact)

---

## Run it

The Replit workflow already runs the API server. To run by hand:

```bash
pnpm install
pnpm --filter @workspace/api-server run dev
```

Open the **API Server** artifact in the preview pane (or visit `/api/` on the dev domain) and log in:

| Username | Tenant | Notes |
|---|---|---|
| `alice` | `default` | Has access to the seeded findings |
| `bob` | `default` | Same tenant, separate user — useful for testing per-user RLS |
| `carol` | `other` | Different tenant — should see *no* findings (RLS proof) |

### Things to try

1. **Hybrid retrieval:** *"Show me the critical findings"* — agent uses `search_findings` (BM25 ∪ vector ∪ RRF) and cites results as `[F:id]`. Preloaded id list appears in the `chat.agent_turn` ledger entry.
2. **Tool call:** *"Show me the details of F-001"* — SSE stream emits `tool_call` then `tool_result` for `get_finding`.
3. **Input PHI guard:** *"my ssn is 123-45-6789"* — refused before Gemini is called; new `F-INPUT-PHI-*` finding appears and a `chat.input_phi_refused` ledger entry is written.
4. **Canary-in-tool-args trap:** ask the agent to call `get_finding` with the canary id from F-CANARY's description — refused by `validateToolArgs`, ledgered as `agent.canary_in_tool_args`, and a new critical incident finding is created.
5. **RLS:** Log out, log back in as `carol` — findings list is empty.
6. **Step-up + break-glass:**
   ```bash
   curl -c jar -b jar -X POST /api/auth/login -d '{"username":"alice","tenantId":"default"}' -H 'content-type: application/json'
   curl -c jar -b jar -X POST /api/auth/step-up -d '{"token":"dev-stepup"}' -H 'content-type: application/json'
   curl -c jar -b jar -X POST /api/admin/break-glass/grants -d '{"findingId":"F-CANARY","justification":"investigating prompt-injection incident #123"}' -H 'content-type: application/json'
   curl -c jar -b jar /api/admin/findings/F-CANARY/raw   # returns raw payload; ledgers break_glass.raw_phi_accessed
   ```
7. **Ledger:** Open the ledger tab and hit **Verify** — re-walks the full chain (now includes step-up, break-glass, and raw-access entries).
8. **Unauthenticated access:** `curl /api/ledger` → `401`.

---

## Repo layout

```
artifacts/
  api-server/             # Express API + embedded React dashboard
    src/
      app.ts              # Express setup, rate limits (per-user + per-IP), session middleware
      index.ts            # bootstrap → embedding backfill → verifyChain → listen
      lib/
        auth.ts           # signed-cookie sessions + step-up (domain-separated HMAC)
        chat-agent.ts     # Gemini loop, hybrid context preload, onPolicyViolation hook
        cloud-embedders.ts # Bedrock / Vertex / Azure / TEI (lazy-loaded)
        db-context.ts     # withTenant(): per-request RLS GUC
        embedder-config.ts # env-driven factory, registry, dim invariant check
        embeddings.ts     # Embedder interface, featurehash dev embedder, PhiGuardEmbedder
        ledger.ts         # appendLedger + verifyChain
        policy.ts         # per-agent tool allow-list + validateToolArgs (canary/PHI/size/id)
        prompts.ts        # sealed system prompt + prompt_hash
        redact.ts         # PHI/PII/secrets detectors + SAFE_REFUSAL
        search.ts         # BM25 + vector + RRF hybrid retrieval
        sse.ts            # AG-UI SSE envelope + heartbeats
        tools.ts          # ToolRegistry, get_finding + search_findings handlers
      routes/             # auth (login + step-up), findings, chat, ledger, tools, admin (break-glass), ui
  mockup-sandbox/         # canvas component preview (dev-only)

lib/
  api-spec/               # OpenAPI source of truth
  api-zod/                # generated Zod schemas + React Query hooks
  db/
    src/
      schema/             # findings (+ raw_evidence, findingSafeColumns/FindingSafe), ledger, chat, break_glass_grants, finding_embeddings
      setup-sql.ts        # RLS, FORCE RLS, pgvector + ivfflat, FTS tsvector, ENABLE ALWAYS triggers, F-CANARY raw backfill
      bootstrap.ts        # idempotent setup + seed-if-empty + embedding backfill
      seed.ts             # 10 findings + canary
      chain.ts            # hash-chain helpers
      db.ts               # pool + drizzle singleton

docs/
  ARCHITECTURE.md         # full design (M0–M1.6 implementation lives in §23, §24)
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
pnpm --filter @workspace/api-server run dev     # run the API + UI
pnpm --filter @workspace/api-server run test    # vitest (92 tests as of M1.6)
```

Required env: `DATABASE_URL`, `SESSION_SECRET` (both wired up automatically in Replit).
Optional: `STEP_UP_DEV_TOKEN` (defaults to `dev-stepup`; replace with TOTP/WebAuthn in prod), embedder selection via `EMBEDDING_PROVIDER` or `DEPLOYMENT_TARGET` (see `replit.md`).

---

## Security invariants (and where they live)

Every one of these is verifiable from the code or by interacting with the running app:

1. **PHI never reaches LLM prompts** — `scanForPhi` runs on `parsed.data.content` in `routes/chat.ts` before `runChatTurn`; `PhiGuardEmbedder` runs `scanForPhi` on every embedder input; agent context only ever projects `findingSafeColumns`.
2. **PHI never reaches the client** — `runChatTurn` is called with `onDelta: undefined`; the full agent text is buffered, scanned, and only the post-scan result is emitted as a single SSE delta. Findings list/detail and search hydration all project `findingSafeColumns` so `rawEvidence` cannot leak via JSON either.
3. **PHI never reaches tool arguments** — `validateToolArgs` runs after Zod parse on every `ToolRegistry.call` and rejects any string arg matching PHI patterns; refusals materialize as critical/high incident findings + `agent.tool_args_policy_violation` ledger events.
4. **Ledger is tamper-evident** — `appendLedger` takes a `pg_advisory_xact_lock`, reads the head row, computes `sha256(prev_hash || canonical_payload)`, and inserts in one transaction. Boot calls `verifyChain` and `process.exit(2)` on any mismatch. `ENABLE ALWAYS` triggers refuse UPDATE/DELETE on `ledger_entries` even from the owner role.
5. **RLS enforced at the DB** — `setup-sql.ts` runs `ALTER TABLE … ENABLE/FORCE ROW LEVEL SECURITY`; every request binds `app.tenant_id` for the transaction via `withTenant`.
6. **Per-agent tool allow-list + arg revalidation** — `policy.ts` whitelists tools per agent name; `ToolRegistry.call` runs the tool's Zod schema **then** `validateToolArgs` (canary scan, PHI scan, 8KB cap, finding-id whitelist `[A-Za-z0-9_-]{1,64}`).
7. **Raw evidence is reachable through exactly one code path** — `findingSafeColumns` excludes `raw_evidence`; `FindingSafe = Omit<Finding,'rawEvidence'>` is the compile-time gate. The only full-row `.select()` is `GET /admin/findings/:id/raw`, which requires a session **and** an active per-finding break-glass grant and ledgers `break_glass.raw_phi_accessed` on every access.
8. **Step-up is independently signed** — the `phia_stepup` cookie's HMAC input is tagged with a per-purpose label so a session cookie cannot be replayed as a step-up cookie or vice versa (both derive from the same `SESSION_SECRET`). TTL 5 min; grants ≤15 min and per-finding; justification ≥10 chars.
9. **No anonymous endpoints** — `requireSession` is mounted on every route except `/api/healthz` and `/api/auth/login`.
10. **Rate limits** — `app.ts` applies per-user (session.sub) limits on `/chat`, `/tools`, `/admin/break-glass/grants`; per-IP (IPv6-safe via `ipKeyGenerator`) on `/auth/login` and `/auth/step-up` (5/min anti-brute-force).
11. **Errors don't leak internals** — the SSE error path emits the literal string `"agent_error"`; the full error is logged server-side only. Policy-violation messages are value-free (kind + tool name only) so raw args never enter the ledger payload.

---

## Known production gaps (deferred — see `docs/ARCHITECTURE.md`)

- **Append-only at the DB privilege layer.** Three defenses are in place: advisory-lock + single-writer pattern in `appendLedger`, `BEFORE UPDATE/DELETE/TRUNCATE` triggers on `ledger_entries` (`ENABLE ALWAYS`, fire under logical-replication apply), and `findingSafeColumns` projection. What's still missing is **role separation** — the connection role is also the table owner, and an owner can `ALTER TABLE … DISABLE TRIGGER` to bypass. Production uses a dedicated `ledger_writer` role with `INSERT`-only on `ledger_entries`, no DDL, and external notarization to a separate cloud account with Object Lock.
- **No log ingest pipeline.** Findings are seeded; the Stage-1+2 detector pipeline (§9–§11 of the architecture doc) is the next milestone.
- **Single in-process agent runtime.** Bedrock AgentCore / Vertex Agent Builder runtimes (the `LlmAgentRuntime` abstraction lives in the design doc) are wired later.
- **No HITL gates for write actions.** No remediation tools yet; once they exist they MUST return proposals only.
- **Step-up = shared dev token.** `STEP_UP_DEV_TOKEN` is a placeholder for TOTP/WebAuthn / IdP step-up. The cookie machinery and ledger flow are production-shape; only the verifier swaps out.
- **Single-analyst break-glass.** `docs/ARCHITECTURE.md` §18 flags the open question: does a raw-PHI grant require a second approver? Default proposal there is single-analyst for severity ≤ high, two-person for critical. Not enforced in this repo.

---

## License & data

This is a Replit development environment. No real PHI is permitted in dev. All seeded data is synthetic.
