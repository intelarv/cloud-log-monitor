# PHI/PII Log Audit (agentic, cloud-agnostic)

Cloud-agnostic agentic system that ingests cloud-provider logs, detects PHI/PII/secrets, maintains a tamper-evident audit ledger, and exposes a chat-over-audit dashboard for healthcare compliance analysts. See `docs/ARCHITECTURE.md`.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port comes from workflow env)
- `pnpm --filter @workspace/api-server run test` — vitest suite (113 tests as of M1.7.3)
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL`, `SESSION_SECRET`
- Optional embedder config (see "Embedder selection" below): `EMBEDDING_PROVIDER`, `DEPLOYMENT_TARGET`, `EMBEDDING_MODEL`, `EMBEDDING_DIM` plus provider-specific creds.
- Optional step-up auth (dev): `STEP_UP_DEV_TOKEN` (default `dev-stepup`, ≥8 chars). Replace with a TOTP/WebAuthn verifier in production.

## Embedder selection (cloud-aware)

The embedder used for hybrid retrieval is selected at boot via env. Precedence:
`EMBEDDING_PROVIDER` > `DEPLOYMENT_TARGET` > default (`featurehash`).

| Provider | Default model | Native HIPAA story | Required env |
|---|---|---|---|
| `featurehash` (dev) | — | n/a (local) | none |
| `bedrock` (AWS) | `amazon.titan-embed-text-v2:0` | BAA via AWS | `AWS_REGION` + SDK credential chain |
| `vertex` (GCP) | `text-embedding-005` | BAA via GCP | `GCP_PROJECT_ID`, `GCP_LOCATION`, ADC |
| `azure-openai` (Azure) | `text-embedding-3-small` | BAA via Azure | `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT` |
| `tei` (cloud-agnostic) | server-side (e.g. `nomic-embed-text-v1.5`, `Qwen3-Embedding-0.6B`, `embeddinggemma-300m`) | data never leaves cluster | `TEI_ENDPOINT` |

`DEPLOYMENT_TARGET=aws|gcp|azure|local` is a shortcut that picks the cloud-native provider above; explicit `EMBEDDING_PROVIDER` always wins.

`EMBEDDING_DIM` (default `256`) sets both the embedder output dim and the `finding_embeddings.embedding` column dim. All four cloud providers' defaults support Matryoshka truncation to 256 natively. Changing dim on an existing DB: `DROP TABLE finding_embeddings; restart` — embeddings are a cache, backfill rebuilds them. The boot path validates that the existing column dim matches the configured one and fails loudly otherwise.

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5, AG-UI SSE
- DB: PostgreSQL + Drizzle ORM, pgvector 0.8 (M1)
- Validation: Zod v4, `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- LLM: Gemini 2.5 Flash via Replit AI Integrations (no user key required)

## Where things live

- API entry: `artifacts/api-server/src/index.ts` (bootstrap → embedding backfill → chain verify → listen)
- Chat agent loop: `artifacts/api-server/src/lib/chat-agent.ts`
- Tool registry (MCP-shaped): `artifacts/api-server/src/lib/tools.ts`
- Hybrid retrieval (BM25 + vector + RRF): `artifacts/api-server/src/lib/search.ts`
- Embedder interface + dev embedder: `artifacts/api-server/src/lib/embeddings.ts`
- Cloud embedders (Bedrock/Vertex/Azure/TEI, lazy-loaded): `artifacts/api-server/src/lib/cloud-embedders.ts`
- Embedder factory + env config + registry: `artifacts/api-server/src/lib/embedder-config.ts`
- Per-agent tool allow-list **+ tool-arg revalidation (M1.6)**: `artifacts/api-server/src/lib/policy.ts`
- Agent prompts (version-pinned): `artifacts/api-server/src/lib/prompts.ts`
- Ledger writer + chain walk: `artifacts/api-server/src/lib/ledger.ts`
- Session + step-up cookies (HMAC, domain-separated): `artifacts/api-server/src/lib/auth.ts`
- Step-up + break-glass admin routes: `artifacts/api-server/src/routes/admin.ts`, `artifacts/api-server/src/routes/auth.ts`
- Per-user rate limiters (chat, tools, break-glass, step-up): `artifacts/api-server/src/app.ts`
- DB schema (source of truth): `lib/db/src/schema/*.ts` — `findingSafeColumns` / `FindingSafe` in `findings.ts` is the compile-time gate that keeps `raw_evidence` out of non-break-glass reads.
- DB setup SQL (RLS, pgvector, FTS, triggers, break-glass grants table, F-CANARY raw backfill): `lib/db/src/setup-sql.ts`
- Seed (10 findings + canary w/ raw payload + genesis): `lib/db/src/seed.ts`
- Threat model: `threat_model.md`

## Architecture decisions

- **Embedder is pluggable and cloud-aware; dev ships a deterministic feature-hash embedder.** Neither Replit's Gemini nor OpenAI AI Integration exposes embeddings. Rather than require a third-party key for a demo, dev uses a 256-dim SHA-256 feature-hashing embedder (tagged `featurehash-v1@dev:256`) behind an `Embedder` interface. Production picks per cloud via `EMBEDDING_PROVIDER` (or `DEPLOYMENT_TARGET` shortcut): Bedrock Titan v2 on AWS, Vertex `text-embedding-005` on GCP, Azure OpenAI `text-embedding-3-small` on Azure, or self-hosted TEI for cloud-agnostic. All defaults support Matryoshka truncation to 256 so the schema is portable. Cloud SDKs are lazy-imported — dev never pays for them. The BM25 half of the hybrid is real lexical retrieval and carries most of the dev-mode signal; the vector half becomes semantically meaningful as soon as a real embedder is configured.
- **PHI guard wraps every embedder, not just the dev one.** `PhiGuardEmbedder` runs `scanForPhi` on every input before it's embedded — for cloud providers this also means no PHI ever leaves the cluster boundary to a third-party model endpoint. Defense-in-depth on top of the redaction pipeline.
- **Hybrid retrieval = BM25 ∪ vector, fused with RRF (k=60).** Postgres `tsvector` (generated column over redacted snippet + classification + subclass + severity + source, with weights A/B/C) gives lexical matches; pgvector cosine (`ivfflat`, lists=10) gives sub-word/semantic matches. RRF avoids needing score normalization and is the standard fusion choice.
- **Defense-in-depth on embedder input.** `PhiGuardEmbedder` refuses any text that trips `scanForPhi`. Pipeline only ever feeds redacted text, but the guard turns any regression into an immediate failure instead of silently storing PHI-derived vectors.
- **Agent context = hybrid top-K ∪ severity floor.** The chat agent sees (a) the top-10 RRF-fused candidates seeded with the user question and (b) the 8 most recent critical/high open findings. This guarantees questions like "list the critical findings" still surface the right rows even when their tokens don't overlap the query. The full preloaded id list is recorded in the `chat.agent_turn` ledger entry for audit.
- **Tool calls are bounded.** `MAX_TOOL_CALLS=2` per turn (typical chain: `search_findings` → `get_finding`). Per-agent tool allow-list in `policy.ts` is the single source of truth for "which agent can call what".
- **Ledger writes are append-only via a single advisory-locked writer.** `ENABLE ALWAYS` triggers in setup SQL refuse UPDATE/DELETE on the ledger table even from the owner role — belt-and-suspenders for the tamper-evidence claim. SSE envelopes are Zod-validated before being sent.
- **Raw evidence is reachable through exactly one code path.** `findings.raw_evidence` (M1.6, jsonb, nullable) is excluded from `findingSafeColumns`; every read of findings — `get_finding` tool, hybrid-search hydration, chat-agent severity-floor preload, dashboard list + detail — uses `.select(findingSafeColumns)` and is typed `FindingSafe = Omit<Finding,'rawEvidence'>`. The only `.select()` over the full row is `GET /admin/findings/:id/raw`, which requires a session + an active per-finding break-glass grant and ledgers `break_glass.raw_phi_accessed` on every read. Compile-time exclusion + a single audited call site instead of runtime field-stripping.
- **Step-up cookie is signed independently from the session cookie.** Both share `SESSION_SECRET`, but each HMAC input is tagged with a per-purpose label (`session` vs `stepup`) so a session cookie cannot be replayed as a step-up cookie or vice versa. Step-up TTL is 5 min; grants are ≤15 min and per-finding.

## Product

- Auth (session cookies), per-tenant chat sessions, AG-UI SSE chat over findings.
- Findings browse + single-finding read, all RLS-scoped, raw evidence excluded by safe projection.
- Hybrid search exposed to the chat agent as a tool; agents cite findings as `[F:<id>]`.
- Tool-arg revalidation refuses canary tokens, PHI, oversize payloads, or malformed ids on every agent tool call; refusals materialize as critical/high incident findings (M1.6).
- Step-up auth (`POST /api/auth/step-up`) + break-glass raw-PHI view (`POST /api/admin/break-glass/grants`, `GET /api/admin/findings/:id/raw`) with per-access ledger events (M1.6).
- Per-user rate limits on chat, tools, and break-glass issuance; per-IP on login + step-up (M1.6).
- Tamper-evident ledger over every chat turn, every input PHI refusal, every agent output PHI detection, every finding create, every step-up grant/denial, every break-glass grant, and every raw-PHI read. `GET /api/admin/ledger/verify` walks the chain.
- Honeypot canary finding traps prompt-injection attempts; verified working in M1 (canary in chat input) and M1.6 (canary echoed into a tool argument).

## M1.7.1 — Ledger-payload safety on analyst free-text

Code-review on M1.7 surfaced a real pre-existing risk: break-glass `justification`, the M1.7 `approval_note`, and step-up `reason` were all analyst free-text fields that landed unscrubbed in immutable ledger payloads. A careless or hostile analyst could leak PHI/secrets into the chain.

- New `artifacts/api-server/src/lib/text-policy.ts` exports `validateLedgerSafeText`: runs `scanForPhi` (PHI/PII/secrets) + canary-token check against any free-text field about to be persisted.
- Applied at three boundaries: `POST /admin/break-glass/grants` (`justification`), `POST /admin/break-glass/grants/:id/approve` (`approval_note`), `POST /auth/step-up` (`reason`). On hit → HTTP 400 + ledger `policy.text_field_rejected` with detector *names only* (matched substrings never leave the request).
- DB-level defense-in-depth for the two-person rule: `CHECK (approver_user_id IS NULL OR approver_user_id <> user_id)` named `bg_no_self_approval`, added idempotently via DO block (verified — a direct INSERT with `approver_user_id = user_id` raises `check constraint violation` at the DB).

## M1.7 — Two-person rule on critical break-glass

Break-glass grants on findings whose severity is `critical` are created PENDING and require a **second analyst** (different `user_id`, same tenant) to complete step-up and approve before raw-PHI access is permitted. Non-critical grants are unchanged.

- New columns on `break_glass_grants`: `requires_second_approval` (captured at grant-creation time from the finding's then-current severity, so a later severity downgrade cannot retroactively bypass the rule), `approver_user_id`, `approved_at`, `approver_step_up_reason`.
- New endpoints (under existing `/api/admin/break-glass/grants` rate limit prefix):
  - `POST /api/admin/break-glass/grants/:id/approve` — session + step-up by a *different* user. Self-approval returns 403 and is ledgered `break_glass.approval_denied_self_approval`. Approval is ledgered `break_glass.approved` with both requester and approver ids + the approver's step-up reason. Uses a compare-and-swap on `approver_user_id IS NULL` to defeat double-approve races.
  - `GET /api/admin/break-glass/pending-approvals` — lists grants the caller is eligible to approve (other users' pending grants in the same tenant).
- `GET /api/admin/findings/:id/raw` now distinguishes "no grant" (`break_glass_required: true`) from "grant exists but pending approval" (`approval_required: true`).
- Closes the `docs/ARCHITECTURE.md` §18 open question with the proposed rule: single-analyst for severity ≤ high, two-person for critical.
- Threat model §EoP "Insider threat (rogue analyst)" satisfied at the moment of access — a rogue analyst cannot unilaterally read raw PHI on a critical finding even with valid session + step-up.

## Milestones

- **M0** (complete): walking skeleton — auth, RLS, ledger with hash chain, chat over findings, deterministic PHI/PII detectors, input + output PHI scans, honeypot canary, SSE envelope Zod validation.
- **M1** (complete): pgvector + FTS hybrid retrieval, `search_findings` tool, agent context = top-K hybrid ∪ severity floor, preloaded ids in agent-turn ledger, embedder pluggability + PHI guard.
- **M1.5** (complete): cloud-aware embedder factory (Bedrock / Vertex / Azure OpenAI / TEI / featurehash) with env-driven provider+model+dim selection, `DEPLOYMENT_TARGET` shortcut, runtime column-dim invariant check, PHI guard on outbound text. Cloud SDKs are lazy-loaded so dev installs stay small.
- **M1.6** (complete): security pass —
  - **Tool-arg revalidation** (ARCHITECTURE.md §23.1). Every `ToolRegistry.call` runs `validateToolArgs` after Zod parse: canary-token scan in any string arg, PHI-in-args scan, 8KB arg-size cap, finding-id whitelist (`[A-Za-z0-9_-]{1,64}`). Failures return `code: "policy_violation"`; the chat-agent's `onPolicyViolation` hook creates an incident finding (critical for canary trips, high otherwise) and ledgers `agent.canary_in_tool_args` / `agent.tool_args_policy_violation`. Raw arg values never enter the ledger payload — only violation kinds + tool name.
  - **Per-user rate limiting**. `userOrIpKey` (session.sub if authenticated, else IPv6-safe IP) on `/api/chat`, `/api/tools`, `/api/admin/break-glass/grants`. Login + step-up stay per-IP (no stable identity / can't trust the identity being proven). Step-up gets a tight 5/min cap as anti-brute-force per threat_model §AuthN. Break-glass issuance gets 10/min — issuance is intentionally rare; bursts are themselves suspicious.
  - **Step-up auth + break-glass raw-PHI view**. New `POST /api/auth/step-up` issues a separate 5-min HMAC-signed `phia_stepup` cookie (signature domain-separated from the session cookie via a per-purpose tag, so neither can be replayed as the other). `POST /api/admin/break-glass/grants` (requires session + step-up) issues per-finding time-boxed grants (max 15 min, justification ≥10 chars). `GET /api/admin/findings/:id/raw` requires session only — the grant IS the gate — and ledgers `break_glass.raw_phi_accessed` on EVERY access (not just grant). Threat model §EoP "break-glass scope minimization" + §Repudiation "every break-glass access ledgered" both satisfied.
- **M1.7** (complete): two-person rule on critical-severity break-glass grants. Pending state, separate approver, self-approval refused + ledgered, CAS-protected approval. See "M1.7 — Two-person rule on critical break-glass" above.
- **M1.7.1** (complete): boundary scan on analyst free-text (justification, approval_note, step-up reason) keeps PHI/secrets/canary out of immutable ledger payloads; DB CHECK `bg_no_self_approval` enforces the two-person rule below the application layer. See "M1.7.1 — Ledger-payload safety on analyst free-text" above.
- **M1.7.2** (complete): event-type-driven alerting. New `lib/alerts.ts` + post-commit hook in `appendLedger` emits structured `alert=true` stderr lines for `agent.canary_in_tool_args` (critical), `break_glass.approval_denied_self_approval` (critical), `policy.text_field_rejected` (high), `agent.tool_args_policy_violation` (high), `break_glass.raw_phi_accessed` (warning), `ledger.chain_invalid` (critical), plus a rolling 5-min ≥3 threshold on `auth.step_up_failed`. Spec consolidated in `docs/ARCHITECTURE.md` §25; 5 new vitest cases.
- **M1.7.3** (complete): closed out architect's M1.7.1 follow-ups.
  - 11 boundary tests for `validateLedgerSafeText` (SSN/email/AWS key/JWT/MRN/canary/clean/empty/canary-before-PHI/no-substring-leak/deduped detectors).
  - **§25.4 mechanical guard** (`event-type-coverage.test.ts`): scans all source for `eventType:` literals (handles ternary + multi-line forms) and fails if any ledger event isn't either in `ALERT_RULES` or `NOT_ALERTABLE`. Also flags dead `ALERT_RULES` entries that no code emits. First run caught two real gaps: `chat.input_phi_refused` and `agent.output_phi_detected` had no alert decision; both are now in `ALERT_RULES` (high and critical respectively).
  - After architect review: added a symmetric dead-entry check for `NOT_ALERTABLE` (surfaced and removed a speculative `auth.login_success` entry with no emitter); broadened the scan to include `lib/db/src/` so `finding.created` and `ledger.genesis` from seed.ts count as live; excluded drizzle schema dirs to avoid `text("event_type")` false positives; documented the scanner's known limitations (single-quote / template-literal / const-ref / field-rename indirection) and the migration path to a ts-morph AST walk.
  - Test count: 92 (pre-M1.7) → **113** (post-M1.7.3).

## User preferences

_None recorded._

## Gotchas

- Always run `pnpm run typecheck` from the repo root after schema or tool changes — leaf workspace packages are only checked there.
- Bootstrap is idempotent: `CREATE EXTENSION IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, embedding backfill skips rows whose `embedder_version` matches, and the F-CANARY `raw_evidence` backfill is conditional on `IS NULL`. Safe to restart freely.
- Drizzle's `sql\`... = ANY(${ids})\`` interpolates arrays as N separate params and fails at runtime. Use `inArray(col, ids)` instead.
- Don't add to root `tsconfig.json` references — that's libs-only. Artifacts are leaf workspace packages.
- **Never `.select().from(findingsTable)` outside `routes/admin.ts`'s raw endpoint** — use `.select(findingSafeColumns)` so `rawEvidence` cannot enter an LLM prompt or SSE frame. The `FindingSafe` type is the compile-time guard; if you find yourself typing a non-admin result as `Finding`, you've widened the protection away.
- Rate-limiter `keyGenerator` must use `ipKeyGenerator(req.ip)` (not `req.ip` directly) for IPv6 safety — `express-rate-limit` v8 enforces this.

## Pointers

- See `.local/skills/pnpm-workspace/SKILL.md` for workspace structure, TypeScript setup, and package details.
