# PHI/PII Log Audit (agentic, cloud-agnostic)

Cloud-agnostic agentic system that ingests cloud-provider logs, detects PHI/PII/secrets, maintains a tamper-evident audit ledger, and exposes a chat-over-audit dashboard for healthcare compliance analysts. See `docs/ARCHITECTURE.md`.

Current milestone: **M29 + M30** (both opt-in, default-inert). **M29** — step-up backup/recovery codes + factor-enrollment management: once a production factor (totp/webauthn/oidc) is VERIFIED, an analyst can mint one-time backup codes (HMAC-at-rest in a new `step_up_factors.recovery_enc` AES-256-GCM blob, purpose `stepup-recovery`) and remove a stale enrollment; new recovery/factor-remove routes + dashboard surfaces gated on `STEP_UP_PROVIDER !== "dev"`. **M30** — OpenSearch ILM/ISM hot→warm→cold tiering of the redacted lexical mirror index, opt-in via `OPENSEARCH_ILM_ENABLED` (only active when `SEARCH_PROVIDER=opensearch`). **Full per-milestone history (M0 → M30) + a standing "Implemented vs not" survey live in `docs/MILESTONES.md`; per-seam env reference in `docs/CONFIGURATION.md`.** **Default-safe invariant:** every optional / cloud / security seam is default-inert (loads no SDK, changes no behavior unless its env/data is set), so the credential-free offline eval gate stays byte-identical (+0.0pt).

**Docs:** full per-milestone history (M0 → M30) + a standing "Implemented vs not" survey in `docs/MILESTONES.md`; architecture + implementation decisions in `docs/ARCHITECTURE.md`; optional env reference in `docs/CONFIGURATION.md`.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port comes from workflow env)
- `pnpm --filter @workspace/api-server run test` — vitest suite
- `pnpm --filter @workspace/api-server run eval` — on-demand eval suite (separate from `test`); deterministic detector/agent quality suites + regression gate vs `evals/baseline.json`. Detail + `eval:gate` / `eval:gate:llm` in `docs/CONFIGURATION.md` → "Eval gate".
- `pnpm run eval:gate` — credential-free CI quality gate; registered as the `eval-gate` validation command so it runs automatically on changes.
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL`, `SESSION_SECRET`. **Every optional subsystem — full env vars, defaults, credentials, and the cloud-aware embedder-selection table — is documented in `docs/CONFIGURATION.md` ("Optional env (by subsystem)").** All seams are **default-inert**: unset ⇒ no SDK loaded, no behavior change, eval gate byte-identical. Switch families at a glance (names only; `docs/CONFIGURATION.md` has prose, defaults, and credentials per switch):
  - **Embeddings / memory** — `EMBEDDING_PROVIDER`·`DEPLOYMENT_TARGET`·`EMBEDDING_DIM`; `EMBEDDINGS_TENANT_PARTITIONING`; per-tenant KMS via the `tenant_kms_keys` table (no env switch); `MEMORY_*` eviction + `MEMORY_CONSOLIDATION_SUMMARY` (the one memory feature that calls an LLM).
  - **Retrieval / raw-evidence** — `SEARCH_PROVIDER`·`OPENSEARCH_*`·`SEARCH_REINDEX_BATCH_SIZE`; OpenSearch ILM/ISM hot→warm→cold tiering (M30) via `OPENSEARCH_ILM_ENABLED`·`OPENSEARCH_ILM_*`; `RAW_EVIDENCE_PROVIDER` + tiering (`RAW_EVIDENCE_TIER_*`) + write-retry (`RAW_EVIDENCE_WRITE_*`).
  - **Chat memory** — `CHAT_MEMORY_*` (M18 working memory + summary) and `CHAT_MEMORY_SEMANTIC_RECALL*` (M19).
  - **LLM** — `LLM_PROVIDER=bedrock|vertex|azure-openai`; per-decision-point overlay `LLM_<CHAT|TRIAGE|VERIFIER|SUMMARY>_*` (resolver: `lib/llm-decision-points.ts`); harness limits `LLM_CALL_TIMEOUT_MS`·`TOOL_CALL_TIMEOUT_MS`·`AGENT_*`.
  - **Detection** — `NER_PROVIDER=none|local|presidio|aws-comprehend|gcp-dlp|azure-language` (+ provider creds; `local` (M23) is self-contained in-process, no SDK/network, via `NER_LOCAL_*`; `presidio` is self-hosted over HTTP, no cloud account/SDK, via `NER_PRESIDIO_*`).
  - **Agent pipeline** — `AGENT_PIPELINE_EXTENDED` (M23): off ⇒ supervisor runs Triage→Verifier only (byte-identical); on ⇒ adds Context + Notifier specialist agents (Notifier drafts only, never auto-sends).
  - **Ingest** — `LOG_SOURCE=cloudwatch|cloud_logging|azure_monitor`·`CLOUDWATCH_MAX_CONCURRENT_GROUPS`; `LOG_BUS_PROVIDER=memory|kafka|nats`; stuck-cursor reaper (`INGEST_SOURCE_STALL_*`); dead-letter queue (`INGEST_DEAD_LETTER_ENABLED`·`INGEST_DLQ_*`).
  - **Orchestration** — `WORKFLOW_ENGINE=inprocess|temporal` (+ `TEMPORAL_*`).
  - **Security / ops** — `STEP_UP_PROVIDER=dev|totp|webauthn|oidc` (M24: `dev` ⇒ `STEP_UP_DEV_TOKEN`, byte-identical; `totp` ⇒ RFC 6238 TOTP via the `StepUpVerifier` seam, AES-256-GCM secret-at-rest, enrollment endpoints; M27: `webauthn` ⇒ hand-rolled WebAuthn/FIDO2 via `lib/webauthn.ts` — no SDK/network, `node:crypto` only; register/finish + challenge endpoints, public key + single-use challenge AES-256-GCM in reused `secret_enc`, signature counter in `last_used_step`, needs `WEBAUTHN_RP_ID`·`WEBAUTHN_ORIGIN`; M28: `oidc` ⇒ IdP-federated step-up via `lib/oidc.ts` — vendor-neutral OIDC Authorization Code + PKCE, no SDK, `node:crypto` + global `fetch` only; register/begin·finish + challenge endpoints, bound subject + pending state/nonce/PKCE-verifier AES-256-GCM in reused `secret_enc` (purpose `stepup-oidc`), redirect-based popup→postMessage `{code,state}`, needs `STEP_UP_OIDC_ISSUER`·`STEP_UP_OIDC_CLIENT_ID`·`STEP_UP_OIDC_CLIENT_SECRET`·`STEP_UP_OIDC_REDIRECT_URI`; M29: backup/recovery codes + factor-enrollment management — no env switch, gated `provider !== "dev"`, one-time codes HMAC-at-rest in the new `recovery_enc` AES-256-GCM blob (purpose `stepup-recovery`)); `NOTARIZATION_SECRET`·`NOTARIZATION_RETIRED_KEYS` (separate trust zone); `CHANNEL_*` (Slack / HMAC webhook / PagerDuty); `A2A_REQUIRE_MTLS`·`A2A_MTLS_*` (cross-cloud mTLS + peer ABAC).

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5; **AG-UI** (`@ag-ui/encoder` / `@ag-ui/core`) for UI↔agent SSE; **A2A** (`@a2a-js/sdk`) for agent↔agent (Supervisor → Triage/Verifier); **Temporal** (`@temporalio/*`, optional/lazy) as a selectable durable supervisor-orchestration backend behind the `WorkflowEngine` seam (default in-process)
- DB: PostgreSQL + Drizzle ORM, pgvector 0.8
- Validation: Zod v4, `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- LLM: Gemini 2.5 Flash via Replit AI Integrations (no user key required)

## Where things live

Full per-component index moved to **`docs/CODE_MAP.md`** (grouped: API server, retrieval/embeddings, raw-evidence storage & lifecycle, LLM runtime, ingestion, detection/redaction, policy/prompts, ledger/notarization/alerting, auth/routes, DB) to keep this file scannable. Top entry points:

- API entry: `artifacts/api-server/src/index.ts` (bootstrap → embedding backfill → chain verify → start chain verifier + notarizer → wire ingest pipeline → listen)
- Chat agent loop: `artifacts/api-server/src/lib/chat-agent.ts`; tool registry (MCP-shaped): `artifacts/api-server/src/lib/tools.ts`
- Ledger writer + chain walk: `artifacts/api-server/src/lib/ledger.ts`; HMAC notarization: `artifacts/api-server/src/lib/notarization.ts`
- Hybrid retrieval (BM25 + vector + RRF): `artifacts/api-server/src/lib/search.ts`
- Ingest pipeline (detector → redact → fingerprint upsert → ledger): `artifacts/api-server/src/lib/ingest.ts`
- DB schema (source of truth): `lib/db/src/schema/*.ts` — `findingSafeColumns` / `FindingSafe` in `findings.ts` is the compile-time gate that keeps `raw_evidence` out of non-break-glass reads; setup SQL (RLS, pgvector, FTS, triggers): `lib/db/src/setup-sql.ts`
- Threat model: `threat_model.md`

## Architecture decisions

Moved to `docs/ARCHITECTURE.md` **Appendix A — Implementation decisions log** to keep this file scannable. One-line index of what lives there (newest last):

- Pluggable + PHI-guarded embedder; cloud-aware factory; deterministic dev feature-hash.
- Hybrid retrieval = BM25 ∪ pgvector cosine, fused via RRF (k=60).
- Lexical (BM25) leg is pluggable (`SEARCH_PROVIDER`): Postgres FTS (dev) or OpenSearch (prod) behind a `LexicalSearchProvider` seam; redacted-only mirror, opt-in per-tenant index isolation, `tenant_id` filter as defense-in-depth.
- Agent context = hybrid top-K ∪ severity floor; full preloaded id list ledgered.
- Bounded tool loop (`MAX_TOOL_CALLS=2`); per-agent allow-list in `policy.ts`.
- Append-only ledger via advisory-locked writer + `ENABLE ALWAYS` triggers on `ledger_entries` AND `ledger_checkpoints`.
- Two-layer tamper-evidence: internal hash chain (hourly/weekly walks) + external HMAC checkpoints (5-min, separate trust zone).
- Raw evidence reachable through exactly one code path; `findingSafeColumns` is the compile-time gate.
- Raw-evidence storage is pluggable (`RAW_EVIDENCE_PROVIDER`): inline `raw_evidence` jsonb (dev) or external WORM object store (S3 Object Lock / GCS / Azure Blob) behind a `RawEvidenceStore` seam; WORM `{first,latest}` URIs in `raw_evidence_ref` (out of `findingSafeColumns`), break-glass resolves server-side with inline fallback.
- Step-up cookie domain-separated from session cookie via per-purpose HMAC label.
- Two-person rule on critical-severity break-glass; `requires_second_approval` frozen at grant-creation; DB-level `bg_no_self_approval`.
- Analyst free-text scanned before it lands in the immutable ledger (`validateLedgerSafeText`).
- Ingest is interface-first; `LogBus` + `LogSource` seams, cloud SDKs lazy-imported. `LogBus` is pluggable (`LOG_BUS_PROVIDER=memory|kafka|nats`) behind a `BrokerDriver` seam: Zod-revalidated wire records (poison → drop), at-least-once delivery (ingest dedupes by fingerprint), broker TLS/SASL is the in-transit control for the pre-detection `raw.logs` transport.
- Ingest does defense-in-depth on redaction; regression → critical alert + opaque placeholder.
- Ingest dedupes by fingerprint; `finding.created` fires on first observation only.
- Event-type-driven alerting + mechanical coverage scan in CI.
- Real CloudWatch source behind same `LogSource` seam; `DbCheckpointStore` is mutable by design (cursor only — audit anchor stays locked).
- Channel dispatch: 5 hard guarantees (outbound PHI hard gate, self-recursion guard, per-channel rate limit, webhook host allow-list + HMAC, adapter failure isolation).
- Chat agent routes through the `LlmAgentRuntime` seam (M9.5) so `LLM_PROVIDER` controls every cloud LLM call (chat included); `PhiGuardLlmRuntime` scans multi-turn history; `agent_identity.model_id` records the effective model.
- Agent loop is hardened + dependency-injected (`runAgentLoop`): hard LLM/tool timeouts, bounded tool budget, per-turn output-token circuit breaker, bounded retry, dedup, result clamp. Any LLM failure / cost-cap / budget-exhaustion **degrades to a deterministic redacted finding summary** (never an error page or raw `tool_call` JSON), ledgered on `chat.agent_turn`.
- Specialist agents (Triage, Verifier) speak the **official A2A protocol** (`@a2a-js/sdk`, Agent Cards + JSON-RPC `message/send`) through the `AgentInvoker` seam (loopback in prod, in-process in tests); only redacted `FindingSafe` crosses the wire, returned rationale re-scanned before the ledger. Loopback-only, shared-secret bearer + signed-JWT caller-identity/ABAC authed, with an optional mTLS transport (`A2A_REQUIRE_MTLS`) + per-claim peer ABAC (allow-list + cert↔JWT-subject binding) that 403s + ledgers `a2a.transport_rejected` (fixed route + static reason only); default-inert. UI↔agent chat streams **official AG-UI events** via `@ag-ui/encoder`.

## Product

- Auth (session cookies), per-tenant chat sessions, AG-UI SSE chat over findings. Chat agent has working memory (M18): each turn replays the session's persisted conversation into the LLM via a token+turn-budgeted sliding window, with an opt-in (`CHAT_MEMORY_SUMMARY`) rolling per-session summary for context that overflows the window (PHI-rescanned, ledgered counts-only). Opt-in **semantic recall (M19, `CHAT_MEMORY_SEMANTIC_RECALL`)** upgrades that window from most-recent to most-RELEVANT: per-message embeddings (`chat_message_embeddings`, pgvector cosine) retrieve the top-K prior turns ∪ a recency tail, under the same budgets, falling back to the recency window on any failure (offline embedder ⇒ credential-free; no LLM call, no new ledger events).
- Findings browse + single-finding read, all RLS-scoped, raw evidence excluded by safe projection.
- Hybrid search exposed to the chat agent as a tool; agents cite findings as `[F:<id>]`.
- `structured_query` agent tool: a Zod-validated **typed filter** (classification/severity/status/source[]/limit) resolved through `findingSafeColumns` — the agent plane never emits SQL (threat_model §EoP "no raw SQL from LLMs").
- HITL remediation/proposal plane: the `propose_remediation` tool writes a PENDING `remediation_proposals` row (ledgers `remediation.proposed`) and **never executes**; humans decide via `GET /api/admin/remediation/proposals`, `POST …/:id/confirm` (session + step-up, ledgers `remediation.confirmed`) and `POST …/:id/reject` (ledgers `remediation.rejected`), CAS-guarded `pending→confirmed|rejected`. The proposal-inbox dashboard UI is **built (M15)**: `artifacts/dashboard/src/pages/remediation.tsx` (status-tabbed list, step-up-gated confirm, reject) over generated hooks. An **opt-in executing worker is built** (`REMEDIATION_EXECUTOR`, default-inert): once a human has confirmed, the leader-locked worker drives `confirmed→executing→executed|execution_failed` (CAS each step, stale-row recovery, idempotency via `executed_at`+`external_ref`) through the `RemediationExecutor` seam (`lib/remediation-executor.ts`; default `DevNoopExecutor`, plus opt-in real backends — `ChannelSendExecutor`, `GitHubIssueExecutor`, `RedactionQueueExecutor`, `RoutingRemediationExecutor` — all default-inert; an actual code-change PR and the redact-at-source worker that drains `redaction_requests` stay operator-owned), ledgering `remediation.executed`/`remediation.execution_failed`; the agent plane still never executes (HITL preserved).
- Tool-arg revalidation refuses canary tokens, PHI, oversize payloads, or malformed ids on every agent tool call; refusals materialize as critical/high incident findings.
- Step-up auth (`POST /api/auth/step-up`) + break-glass raw-PHI view (`POST /api/admin/break-glass/grants`, `GET /api/admin/findings/:id/raw`) with per-access ledger events. Critical-severity grants require a second-analyst approval (`POST /api/admin/break-glass/grants/:id/approve`, `GET /api/admin/break-glass/pending-approvals`). The dashboard surfaces all three opt-in second factors on the admin page (gated on `useStepUpStatus().provider`, so the default `dev` surface is unchanged): TOTP enrollment (`components/totp-enrollment.tsx`, M24), WebAuthn/passkey enrollment (`components/webauthn-enrollment.tsx`, M27), and IdP-federated OIDC linking (`components/oidc-enrollment.tsx`, M28); `components/step-up-modal.tsx` runs the matching ceremony at step-up time (typed token for dev/TOTP, passkey assertion for webauthn via `lib/webauthn-client.ts`, IdP popup→postMessage `{code,state}` for oidc via `lib/oidc-client.ts` + `pages/oidc-callback.tsx`). **M29** adds, on any non-dev provider, backup/recovery codes (`components/recovery-codes.tsx` generate/regenerate/show-once + a "use a recovery code" branch in the step-up modal) and a step-up-gated "remove second factor" action.
- Per-user rate limits on chat, tools, and break-glass issuance; per-IP on login + step-up.
- Tamper-evident ledger over every chat turn, every input PHI refusal, every agent output PHI detection, every finding create, every step-up grant/denial, every break-glass grant + approval + raw-PHI read, every chain walk, and every notarization checkpoint. `GET /api/admin/ledger/verify` walks the chain on demand; `GET /api/admin/ledger/checkpoints?verify=1` walks the external notarization.
- Honeypot canary finding traps prompt-injection attempts in chat input and tool arguments.

## User preferences

_None recorded._

## Gotchas

- Always run `pnpm run typecheck` from the repo root after schema or tool changes — leaf workspace packages are only checked there.
- Bootstrap is idempotent: `CREATE EXTENSION IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, embedding backfill skips rows whose `embedder_version` matches, F-CANARY `raw_evidence` backfill is conditional on `IS NULL`, and `CREATE TABLE IF NOT EXISTS ledger_checkpoints` runs *before* the ENABLE ALWAYS trigger block in `setup-sql.ts` so boot ordering is correct. Safe to restart freely.
- **Never run `drizzle-kit push` / `db push` / `push-force` against a populated DB, and never try to make `push` produce a clean diff.** A large part of the schema is raw-DDL-owned in `setup-sql.ts` — pgvector `finding_embeddings`, the generated `findings.search_tsv` FTS column + GIN index, ROW LEVEL SECURITY (+ FORCE RLS) on every tenant-scoped table, the `findings_redacted` view, and CHECK constraints like break-glass `bg_no_self_approval`. drizzle-kit only knows the Drizzle table definitions, so `push` diffs all of those as orphans and wants to `DROP`/`DISABLE` them. It is "safe" today only by accident: the data-loss prompt on dropping the populated `finding_embeddings`/`search_tsv` aborts the whole batch under a closed stdin, so nothing applies. Remove that abort (a clean diff, `--force`, or an empty DB) and push **silently disables RLS and drops the redacted view + self-approval constraint** — a security teardown. So `scripts/post-merge.sh` and app boot reconcile the DB via the idempotent `db setup` (SETUP_SQL), not push; core Drizzle tables are provisioned out of band by a one-time `db push` on a fresh DB. (Expression indexes like `ledger_actor_id_idx` also churn on every push — drizzle-kit can't round-trip the `->>'…'::text` form — another reason push is the wrong tool here.)
- Drizzle's `sql\`... = ANY(${ids})\`` interpolates arrays as N separate params and fails at runtime. Use `inArray(col, ids)` instead.
- `db.execute(sql\`...\`)` returns a QueryResult; use `.rows[0]`, not array destructuring on the result.
- Drizzle wraps trigger-raised errors inside `"Failed query: ..."`, so test assertions should match the underlying cause string, not the outer envelope.
- Don't add to root `tsconfig.json` references — that's libs-only. Artifacts are leaf workspace packages.
- **Never `.select().from(findingsTable)` outside `routes/admin.ts`'s raw endpoint** — use `.select(findingSafeColumns)` so `rawEvidence` cannot enter an LLM prompt or SSE frame. The `FindingSafe` type is the compile-time guard; if you find yourself typing a non-admin result as `Finding`, you've widened the protection away.
- Rate-limiter `keyGenerator` must use `ipKeyGenerator(req.ip)` (not `req.ip` directly) for IPv6 safety — `express-rate-limit` v8 enforces this.
- DB integration tests pollute the shared dev ledger with `system.integration_test_marker` rows + sequence gaps + occasional forged checkpoint rows (deferred isolation per M1.9). New tests that walk ledger or checkpoints must scope to just-created rows (pass `sinceSeq` / filter by id), not assume the table is clean. The scoping vocabulary is centralized in `artifacts/api-server/src/test-support/ledger-harness.ts` (`ledgerHeadSeq()` to capture head-seq before the code under test, `uniq()` for random source/fingerprint suffixes, `uniqueTenant(label)` for a per-test tenant id that cannot collide with the seed `default` tenant) — import from there rather than re-declaring per file. Vitest still runs with `fileParallelism: false` (configured in `artifacts/api-server/vitest.config.ts`): the harness reduces coupling but does NOT make parallel files safe — `appendLedger`'s single advisory lock + the notarization head-seq idempotency invariant are a genuine serialization requirement, so it stays serialized by design, not just as a pollution workaround.
- When adding a new `eventType:` literal, also add it to `ALERT_RULES` or `NOT_ALERTABLE` in `alerts.ts` in the same change, or `event-type-coverage.test.ts` will fail.

## Pointers

- See `.local/skills/pnpm-workspace/SKILL.md` for workspace structure, TypeScript setup, and package details.
- Agent continuity / crash-recovery notes (gitignored): `.agent-context.md`.
- Temporal supervisor backend (`WORKFLOW_ENGINE=temporal`) has an opt-in live-cluster verification harness: `pnpm --filter @workspace/api-server run test:temporal` (gated `temporal-integration.test.ts` + `scripts/run-temporal-integration.sh`, starts a local `temporal server start-dev`, no Docker). `@temporalio/*` are `optionalDependencies` (inert for the normal suite + eval gate). See `deploy/README.md` → "Live-cluster verification harness". Note: a live native worker can't execute in the Replit dev sandbox (OOM under host memory pressure) — run the harness on a resourced machine.
- Deployment (M9.1 Helm + Docker, M9.4 Replit deploy path): `deploy/README.md`. Per-cloud overlays: `deploy/helm/phi-audit/values-{aws,gcp,azure}.yaml`. Terraform IaC is **built**: M9.2 `deploy/terraform/modules/postgres` (4 branches) + M9.3 `deploy/terraform/roots/{aws,gcp,azure}` (each consumes the module, emits Helm-overlay values, provisions the notarization key in a separate account/project/subscription). `pnpm run tf:fmt` validates. CI pipeline (`.github/workflows/ci.yml`) runs typecheck / eval-gate / api+dashboard tests / IaC-lint on push + PR. Deferred (cluster/cloud operator policy): service-mesh mTLS enforcement, per-tenant KMS lifecycle — see `deploy/README.md` "Still deferred".
- Full env + embedder config reference: `docs/CONFIGURATION.md`. Per-milestone history (M0 → M26): `docs/MILESTONES.md`. Architecture + implementation decisions: `docs/ARCHITECTURE.md`.
