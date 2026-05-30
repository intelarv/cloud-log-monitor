# PHI/PII Log Audit (agentic, cloud-agnostic)

Cloud-agnostic agentic system that ingests cloud-provider logs, detects PHI/PII/secrets, maintains a tamper-evident audit ledger, and exposes a chat-over-audit dashboard for healthcare compliance analysts. See `docs/ARCHITECTURE.md`.

Current milestone: **M9 complete** (M9.1 Helm chart, M9.2 Postgres TF module, M9.3 per-cloud TF roots, M9.4 Replit deploy path, M9.5 chat-agent via runtime seam, helm CI matrix). Net effect: operator can `tofu apply` the AWS/GCP/Azure root in `deploy/terraform/roots/{aws,gcp,azure}/`, get an EKS/GKE/AKS cluster + RDS/Cloud SQL/Flexible Server (via M9.2 module) + IRSA/WI/MI bindings + secrets-with-separate-account-KMS-for-NOTARIZATION_SECRET (threat_model §23.2), then `helm install` the M9.1 chart against it. `LLM_PROVIDER` / `DEPLOYMENT_TARGET` controls every LLM call — chat included — via the `LlmAgentRuntime` seam. Test suite: **226 tests** passing. Per-milestone history in `docs/MILESTONES.md`; planned M10/M11/M12 (OpenSearch+S3, eval suite, multi-tenant hardening) in the same file's "Planned (backlog)" section.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port comes from workflow env)
- `pnpm --filter @workspace/api-server run test` — vitest suite
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL`, `SESSION_SECRET`
- Optional embedder config (see "Embedder selection" below): `EMBEDDING_PROVIDER`, `DEPLOYMENT_TARGET`, `EMBEDDING_MODEL`, `EMBEDDING_DIM` plus provider-specific creds.
- Optional step-up auth (dev): `STEP_UP_DEV_TOKEN` (default `dev-stepup`, ≥8 chars). Replace with a TOTP/WebAuthn verifier in production.
- Optional notarization: `NOTARIZATION_SECRET` (≥16 chars, held in a *separate* trust zone from `SESSION_SECRET` — KMS in a separate cloud account per §23.2). Unset → SESSION_SECRET-derived dev fallback + boot WARN. Rotation: set `NOTARIZATION_RETIRED_KEYS={"<old_key_id>":"<old_secret>"}` so existing checkpoints keep verifying after `ACTIVE_KEY_ID` is bumped.
- Optional channel adapters (M6): `CHANNEL_SLACK_WEBHOOK_URL` [+ `CHANNEL_SLACK_MIN_SEVERITY=warning|high|critical`]; `CHANNEL_WEBHOOK_URL` + `CHANNEL_WEBHOOK_SECRET` (≥16) + `CHANNEL_WEBHOOK_ALLOWED_HOSTS` (CSV) [+ `CHANNEL_WEBHOOK_MIN_SEVERITY`]; `CHANNEL_RATE_LIMIT_PER_MINUTE` (default 30). Channels are inert without these.
- Optional cloud LLM runtime: `LLM_PROVIDER=bedrock|vertex|azure-openai` (or `DEPLOYMENT_TARGET=aws|gcp|azure` shortcut). Per-provider: `bedrock` → AWS chain + `AWS_REGION` (+ `LLM_DEFAULT_MODEL`, default Claude 3.5 Haiku); `vertex` → `GCP_PROJECT_ID` + `GCP_LOCATION` (default `us-central1`) + ADC; `azure-openai` → `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` + `AZURE_OPENAI_DEPLOYMENT` (+ `AZURE_OPENAI_API_VERSION`). SDKs lazy-loaded (`@aws-sdk/client-bedrock-runtime`, `google-auth-library`); Azure is pure fetch.
- Optional cloud log source (M8): `LOG_SOURCE=cloudwatch` + `CLOUDWATCH_TENANT_ID` + `CLOUDWATCH_LOG_GROUPS` (CSV) + `AWS_REGION` [+ `CLOUDWATCH_POLL_INTERVAL_MS` (default 5000), `CLOUDWATCH_LOOKBACK_MS` (default 300000, only used when no checkpoint exists yet for a group)]. SDK is lazy-loaded; without `LOG_SOURCE=cloudwatch` no source is started. Operators must `pnpm --filter @workspace/api-server add @aws-sdk/client-cloudwatch-logs` before enabling. Credentials follow the standard AWS chain (IRSA on EKS, env, instance role).

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
- DB: PostgreSQL + Drizzle ORM, pgvector 0.8
- Validation: Zod v4, `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- LLM: Gemini 2.5 Flash via Replit AI Integrations (no user key required)

## Where things live

- API entry: `artifacts/api-server/src/index.ts` (bootstrap → embedding backfill → chain verify → start chain verifier + notarizer → wire ingest pipeline → listen)
- Chat agent loop: `artifacts/api-server/src/lib/chat-agent.ts`
- Tool registry (MCP-shaped): `artifacts/api-server/src/lib/tools.ts`
- Hybrid retrieval (BM25 + vector + RRF): `artifacts/api-server/src/lib/search.ts`
- Embedder interface + dev embedder: `artifacts/api-server/src/lib/embeddings.ts`
- Cloud embedders (Bedrock/Vertex/Azure/TEI, lazy-loaded): `artifacts/api-server/src/lib/cloud-embedders.ts`
- Cloud LLM runtimes + PHI guard wrapper (Bedrock Converse / Vertex generateContent / Azure OpenAI Chat, lazy-loaded): `artifacts/api-server/src/lib/cloud-llm-runtimes.ts`; env factory: `artifacts/api-server/src/lib/llm-runtime-config.ts`
- Log ingestion (M3): `artifacts/api-server/src/lib/log-source.ts` (LogRecord + LogSource interface + StaticFixtureLogSource; re-exports `CloudwatchLogSource` from cloud-log-sources.ts), `artifacts/api-server/src/lib/log-bus.ts` (LogBus interface + InMemoryLogBus stub for Kafka/NATS), `artifacts/api-server/src/lib/ingest.ts` (detector → redact → fingerprint upsert → ledger), `artifacts/api-server/src/routes/ingest.ts` (`POST /api/admin/ingest/replay` dev/demo trigger)
- Real CloudWatch Logs source + checkpoint store (M8): `artifacts/api-server/src/lib/cloud-log-sources.ts` (`CloudwatchLogSource` w/ lazy `@aws-sdk/client-cloudwatch-logs`, `DbCheckpointStore` + `InMemoryCheckpointStore`, env-driven `buildCloudwatchSourceFromEnv`), `lib/db/src/schema/log-source-checkpoints.ts` (mutable cursor table — `source_name` PK, `tenant_id`, `last_event_ts` bigint ms, `updated_at`), DDL mirrored in `lib/db/src/setup-sql.ts` so first boot creates the table.
- Chat agent + LLM runtime seam (M9.5): `artifacts/api-server/src/lib/chat-agent.ts` (`runChatTurn` calls `streamFromRuntime(getLlmRuntime(), ...)`); runtime adapter + `streamFromRuntime` helper in `cloud-llm-runtimes.ts` / `llm-runtime-config.ts`.
- Inline redaction helper (`redactInline`): `artifacts/api-server/src/lib/redact.ts`
- Embedder factory + env config + registry: `artifacts/api-server/src/lib/embedder-config.ts`
- Per-agent tool allow-list + tool-arg revalidation: `artifacts/api-server/src/lib/policy.ts`
- Free-text ledger-payload guard (justification/approval_note/step-up reason): `artifacts/api-server/src/lib/text-policy.ts`
- Agent prompts (version-pinned): `artifacts/api-server/src/lib/prompts.ts`
- Ledger writer + chain walk: `artifacts/api-server/src/lib/ledger.ts`
- Periodic chain verifier + notarization scheduler (per-scope advisory leader lock): `artifacts/api-server/src/lib/chain-verifier.ts`
- HMAC notarization (canonical-JSON signing, retired-key registry): `artifacts/api-server/src/lib/notarization.ts`
- Event-type alert routing + post-commit hook: `artifacts/api-server/src/lib/alerts.ts`
- Mechanical event-type coverage scan: `artifacts/api-server/src/lib/event-type-coverage.test.ts`
- Channel router + Slack/webhook adapters + dispatch hook (M6): `artifacts/api-server/src/lib/channels/{types,router,dispatch,index,adapters/slack,adapters/webhook}.ts`
- Session + step-up cookies (HMAC, domain-separated): `artifacts/api-server/src/lib/auth.ts`
- Step-up + break-glass admin routes: `artifacts/api-server/src/routes/admin.ts`, `artifacts/api-server/src/routes/auth.ts`
- Ledger admin route (incl. `GET /api/admin/ledger/checkpoints?verify=1`): `artifacts/api-server/src/routes/ledger.ts`
- Per-user rate limiters (chat, tools, break-glass, step-up): `artifacts/api-server/src/app.ts`
- DB schema (source of truth): `lib/db/src/schema/*.ts` — `findingSafeColumns` / `FindingSafe` in `findings.ts` is the compile-time gate that keeps `raw_evidence` out of non-break-glass reads.
- DB setup SQL (RLS, pgvector, FTS, triggers, break-glass grants table, `ledger_checkpoints` + ENABLE ALWAYS triggers, F-CANARY raw backfill): `lib/db/src/setup-sql.ts`
- Seed (10 findings + canary w/ raw payload + genesis): `lib/db/src/seed.ts`
- Threat model: `threat_model.md`

## Architecture decisions

Moved to `docs/ARCHITECTURE.md` **Appendix A — Implementation decisions log** to keep this file scannable. One-line index of what lives there (newest last):

- Pluggable + PHI-guarded embedder; cloud-aware factory; deterministic dev feature-hash.
- Hybrid retrieval = BM25 ∪ pgvector cosine, fused via RRF (k=60).
- Agent context = hybrid top-K ∪ severity floor; full preloaded id list ledgered.
- Bounded tool loop (`MAX_TOOL_CALLS=2`); per-agent allow-list in `policy.ts`.
- Append-only ledger via advisory-locked writer + `ENABLE ALWAYS` triggers on `ledger_entries` AND `ledger_checkpoints`.
- Two-layer tamper-evidence: internal hash chain (hourly/weekly walks) + external HMAC checkpoints (5-min, separate trust zone).
- Raw evidence reachable through exactly one code path; `findingSafeColumns` is the compile-time gate.
- Step-up cookie domain-separated from session cookie via per-purpose HMAC label.
- Two-person rule on critical-severity break-glass; `requires_second_approval` frozen at grant-creation; DB-level `bg_no_self_approval`.
- Analyst free-text scanned before it lands in the immutable ledger (`validateLedgerSafeText`).
- Ingest is interface-first; `LogBus` + `LogSource` seams; cloud SDKs lazy-imported.
- Ingest does defense-in-depth on redaction; regression → critical alert + opaque placeholder.
- Ingest dedupes by fingerprint; `finding.created` fires on first observation only.
- Event-type-driven alerting + mechanical coverage scan in CI.
- Real CloudWatch source behind same `LogSource` seam; `DbCheckpointStore` is mutable by design (cursor only — audit anchor stays locked).
- Channel dispatch: 5 hard guarantees (outbound PHI hard gate, self-recursion guard, per-channel rate limit, webhook host allow-list + HMAC, adapter failure isolation).
- Chat agent routes through `LlmAgentRuntime` seam (M9.5) so `LLM_PROVIDER` controls every cloud LLM call — chat included; native streaming on Bedrock/Vertex/Azure; `PhiGuardLlmRuntime.generateStream` scans multi-turn history at first `next()`; `agent_identity.model_id` records the runtime's effective `done.modelId`.

## Product

- Auth (session cookies), per-tenant chat sessions, AG-UI SSE chat over findings.
- Findings browse + single-finding read, all RLS-scoped, raw evidence excluded by safe projection.
- Hybrid search exposed to the chat agent as a tool; agents cite findings as `[F:<id>]`.
- Tool-arg revalidation refuses canary tokens, PHI, oversize payloads, or malformed ids on every agent tool call; refusals materialize as critical/high incident findings.
- Step-up auth (`POST /api/auth/step-up`) + break-glass raw-PHI view (`POST /api/admin/break-glass/grants`, `GET /api/admin/findings/:id/raw`) with per-access ledger events. Critical-severity grants require a second-analyst approval (`POST /api/admin/break-glass/grants/:id/approve`, `GET /api/admin/break-glass/pending-approvals`).
- Per-user rate limits on chat, tools, and break-glass issuance; per-IP on login + step-up.
- Tamper-evident ledger over every chat turn, every input PHI refusal, every agent output PHI detection, every finding create, every step-up grant/denial, every break-glass grant + approval + raw-PHI read, every chain walk, and every notarization checkpoint. `GET /api/admin/ledger/verify` walks the chain on demand; `GET /api/admin/ledger/checkpoints?verify=1` walks the external notarization.
- Honeypot canary finding traps prompt-injection attempts in chat input and tool arguments.

## User preferences

_None recorded._

## Gotchas

- Always run `pnpm run typecheck` from the repo root after schema or tool changes — leaf workspace packages are only checked there.
- Bootstrap is idempotent: `CREATE EXTENSION IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`, embedding backfill skips rows whose `embedder_version` matches, F-CANARY `raw_evidence` backfill is conditional on `IS NULL`, and `CREATE TABLE IF NOT EXISTS ledger_checkpoints` runs *before* the ENABLE ALWAYS trigger block in `setup-sql.ts` so boot ordering is correct. Safe to restart freely.
- Drizzle's `sql\`... = ANY(${ids})\`` interpolates arrays as N separate params and fails at runtime. Use `inArray(col, ids)` instead.
- `db.execute(sql\`...\`)` returns a QueryResult; use `.rows[0]`, not array destructuring on the result.
- Drizzle wraps trigger-raised errors inside `"Failed query: ..."`, so test assertions should match the underlying cause string, not the outer envelope.
- Don't add to root `tsconfig.json` references — that's libs-only. Artifacts are leaf workspace packages.
- **Never `.select().from(findingsTable)` outside `routes/admin.ts`'s raw endpoint** — use `.select(findingSafeColumns)` so `rawEvidence` cannot enter an LLM prompt or SSE frame. The `FindingSafe` type is the compile-time guard; if you find yourself typing a non-admin result as `Finding`, you've widened the protection away.
- Rate-limiter `keyGenerator` must use `ipKeyGenerator(req.ip)` (not `req.ip` directly) for IPv6 safety — `express-rate-limit` v8 enforces this.
- DB integration tests pollute the shared dev ledger with `system.integration_test_marker` rows + sequence gaps + occasional forged checkpoint rows (deferred isolation per M1.9). New tests that walk ledger or checkpoints must scope to just-created rows (pass `sinceSeq` / filter by id), not assume the table is clean. Vitest runs with `fileParallelism: false` (configured in `artifacts/api-server/vitest.config.ts`) for the same reason — cross-file parallel writes used to race the notarization idempotency invariant.
- When adding a new `eventType:` literal, also add it to `ALERT_RULES` or `NOT_ALERTABLE` in `alerts.ts` in the same change, or `event-type-coverage.test.ts` will fail.

## Pointers

- See `.local/skills/pnpm-workspace/SKILL.md` for workspace structure, TypeScript setup, and package details.
- Agent continuity / crash-recovery notes (gitignored): `.agent-context.md`.
- Deployment (M9.1 Helm + Docker, M9.4 Replit deploy path): `deploy/README.md`. Per-cloud overlays: `deploy/helm/phi-audit/values-{aws,gcp,azure}.yaml`. Terraform (M9.2 + M9.3) deferred.

---

Milestone history (M0 → current) lives in `docs/MILESTONES.md` to keep this file scannable.
