# PHI/PII Log Audit (agentic, cloud-agnostic)

Cloud-agnostic agentic system that ingests cloud-provider logs, detects PHI/PII/secrets, maintains a tamper-evident audit ledger, and exposes a chat-over-audit dashboard for healthcare compliance analysts. See `docs/ARCHITECTURE.md`.

Current milestone: **M13 deterministic slices complete** (detector coverage expansion) on top of **M11** (eval suite) and **M10.1/M10.2/M10.3** (pluggable lexical search + WORM raw-PHI store). M13 closed the recorded PHI/secret gaps in `scanForPhi` (`lib/redact.ts`) under M11's precision discipline (a pattern ships only if it fires on the labeled fixture without tripping the benign operational-log precision controls); detector-phi and detector-secrets re-baselined at **1.0** with zero benign false positives. **M13.3 (word-collision names / NER) is DEFERRED** — needs a production NER model incompatible with the credential-free offline eval gate. Full per-milestone detail (M0 → M13, including M12 multi-tenant hardening and the deferred M13.3 NER slice) lives in `docs/MILESTONES.md`.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port comes from workflow env)
- `pnpm --filter @workspace/api-server run test` — vitest suite
- `pnpm --filter @workspace/api-server run eval` — on-demand eval suite (separate from `test`); deterministic detector/agent quality suites + regression gate vs `evals/baseline.json`. Detail + `eval:gate` / `eval:gate:llm` in `docs/CONFIGURATION.md` → "Eval gate".
- `pnpm run eval:gate` — credential-free CI quality gate; registered as the `eval-gate` validation command so it runs automatically on changes.
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL`, `SESSION_SECRET`. **All optional env + the cloud-aware embedder-selection table live in `docs/CONFIGURATION.md`** — one-line summary of each optional subsystem below:
  - Embedder (`EMBEDDING_PROVIDER`/`DEPLOYMENT_TARGET`/`EMBEDDING_DIM`): featurehash dev default; Bedrock/Vertex/Azure/TEI cloud providers; dim defaults to 256.
  - Lexical search (`SEARCH_PROVIDER=postgres|opensearch`, M10.1): only the BM25 leg moves to OpenSearch; no `DEPLOYMENT_TARGET` shortcut; redacted-only mirror.
  - Raw-evidence store (`RAW_EVIDENCE_PROVIDER=database|s3|gcs|azure-blob`, M10.2/M10.3): inline jsonb default vs external WORM (S3 Object Lock / GCS / Azure Blob); `GOVERNANCE` mode warns at boot; break-glass resolves ref with inline fallback.
  - Agent/LLM harness limits (`LLM_CALL_TIMEOUT_MS`/`TOOL_CALL_TIMEOUT_MS`/`AGENT_MAX_TOOL_CALLS`/`AGENT_MAX_OUTPUT_TOKENS_PER_TURN`/`AGENT_MAX_LLM_RETRIES`/`AGENT_LLM_RETRY_DELAY_MS`/`AGENT_MAX_TOOL_RESULT_BYTES`): per-call LLM + per-tool-handler hard timeouts, bounded tool budget, per-turn output-token circuit breaker, bounded retry, tool-result clamp; chat turn degrades to a deterministic redacted finding summary (never an error page or raw tool_call JSON) on LLM failure / cost cap / budget exhaustion, recorded as `degraded`/`degrade_reason`/`approx_output_tokens` in the `chat.agent_turn` ledger.
  - Step-up auth (`STEP_UP_DEV_TOKEN`, dev only).
  - Notarization (`NOTARIZATION_SECRET` + `NOTARIZATION_RETIRED_KEYS`): separate trust zone; dev fallback + WARN when unset.
  - Channel adapters (`CHANNEL_*`, M6): Slack / generic HMAC webhook / PagerDuty; inert without config; per-channel severity gating + rate limit.
  - Cloud LLM runtime (`LLM_PROVIDER=bedrock|vertex|azure-openai`): lazy SDKs; Azure is pure fetch.
  - Cloud log source (`LOG_SOURCE=cloudwatch`, M8): inert by default; standard AWS credential chain.

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
- Hybrid retrieval (BM25 + vector + RRF; `reconcileSearchIndex` boot backfill): `artifacts/api-server/src/lib/search.ts`
- Pluggable lexical search provider seam + config/factory/registry (M10.1, mirrors embedder-config): `artifacts/api-server/src/lib/search-config.ts` (`PostgresLexicalSearchProvider` default; `LexicalSearchProvider` interface)
- OpenSearch lexical provider (lazy `@opensearch-project/opensearch`, single shared index w/ mandatory tenant_id term-filter): `artifacts/api-server/src/lib/cloud-search.ts`
- Pluggable raw-evidence store seam + config/factory/registry + DB default store (M10.2/M10.3, mirrors embedder/search): `artifacts/api-server/src/lib/raw-evidence-store.ts` (`RawEvidenceStore` interface, `RawEvidenceRef {first,latest}`, `DatabaseRawEvidenceStore`)
- Cloud WORM raw-evidence stores (S3 Object Lock / GCS retention / Azure Blob immutability; lazy SDKs, thin mockable clients, tenant-scoped keys + get-time tenant/bucket check): `artifacts/api-server/src/lib/cloud-raw-evidence-stores.ts`
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
- Lexical (BM25) leg is pluggable (`SEARCH_PROVIDER`): Postgres FTS (dev) or OpenSearch (prod), behind a `LexicalSearchProvider` seam mirroring the embedder factory/registry. No `DEPLOYMENT_TARGET` shortcut — OpenSearch needs an explicit endpoint. Index updates are best-effort at ingest + reconciled at boot; only the redacted projection is mirrored (no raw PHI in the searchable tier).
- Agent context = hybrid top-K ∪ severity floor; full preloaded id list ledgered.
- Bounded tool loop (`MAX_TOOL_CALLS=2`); per-agent allow-list in `policy.ts`.
- Append-only ledger via advisory-locked writer + `ENABLE ALWAYS` triggers on `ledger_entries` AND `ledger_checkpoints`.
- Two-layer tamper-evidence: internal hash chain (hourly/weekly walks) + external HMAC checkpoints (5-min, separate trust zone).
- Raw evidence reachable through exactly one code path; `findingSafeColumns` is the compile-time gate.
- Raw-evidence storage is pluggable (`RAW_EVIDENCE_PROVIDER`): inline `raw_evidence` jsonb (dev) or external WORM object store (S3 Object Lock / GCS retention / Azure Blob immutability), behind a `RawEvidenceStore` seam mirroring the embedder/search factory. External stores write each occurrence as a NEW immutable object + record `{first,latest}` URIs in `raw_evidence_ref` (jsonb, race-safe COALESCE; out of `findingSafeColumns`); ingest two-phase keeps object I/O outside the dedup lock; break-glass resolves the ref server-side (tenant + bucket re-validated) with read-fallback to the legacy inline `raw_evidence` column when the ref can't be resolved (mixed-state rows). No `DEPLOYMENT_TARGET` shortcut; failed external write → finding committed, ref NULL, break-glass reports `raw_unresolved` (no inline fallback available).
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
- Agent loop is hardened + dependency-injected (`runAgentLoop` in `chat-agent.ts`, separated from DB retrieval): hard LLM-call + tool-handler timeouts (`with-timeout.ts`), bounded tool budget, per-turn output-token circuit breaker, bounded retry, duplicate-tool-call dedup, tool-result clamp. Any LLM failure / cost-cap / budget-exhaustion **degrades to a deterministic redacted finding summary** (threat model §DoS) — never an error page, never raw `tool_call` JSON to the user; `degraded`/`degrade_reason`/`approx_output_tokens` are ledgered on `chat.agent_turn`. Loop branches are unit-tested offline via injected fake runtime + tool executor.

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
- Full env + embedder config reference: `docs/CONFIGURATION.md`. Per-milestone history (M0 → M13): `docs/MILESTONES.md`. Architecture + implementation decisions: `docs/ARCHITECTURE.md`.
