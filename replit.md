# PHI/PII Log Audit (agentic, cloud-agnostic)

Cloud-agnostic agentic system that ingests cloud-provider logs, detects PHI/PII/secrets, maintains a tamper-evident audit ledger, and exposes a chat-over-audit dashboard for healthcare compliance analysts. See `docs/ARCHITECTURE.md`.

Current milestone: **M13** (deterministic detector slices) on top of the eval suite, pluggable lexical search + WORM raw-PHI store, and multi-tenant hardening. All optional cloud/security seams (NER, A2A mTLS, cloud embedders, brokers, etc.) are **default-inert** — they load no SDK and change no behavior unless their env is set, so the credential-free offline eval gate stays byte-identical.

**Docs:** full per-milestone history (M0 → M13) in `docs/MILESTONES.md`; architecture + implementation decisions in `docs/ARCHITECTURE.md`; optional env reference in `docs/CONFIGURATION.md`.

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
  - Raw-evidence tiering (`RAW_EVIDENCE_TIER_AGE_DAYS`/`RAW_EVIDENCE_TIER_INTERVAL_MS`/`RAW_EVIDENCE_TIER_BATCH_SIZE`, M10.4): opt-in leader-locked job that ages already-stored inline raw PHI out of the hot `findings.raw_evidence` column into the active external WORM store (get-after-put before nulling); default-inert unless the age is set AND an external store is active.
  - Memory eviction (`MEMORY_MAX_EMBEDDINGS_PER_TENANT`/`MEMORY_DECAY_HALF_LIFE_DAYS` def30/`MEMORY_EVICT_INTERVAL_MS` def6h, M10.5): opt-in leader-locked job that bounds the `finding_embeddings` derived pgvector cache by deterministic importance — group-dedup of old/resolved same-`(classification,subclass,source)` findings + per-tenant top-N count cap, never evicting critical+open; one shared `selectEvictions` policy gates both `backfillEmbeddings` (don't create) and eviction (remove) so boot never re-creates what eviction removed; prunes only the derived cache (audit record + lexical leg + break-glass untouched); default-inert unless the cap is set.
  - Agent/LLM harness limits (`LLM_CALL_TIMEOUT_MS`/`TOOL_CALL_TIMEOUT_MS`/`AGENT_MAX_TOOL_CALLS`/`AGENT_MAX_OUTPUT_TOKENS_PER_TURN`/`AGENT_MAX_LLM_RETRIES`/`AGENT_LLM_RETRY_DELAY_MS`/`AGENT_MAX_TOOL_RESULT_BYTES`): per-call LLM + per-tool-handler hard timeouts, bounded tool budget, per-turn output-token circuit breaker, bounded retry, tool-result clamp; chat turn degrades to a deterministic redacted finding summary (never an error page or raw tool_call JSON) on LLM failure / cost cap / budget exhaustion, recorded as `degraded`/`degrade_reason`/`approx_output_tokens` in the `chat.agent_turn` ledger.
  - Step-up auth (`STEP_UP_DEV_TOKEN`, dev only).
  - Notarization (`NOTARIZATION_SECRET` + `NOTARIZATION_RETIRED_KEYS`): separate trust zone; dev fallback + WARN when unset.
  - Channel adapters (`CHANNEL_*`, M6): Slack / generic HMAC webhook / PagerDuty; inert without config; per-channel severity gating + rate limit.
  - Cloud LLM runtime (`LLM_PROVIDER=bedrock|vertex|azure-openai`): lazy SDKs; Azure is pure fetch.
  - Cloud log source (`LOG_SOURCE=cloudwatch`, M8): inert by default; standard AWS credential chain.
  - Event-bus transport (`LOG_BUS_PROVIDER=memory|kafka|nats`): in-process `InMemoryLogBus` default; real Kafka/Redpanda (`kafkajs`) or NATS JetStream (`nats`) brokers for the `raw.logs` ingest topic, lazy SDKs, at-least-once (handler throw → no-ack → redeliver; ingest dedupes by fingerprint). No `DEPLOYMENT_TARGET` shortcut.

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5; **AG-UI** (`@ag-ui/encoder` / `@ag-ui/core`) for UI↔agent SSE; **A2A** (`@a2a-js/sdk`) for agent↔agent (Supervisor → Triage/Verifier)
- DB: PostgreSQL + Drizzle ORM, pgvector 0.8
- Validation: Zod v4, `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- LLM: Gemini 2.5 Flash via Replit AI Integrations (no user key required)

## Where things live

- API entry: `artifacts/api-server/src/index.ts` (bootstrap → embedding backfill → chain verify → start chain verifier + notarizer → wire ingest pipeline → listen)
- Chat agent loop: `artifacts/api-server/src/lib/chat-agent.ts`
- A2A agent-to-agent protocol (`@a2a-js/sdk`): `artifacts/api-server/src/lib/a2a/` — `protocol.ts` (Zod wire schemas + `AgentInvoker` seam + loopback paths), `auth.ts` (shared-secret bearer + `timingSafeEqual`, dev fallback from `SESSION_SECRET`+WARN), `cards.ts` (Triage/Verifier Agent Cards), `executors.ts` (Triage/Verifier `AgentExecutor`s that parse+strip the inbound finding then wrap `runTriageAgent`/`runVerifierAgent`), `server.ts` (`mountA2AAgents` — card + JSON-RPC routes under `/a2a/triage`,`/a2a/verify`, both behind `a2aAuthMiddleware`), `client.ts` (`A2AAgentInvoker` over loopback handling Message-or-Task results + `inProcessAgentInvoker` test seam + `getAgentInvoker()`). Supervisor calls agents only through `getAgentInvoker()`.
- AG-UI SSE encoder seam (`@ag-ui/encoder`): `artifacts/api-server/src/lib/sse.ts` (emits official AG-UI `EventType` frames; PHI-safe write seam + heartbeat preserved); dashboard consumer: `artifacts/dashboard/src/pages/chat.tsx` (parses `EventType` from `@ag-ui/core`).
- Tool registry (MCP-shaped): `artifacts/api-server/src/lib/tools.ts`
- Hybrid retrieval (BM25 + vector + RRF; `reconcileSearchIndex` boot backfill): `artifacts/api-server/src/lib/search.ts`
- Pluggable lexical search provider seam + config/factory/registry (M10.1, mirrors embedder-config): `artifacts/api-server/src/lib/search-config.ts` (`PostgresLexicalSearchProvider` default; `LexicalSearchProvider` interface)
- OpenSearch lexical provider (lazy `@opensearch-project/opensearch`, single shared index w/ mandatory tenant_id term-filter): `artifacts/api-server/src/lib/cloud-search.ts`
- Pluggable raw-evidence store seam + config/factory/registry + DB default store (M10.2/M10.3, mirrors embedder/search): `artifacts/api-server/src/lib/raw-evidence-store.ts` (`RawEvidenceStore` interface, `RawEvidenceRef {first,latest}`, `DatabaseRawEvidenceStore`)
- Cloud WORM raw-evidence stores (S3 Object Lock / GCS retention / Azure Blob immutability; lazy SDKs, thin mockable clients, tenant-scoped keys + get-time tenant/bucket check): `artifacts/api-server/src/lib/cloud-raw-evidence-stores.ts`
- Raw-evidence tiering lifecycle (M10.4, opt-in leader-locked hot→WORM aging job; default-inert unless `RAW_EVIDENCE_TIER_AGE_DAYS` set AND external store active; get-after-put before nulling inline `raw_evidence`; ledgers `raw_evidence.tiered`/`tier_failed` with finding id + provider only): `artifacts/api-server/src/lib/raw-evidence-tiering.ts`
- Vector-memory consolidation + importance-decay eviction (M10.5, opt-in leader-locked job bounding the `finding_embeddings` derived cache; pure `computeImportance`/`selectEvictions` shared by `backfillEmbeddings` create-gate AND eviction remove-gate so boot never recreates; group-dedup + per-tenant count cap, hard floor on critical+open; default-inert unless `MEMORY_MAX_EMBEDDINGS_PER_TENANT` set; ledgers `memory.evicted`/`memory.evict_failed` with counts + policy params only): `artifacts/api-server/src/lib/memory-eviction.ts`; backfill create-gate lives in `artifacts/api-server/src/lib/search.ts` (`backfillEmbeddings` `memoryPolicy?` opt)
- Embedder interface + dev embedder: `artifacts/api-server/src/lib/embeddings.ts`
- Cloud embedders (Bedrock/Vertex/Azure/TEI, lazy-loaded): `artifacts/api-server/src/lib/cloud-embedders.ts`
- Cloud LLM runtimes + PHI guard wrapper (Bedrock Converse / Vertex generateContent / Azure OpenAI Chat, lazy-loaded): `artifacts/api-server/src/lib/cloud-llm-runtimes.ts`; env factory: `artifacts/api-server/src/lib/llm-runtime-config.ts`
- Log ingestion (M3): `artifacts/api-server/src/lib/log-source.ts` (LogRecord + LogSource interface + StaticFixtureLogSource; re-exports `CloudwatchLogSource` from cloud-log-sources.ts), `artifacts/api-server/src/lib/log-bus.ts` (LogBus interface + InMemoryLogBus stub for Kafka/NATS), `artifacts/api-server/src/lib/ingest.ts` (detector → redact → fingerprint upsert → ledger), `artifacts/api-server/src/routes/ingest.ts` (`POST /api/admin/ingest/replay` dev/demo trigger)
- Pluggable event-bus transport seam + config/factory/registry (mirrors embedder/search/raw-evidence factories): `artifacts/api-server/src/lib/log-bus-config.ts` (`LOG_BUS_PROVIDER` env factory, discriminated-union `LogBusConfig`, `getLogBus`/`setLogBus`/`initLogBusFromEnv`/`resetLogBusForTests` registry — lazy-defaults to the in-memory singleton); broker impls in `artifacts/api-server/src/lib/cloud-log-bus.ts` (`BrokerDriver` seam + one `BrokeredLogBus`; `createKafkaDriver` lazy `kafkajs`, `createNatsDriver` lazy `nats` JetStream); wire codec (`encodeLogRecord`/`decodeLogRecord`, Zod-validated) + optional `start?()`/`stop?()` lifecycle live on the `LogBus` interface in `lib/log-bus.ts`.
- Real CloudWatch Logs source + checkpoint store (M8): `artifacts/api-server/src/lib/cloud-log-sources.ts` (`CloudwatchLogSource` w/ lazy `@aws-sdk/client-cloudwatch-logs`, `DbCheckpointStore` + `InMemoryCheckpointStore`, env-driven `buildCloudwatchSourceFromEnv`), `lib/db/src/schema/log-source-checkpoints.ts` (mutable cursor table — `source_name` PK, `tenant_id`, `last_event_ts` bigint ms, `updated_at`), DDL mirrored in `lib/db/src/setup-sql.ts` so first boot creates the table.
- Chat agent + LLM runtime seam (M9.5): `artifacts/api-server/src/lib/chat-agent.ts` (`runChatTurn` calls `streamFromRuntime(getLlmRuntime(), ...)`); runtime adapter + `streamFromRuntime` helper in `cloud-llm-runtimes.ts` / `llm-runtime-config.ts`.
- Inline redaction helper (`redactInline`) + Stage-1 `scanForPhi` + async `scanForPhiWithNer` (Stage-1 ∪ NER): `artifacts/api-server/src/lib/redact.ts`
- Optional Stage-2 NER detector seam (M13.3 production path; mirrors embedder/search/raw-evidence factories): `artifacts/api-server/src/lib/ner.ts` (`NerProvider` interface + default `NoopNerProvider` + `nerHit`), `artifacts/api-server/src/lib/ner-config.ts` (`NER_PROVIDER` env factory/registry/`initNerProviderFromEnv`/`getNerProviderOrNull`), `artifacts/api-server/src/lib/cloud-ner.ts` (lazy AWS Comprehend / GCP DLP / Azure Language providers). Default-inert; wired into the async ingest detection path only.
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
- Lexical (BM25) leg is pluggable (`SEARCH_PROVIDER`): Postgres FTS (dev) or OpenSearch (prod), behind a `LexicalSearchProvider` seam; redacted-only mirror, no raw PHI in the searchable tier.
- Agent context = hybrid top-K ∪ severity floor; full preloaded id list ledgered.
- Bounded tool loop (`MAX_TOOL_CALLS=2`); per-agent allow-list in `policy.ts`.
- Append-only ledger via advisory-locked writer + `ENABLE ALWAYS` triggers on `ledger_entries` AND `ledger_checkpoints`.
- Two-layer tamper-evidence: internal hash chain (hourly/weekly walks) + external HMAC checkpoints (5-min, separate trust zone).
- Raw evidence reachable through exactly one code path; `findingSafeColumns` is the compile-time gate.
- Raw-evidence storage is pluggable (`RAW_EVIDENCE_PROVIDER`): inline `raw_evidence` jsonb (dev) or external WORM object store (S3 Object Lock / GCS / Azure Blob), behind a `RawEvidenceStore` seam; WORM stores record `{first,latest}` URIs in `raw_evidence_ref` (out of `findingSafeColumns`), break-glass resolves server-side with inline fallback.
- Step-up cookie domain-separated from session cookie via per-purpose HMAC label.
- Two-person rule on critical-severity break-glass; `requires_second_approval` frozen at grant-creation; DB-level `bg_no_self_approval`.
- Analyst free-text scanned before it lands in the immutable ledger (`validateLedgerSafeText`).
- Ingest is interface-first; `LogBus` + `LogSource` seams; cloud SDKs lazy-imported. The `LogBus` is pluggable (`LOG_BUS_PROVIDER=memory|kafka|nats`): in-process `InMemoryLogBus` (dev) or a real broker (Kafka/Redpanda via `kafkajs`, NATS JetStream via `nats`) behind a `BrokerDriver` seam; default-inert, lazy SDKs, no `DEPLOYMENT_TARGET` shortcut. Wire records are JSON+Zod-revalidated on consume (poison → drop); delivery is at-least-once (handler throw → no-ack → broker redelivers; ingest dedupes by fingerprint). `raw.logs` is a pre-detection transport, so raw payloads ride it by design — broker TLS/SASL is the in-transit control.
- Ingest does defense-in-depth on redaction; regression → critical alert + opaque placeholder.
- Ingest dedupes by fingerprint; `finding.created` fires on first observation only.
- Event-type-driven alerting + mechanical coverage scan in CI.
- Real CloudWatch source behind same `LogSource` seam; `DbCheckpointStore` is mutable by design (cursor only — audit anchor stays locked).
- Channel dispatch: 5 hard guarantees (outbound PHI hard gate, self-recursion guard, per-channel rate limit, webhook host allow-list + HMAC, adapter failure isolation).
- Chat agent routes through the `LlmAgentRuntime` seam (M9.5) so `LLM_PROVIDER` controls every cloud LLM call (chat included); `PhiGuardLlmRuntime` scans multi-turn history; `agent_identity.model_id` records the effective model.
- Agent loop is hardened + dependency-injected (`runAgentLoop`): hard LLM/tool timeouts, bounded tool budget, per-turn output-token circuit breaker, bounded retry, dedup, result clamp. Any LLM failure / cost-cap / budget-exhaustion **degrades to a deterministic redacted finding summary** (never an error page or raw `tool_call` JSON), ledgered on `chat.agent_turn`.
- Specialist agents (Triage, Verifier) speak the **official A2A protocol** (`@a2a-js/sdk`, Agent Cards + JSON-RPC `message/send`); Supervisor calls them through the `AgentInvoker` seam (loopback in prod, in-process in tests). Only the redacted `FindingSafe` projection crosses the wire (executors parse+strip the inbound payload); returned rationale is re-scanned before the ledger. Endpoints are loopback-only, shared-secret bearer + signed-JWT caller-identity/ABAC authed, with an optional mTLS transport layer (`A2A_REQUIRE_MTLS`) that 403s + ledgers `a2a.transport_rejected` (fixed route + static reason only). When mTLS is on, the transport also extracts the peer's cert identity (SAN/CN/DN, direct TLS or ingress PEM/DN header; `a2a/peer-identity.ts`) and enforces two opt-in per-claim ABAC controls: an allow-list (`A2A_MTLS_ALLOWED_PEERS` → reason `peer_not_allowed`/`peer_identity_unavailable`) and a cert↔caller-JWT-subject binding (`A2A_MTLS_PEER_BINDINGS` → reason `peer_subject_mismatch`), all reusing `a2a.transport_rejected` and default-inert. UI↔agent chat streams **official AG-UI events** via `@ag-ui/encoder`.

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
- DB integration tests pollute the shared dev ledger with `system.integration_test_marker` rows + sequence gaps + occasional forged checkpoint rows (deferred isolation per M1.9). New tests that walk ledger or checkpoints must scope to just-created rows (pass `sinceSeq` / filter by id), not assume the table is clean. The scoping vocabulary is centralized in `artifacts/api-server/src/test-support/ledger-harness.ts` (`ledgerHeadSeq()` to capture head-seq before the code under test, `uniq()` for random source/fingerprint suffixes, `uniqueTenant(label)` for a per-test tenant id that cannot collide with the seed `default` tenant) — import from there rather than re-declaring per file. Vitest still runs with `fileParallelism: false` (configured in `artifacts/api-server/vitest.config.ts`): the harness reduces coupling but does NOT make parallel files safe — `appendLedger`'s single advisory lock + the notarization head-seq idempotency invariant are a genuine serialization requirement, so it stays serialized by design, not just as a pollution workaround.
- When adding a new `eventType:` literal, also add it to `ALERT_RULES` or `NOT_ALERTABLE` in `alerts.ts` in the same change, or `event-type-coverage.test.ts` will fail.

## Pointers

- See `.local/skills/pnpm-workspace/SKILL.md` for workspace structure, TypeScript setup, and package details.
- Agent continuity / crash-recovery notes (gitignored): `.agent-context.md`.
- Deployment (M9.1 Helm + Docker, M9.4 Replit deploy path): `deploy/README.md`. Per-cloud overlays: `deploy/helm/phi-audit/values-{aws,gcp,azure}.yaml`. Terraform IaC is **built**: M9.2 `deploy/terraform/modules/postgres` (4 branches) + M9.3 `deploy/terraform/roots/{aws,gcp,azure}` (each consumes the module, emits Helm-overlay values, provisions the notarization key in a separate account/project/subscription). `pnpm run tf:fmt` validates. Deferred: CI/CD, service-mesh mTLS, per-tenant KMS lifecycle.
- Full env + embedder config reference: `docs/CONFIGURATION.md`. Per-milestone history (M0 → M13): `docs/MILESTONES.md`. Architecture + implementation decisions: `docs/ARCHITECTURE.md`.
