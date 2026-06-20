# Code Map — Where things live

A per-component index of the codebase. `replit.md` keeps only the top-level entry
points; this file is the full map. Architecture rationale for each item lives in
`docs/ARCHITECTURE.md` (Appendix A — Implementation decisions log); per-milestone
history in `docs/MILESTONES.md`; optional-env reference in `docs/CONFIGURATION.md`.

## API server

- API entry: `artifacts/api-server/src/index.ts` (bootstrap → embedding backfill → chain verify → start chain verifier + notarizer → wire ingest pipeline → listen)
- Chat agent loop: `artifacts/api-server/src/lib/chat-agent.ts`
- A2A agent-to-agent protocol (`@a2a-js/sdk`): `artifacts/api-server/src/lib/a2a/` — `protocol.ts` (Zod wire schemas + `AgentInvoker` seam + loopback paths), `auth.ts` (shared-secret bearer + `timingSafeEqual`, dev fallback from `SESSION_SECRET`+WARN), `cards.ts` (Triage/Verifier Agent Cards), `executors.ts` (Triage/Verifier `AgentExecutor`s that parse+strip the inbound finding then wrap `runTriageAgent`/`runVerifierAgent`), `server.ts` (`mountA2AAgents` — card + JSON-RPC routes under `/a2a/triage`,`/a2a/verify`, both behind `a2aAuthMiddleware`), `client.ts` (`A2AAgentInvoker` over loopback handling Message-or-Task results + `inProcessAgentInvoker` test seam + `getAgentInvoker()`). Supervisor calls agents only through `getAgentInvoker()`.
- Multi-agent supervisor + workflow-engine seam (`WORKFLOW_ENGINE`): `artifacts/api-server/src/lib/agents/` — `supervisor.ts` (thin facade: `enqueueReview`/`startAgentSupervisor`/`maybeEnqueueReviewFromLedger` dispatch through `getWorkflowEngine()`), `review-orchestration.ts` (PURE, type-only imports: `ReviewActivities` interface + `runReviewOrchestration` driver + `ReviewJob` — shared by both engines), `review-steps.ts` (`inProcessReviewActivities` — the real DB/LLM/PHI-scan/ledger/budget activity impls, payloads byte-identical to the old `reviewOne`), `agent-budget.ts` (per-tenant daily-token budget map + `__*ForTest` hooks), `workflow-engine.ts` (`WorkflowEngine` interface, `InProcessWorkflowEngine` CONCURRENCY=2, env config loader + factory + registry + `initWorkflowEngineFromEnv`), `temporal-engine.ts` (`TemporalWorkflowEngine` + injectable `TemporalRuntimeFactory` lazy-loading `@temporalio/*`; `workflowIdFor` = `review-`+sha256(length-prefixed `{tenant,finding}`).slice(0,32); AlreadyStarted swallowed), `temporal-workflows.ts` (deterministic workflow via `proxyActivities`, bundled as a separate esbuild entry with `@temporalio/*` external). Default `inprocess` is byte-identical; Temporal is opt-in + default-inert.
- AG-UI SSE encoder seam (`@ag-ui/encoder`): `artifacts/api-server/src/lib/sse.ts` (emits official AG-UI `EventType` frames; PHI-safe write seam + heartbeat preserved); dashboard consumer: `artifacts/dashboard/src/pages/chat.tsx` (parses `EventType` from `@ag-ui/core`).
- Tool registry (MCP-shaped): `artifacts/api-server/src/lib/tools.ts`

## Retrieval & embeddings

- Hybrid retrieval (BM25 + vector + RRF; `reconcileSearchIndex` boot backfill): `artifacts/api-server/src/lib/search.ts`
- Pluggable lexical search provider seam + config/factory/registry (M10.1, mirrors embedder-config): `artifacts/api-server/src/lib/search-config.ts` (`PostgresLexicalSearchProvider` default; `LexicalSearchProvider` interface)
- OpenSearch lexical provider (lazy `@opensearch-project/opensearch`, single shared index w/ mandatory tenant_id term-filter): `artifacts/api-server/src/lib/cloud-search.ts`
- Embedder interface + dev embedder: `artifacts/api-server/src/lib/embeddings.ts`
- Cloud embedders (Bedrock/Vertex/Azure/TEI, lazy-loaded): `artifacts/api-server/src/lib/cloud-embedders.ts`
- Embedder factory + env config + registry: `artifacts/api-server/src/lib/embedder-config.ts`
- Chat memory window assembly (M18 recency + M19 semantic + M21 hybrid): `artifacts/api-server/src/lib/chat-memory.ts` (`assembleRecallWindow`, token+turn budgets) + `artifacts/api-server/src/lib/chat-recall.ts` (`chat_message_embeddings` upsert, vector cosine recall, M21 BM25 lexical leg + RRF fuse `k=60` behind `CHAT_MEMORY_HYBRID_RECALL`; falls back to recency on any failure).
- Chat-embeddings tenant-partition switch (M22, independent of the finding-embeddings switch): `artifacts/api-server/src/lib/embeddings-partition-config.ts` (`CHAT_EMBEDDINGS_TENANT_PARTITIONING` reader, conflict-target selection, `reconcileChatEmbeddingsPartitioningFromDb` boot reconcile trusting the live catalog).

## Raw-evidence storage & lifecycle

- Pluggable raw-evidence store seam + config/factory/registry + DB default store (M10.2/M10.3, mirrors embedder/search): `artifacts/api-server/src/lib/raw-evidence-store.ts` (`RawEvidenceStore` interface, `RawEvidenceRef {first,latest}`, `DatabaseRawEvidenceStore`)
- Cloud WORM raw-evidence stores (S3 Object Lock / GCS retention / Azure Blob immutability; lazy SDKs, thin mockable clients, tenant-scoped keys + get-time tenant/bucket check): `artifacts/api-server/src/lib/cloud-raw-evidence-stores.ts`
- Raw-evidence tiering lifecycle (M10.4, opt-in leader-locked hot→WORM aging job; default-inert unless `RAW_EVIDENCE_TIER_AGE_DAYS` set AND external store active; get-after-put before nulling inline `raw_evidence`; ledgers `raw_evidence.tiered`/`tier_failed` with finding id + provider only): `artifacts/api-server/src/lib/raw-evidence-tiering.ts`
- Vector-memory consolidation + importance-decay eviction (M10.5, opt-in leader-locked job bounding the `finding_embeddings` derived cache; pure `computeImportance`/`selectEvictions` shared by `backfillEmbeddings` create-gate AND eviction remove-gate so boot never recreates; group-dedup + per-tenant count cap, hard floor on critical+open; default-inert unless `MEMORY_MAX_EMBEDDINGS_PER_TENANT` set; ledgers `memory.evicted`/`memory.evict_failed` with counts + policy params only): `artifacts/api-server/src/lib/memory-eviction.ts`; backfill create-gate lives in `artifacts/api-server/src/lib/search.ts` (`backfillEmbeddings` `memoryPolicy?` opt)

## LLM runtime

- Cloud LLM runtimes + PHI guard wrapper (Bedrock Converse / Vertex generateContent / Azure OpenAI Chat, lazy-loaded): `artifacts/api-server/src/lib/cloud-llm-runtimes.ts`; env factory: `artifacts/api-server/src/lib/llm-runtime-config.ts`
- Chat agent + LLM runtime seam (M9.5): `artifacts/api-server/src/lib/chat-agent.ts` (`runChatTurn` calls `streamFromRuntime(getLlmRuntime(), ...)`); runtime adapter + `streamFromRuntime` helper in `cloud-llm-runtimes.ts` / `llm-runtime-config.ts`.
- Per-decision-point LLM selection (M17): `artifacts/api-server/src/lib/llm-decision-points.ts` (`resolveLlmForDecisionPoint(point, defaultModelId, env?)`, scoped `LLM_<POINT>_*` overlay).
- Input-based LLM router (M20): `artifacts/api-server/src/lib/llm-router.ts` (`classifyTier` cheap/standard/strong from input length/risk, `isRouterEnabled`/`loadRouterPolicyFromEnv`, `resolveLlmForRequest` with per-tier `LLM_ROUTER_<TIER>_*` overlay layered in front of the M17 resolver).

## Ingestion & log sources

- Log ingestion (M3): `artifacts/api-server/src/lib/log-source.ts` (LogRecord + LogSource interface + StaticFixtureLogSource; re-exports `CloudwatchLogSource` from cloud-log-sources.ts), `artifacts/api-server/src/lib/log-bus.ts` (LogBus interface + InMemoryLogBus stub for Kafka/NATS), `artifacts/api-server/src/lib/ingest.ts` (detector → redact → fingerprint upsert → ledger), `artifacts/api-server/src/routes/ingest.ts` (`POST /api/admin/ingest/replay` dev/demo trigger)
- Pluggable event-bus transport seam + config/factory/registry (mirrors embedder/search/raw-evidence factories): `artifacts/api-server/src/lib/log-bus-config.ts` (`LOG_BUS_PROVIDER` env factory, discriminated-union `LogBusConfig`, `getLogBus`/`setLogBus`/`initLogBusFromEnv`/`resetLogBusForTests` registry — lazy-defaults to the in-memory singleton); broker impls in `artifacts/api-server/src/lib/cloud-log-bus.ts` (`BrokerDriver` seam + one `BrokeredLogBus`; `createKafkaDriver` lazy `kafkajs`, `createNatsDriver` lazy `nats` JetStream); wire codec (`encodeLogRecord`/`decodeLogRecord`, Zod-validated) + optional `start?()`/`stop?()` lifecycle live on the `LogBus` interface in `lib/log-bus.ts`.
- Real CloudWatch Logs source + checkpoint store (M8): `artifacts/api-server/src/lib/cloud-log-sources.ts` (`CloudwatchLogSource` w/ lazy `@aws-sdk/client-cloudwatch-logs`, `DbCheckpointStore` + `InMemoryCheckpointStore`, env-driven `buildCloudwatchSourceFromEnv`), `lib/db/src/schema/log-source-checkpoints.ts` (mutable cursor table — `source_name` PK, `tenant_id`, `last_event_ts` bigint ms, `updated_at`), DDL mirrored in `lib/db/src/setup-sql.ts` so first boot creates the table.

## Detection & redaction

- Inline redaction helper (`redactInline`) + Stage-1 `scanForPhi` + async `scanForPhiWithNer` (Stage-1 ∪ NER): `artifacts/api-server/src/lib/redact.ts`
- Optional Stage-2 NER detector seam (M13.3 production path; mirrors embedder/search/raw-evidence factories): `artifacts/api-server/src/lib/ner.ts` (`NerProvider` interface + default `NoopNerProvider` + `nerHit`), `artifacts/api-server/src/lib/ner-config.ts` (`NER_PROVIDER` env factory/registry/`initNerProviderFromEnv`/`getNerProviderOrNull`), `artifacts/api-server/src/lib/local-ner.ts` (M23 — self-contained in-process gazetteer NER, no SDK/network; `NER_LOCAL_MIN_TOKEN_LEN`/`NER_LOCAL_CAPITALIZED_ONLY`, reuses `redact.ts` name dictionaries), `artifacts/api-server/src/lib/presidio-ner.ts` (self-hosted Microsoft Presidio Analyzer over HTTP — no cloud account/BAA, no SDK; `${endpoint}/analyze` → PERSON/LOCATION, codepoint→UTF-16 offset conversion, injectable `fetchImpl`), `artifacts/api-server/src/lib/cloud-ner.ts` (lazy AWS Comprehend / GCP DLP / Azure Language providers). Default-inert; wired into the async ingest detection path only.
- Specialist review agents (Triage, Verifier, and M23 Context + Notifier): `artifacts/api-server/src/lib/agents/context.ts` (`runContextAgent` + default-inert `ContextEnrichmentProvider` seam), `artifacts/api-server/src/lib/agents/notifier.ts` (`runNotifierAgent` — drafts only, never auto-sends), orchestrated by `artifacts/api-server/src/lib/agents/review-orchestration.ts` + `review-steps.ts` (Context/Notifier steps gated on `AGENT_PIPELINE_EXTENDED`). A2A wiring for all specialists lives under `artifacts/api-server/src/lib/a2a/` (`protocol.ts`, `cards.ts`, `executors.ts`, `server.ts`, `client.ts`, `caller-identity.ts`).

## Policy & prompts

- Per-agent tool allow-list + tool-arg revalidation: `artifacts/api-server/src/lib/policy.ts`
- Free-text ledger-payload guard (justification/approval_note/step-up reason): `artifacts/api-server/src/lib/text-policy.ts`
- Agent prompts (version-pinned): `artifacts/api-server/src/lib/prompts.ts`

## Ledger, notarization & alerting

- Ledger writer + chain walk: `artifacts/api-server/src/lib/ledger.ts`
- Periodic chain verifier + notarization scheduler (per-scope advisory leader lock): `artifacts/api-server/src/lib/chain-verifier.ts`
- HMAC notarization (canonical-JSON signing, retired-key registry): `artifacts/api-server/src/lib/notarization.ts`
- Event-type alert routing + post-commit hook: `artifacts/api-server/src/lib/alerts.ts`
- Mechanical event-type coverage scan: `artifacts/api-server/src/lib/event-type-coverage.test.ts`
- Channel router + Slack/webhook adapters + dispatch hook (M6): `artifacts/api-server/src/lib/channels/{types,router,dispatch,index,adapters/slack,adapters/webhook}.ts`

## Auth & routes

- Session + step-up cookies (HMAC, domain-separated): `artifacts/api-server/src/lib/auth.ts`
- Step-up + break-glass admin routes: `artifacts/api-server/src/routes/admin.ts`, `artifacts/api-server/src/routes/auth.ts`
- Ledger admin route (incl. `GET /api/admin/ledger/checkpoints?verify=1`): `artifacts/api-server/src/routes/ledger.ts`
- Per-user rate limiters (chat, tools, break-glass, step-up): `artifacts/api-server/src/app.ts`
- HITL remediation plane: proposal routes (`GET /api/admin/remediation/proposals`, `…/:id/confirm`, `…/:id/reject`, CAS-guarded) in `artifacts/api-server/src/routes/admin.ts`; dashboard inbox UI `artifacts/dashboard/src/pages/remediation.tsx`. Opt-in executing worker (`REMEDIATION_EXECUTOR`, default-inert): `artifacts/api-server/src/lib/remediation-executor.ts` (`RemediationExecutor` seam + `DevNoopExecutor`) + `artifacts/api-server/src/lib/remediation-worker.ts` (leader-locked `confirmed→executing→executed|execution_failed`, CAS each step, idempotency via `executed_at`+`external_ref`; ledgers `remediation.executed`/`remediation.execution_failed`). Agent plane still never executes.

## Database

- DB schema (source of truth): `lib/db/src/schema/*.ts` — `findingSafeColumns` / `FindingSafe` in `findings.ts` is the compile-time gate that keeps `raw_evidence` out of non-break-glass reads.
- DB setup SQL (RLS, pgvector, FTS, triggers, break-glass grants table, `ledger_checkpoints` + ENABLE ALWAYS triggers, F-CANARY raw backfill): `lib/db/src/setup-sql.ts` — opt-in tenant-partitioned layouts for both `finding_embeddings` (`tenantPartitioning?`) and `chat_message_embeddings` (`chatTenantPartitioning?`: `singleChatEmbeddingsDdl` vs `partitionedChatEmbeddingsDdl(dim)`, composite PK `(message_id, tenant_id)`, `PARTITION BY LIST` + DEFAULT partition).
- Per-tenant partition provisioning + live-catalog probes: `lib/db/src/tenant-partition.ts` — `provisionTenantEmbeddingPartition`/`isEmbeddingsPartitionedInDb` (findings) + `provisionTenantChatEmbeddingPartition`/`isChatEmbeddingsPartitionedInDb` (chat, prefix `chat_message_embeddings_t_`).
- Seed (10 findings + canary w/ raw payload + genesis): `lib/db/src/seed.ts`

## Security

- Threat model: `threat_model.md`
