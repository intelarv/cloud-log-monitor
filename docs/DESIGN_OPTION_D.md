# Design — Option D: Multi-Agent Supervisor (Deep Dive)

> **Status:** Design / RFC. Companion to `ARCHITECTURE.md`. Plan only — no implementation in this document.
> **Scope:** Detailed design for the **multi-agent supervisor** architecture applied to the PHI/PII log audit system, sized for the production metrics observed in the source environment.
> **Decision driver:** At measured scale (~199M events/day) the tiered-model, multi-worker supervisor pattern becomes cost- and reliability-justified rather than premature.

---

## 1. Source Environment Metrics

These are the real numbers driving the design.

| Metric | Value |
|---|---|
| Total log groups | 304 |
| Total stored | 3.19 TiB |
| Total ingest (7d) | 733.55 GiB |
| Total events (7d) | 1,393,676,547 |
| Avg daily ingest | 104.79 GiB |
| Avg daily events | ~199,097,000 (~2,300/sec sustained; peaks 5–10k/sec) |
| Groups without KMS | 304 |
| Groups with no retention (never expire) | 127 |
| Groups with subscription filters | 1 |
| Groups with delivery errors/throttling | 0 |

### Implications

- **~38 TiB/year raw** → tiered storage is mandatory, not optional.
- **199M events/day** → single-threaded scanning is infeasible; detector stage must shard.
- **1 subscription filter across 304 groups** → ingest fan-out is the first real engineering task.
- **304 groups without KMS + 127 with no retention** → these are themselves compliance findings the system should emit on day one.
- **0 delivery errors today** → current ingest is healthy; safe to add subscribers without destabilising.
- At a conservative PHI hit rate of 0.01–0.1% of events, expect **~20k–200k candidate findings/day**. The agent layer cannot reason about each one — a deterministic funnel must collapse them to **~200–2,000 deduped findings/day** before any LLM call.

---

## 2. Why Option D Specifically

Recap of the four options from the earlier review:

| | A: Single-shot RAG | B: Tool-using Agent | C: Text-to-SQL | **D: Multi-Agent Supervisor** |
|---|---|---|---|---|
| LLM calls / turn | 1 | 1–3 | 2 | 3–5 (tiered) |
| Cost at 200k+ candidates/day | Low (no triage) | Medium | Medium | **Lowest with tiering** |
| Safety surface | Smallest | Small | Large | Small |
| Fits the source-environment scale | Poor | Adequate | Risky | **Best fit** |
| Action-path extensibility | Hard | Medium | Hard | **Trivial (add worker)** |
| Bedrock AgentCore / Vertex Agent Builder mapping | Partial | Clean | Partial | **Native** |
| Build effort | XS | S | M | M (≈ 2× B day-one) |

**Selected:** Option D, with the source-environment metrics making the tiered-model multi-worker pattern cost-justified rather than over-engineered.

---

## 3. Logical Architecture

```
                                   ┌─────────────────────────────────────────┐
                                   │   AWS Account (304 log groups)          │
                                   │                                         │
                                   │   CloudWatch ─► Subscription filter ─►  │
                                   │   (one per group, auto-provisioned)     │
                                   └──────────────────┬──────────────────────┘
                                                      │  ~2.3k–10k events/sec
                                                      ▼
                                              Kinesis Firehose
                                              (or Kafka via MSK Connect)
                                                      │
                                                      ▼
                              ┌───────────────────────────────────────────┐
                              │  STAGE 1 — Deterministic Filter (k8s)     │
                              │  Pipes & Filters, sharded by log group    │
                              │   • regex (SSN, MRN, email, phone)        │
                              │   • Presidio                              │
                              │   • clinical NER (medspaCy)               │
                              │   • allow-list / known-FP filter          │
                              │   • template extraction (drain3)          │
                              └──────────────┬────────────────────────────┘
                                             │ candidates topic (Kafka)
                                             │ ~20k–200k/day
                                             ▼
                              ┌───────────────────────────────────────────┐
                              │  STAGE 2 — Dedup & Aggregation            │
                              │   • template-level dedup (1 finding per   │
                              │     code path per window, not per event)  │
                              │   • drops 95–99% of candidate volume      │
                              └──────────────┬────────────────────────────┘
                                             │ deduped: ~200–2,000/day
                                             ▼
              ┌──────────────────────────────────────────────────────────────────┐
              │  STAGE 3 — AGENT PLANE (Temporal-orchestrated)                   │
              │                                                                  │
              │   Supervisor (deterministic code — NOT an LLM)                   │
              │    │                                                             │
              │    ├─► Triage Agent     [Flash]  classify, severity, dedup       │
              │    │       └─ tools: vector_search, template_lookup              │
              │    │                                                             │
              │    ├─► Context Agent    [Flash]  enrich with owner, deploys      │
              │    │       └─ tools: git_blame, service_catalog, deploy_history  │
              │    │                                                             │
              │    ├─► Verifier Agent   [Pro/Sonnet]  decide PHI vs FP + reason  │
              │    │       └─ tools: read_redacted_context, phi_taxonomy_rag,    │
              │    │                  safe_harbor_checklist                      │
              │    │                                                             │
              │    ├─► Chat Agent       [Pro/Sonnet]  human-facing Q&A           │
              │    │       └─ tools: semantic_search, keyword_search,            │
              │    │                  structured_query, get_finding,             │
              │    │                  get_ledger_entries                         │
              │    │                                                             │
              │    ├─► Compliance Agent [Flash]  scans config drift → findings   │
              │    │       └─ tools: list_log_groups, kms_status, retention      │
              │    │                                                             │
              │    ├─► Remediation     [Pro/Sonnet, HITL]  propose redaction PR  │
              │    └─► Notifier        [Flash]   pick channel, draft PHI-strip   │
              └──────────────────────┬───────────────────────────────────────────┘
                                     │ findings.confirmed (Kafka)
                                     ▼
          ┌──────────┬──────────────┬───────────────┬────────────────┬───────────────┐
          ▼          ▼              ▼               ▼                ▼               ▼
       Postgres   OpenSearch   pgvector        Object store     Event bus       Audit Ledger
       (hot 90d)  (search)     (semantic mem)  (WORM, tiered)   (configurable    (hash-chained,
                                                                  routing)        Postgres → S3)

       Dashboard (React + Express) ──► Postgres + OpenSearch + presigned URLs + Chat agent (SSE)
```

---

## 4. The Two-Stage Funnel (Mandatory at This Scale)

Without it: 200M events × any LLM call = bankruptcy.
With it:

| Stage | Input/day | Output/day | Reduction | Cost driver |
|---|---|---|---|---|
| Raw ingest | 199M | 199M | — | Storage |
| Deterministic filter (Stage 1) | 199M | ~20k–200k | 1,000–10,000× | CPU only |
| Template dedup (Stage 2) | ~20k–200k | ~200–2,000 | ~100× | CPU only |
| Triage agent (Flash) | ~2,000 | ~2,000 | 1× | Cheap LLM |
| Verifier agent (Pro) | ~200 (low-confidence only) | ~200 | 10× gated | Expensive LLM |

Strong-model spend lands on **~200 findings/day, not 200M events.**

### Template extraction (Stage 2 mechanics)
- Use **drain3** or equivalent to extract a stable template ID from each log message (`User <ID> logged in from <IP>` → template `t_4f81…`).
- Dedup key: `(template_id, redacted_pattern_hash, source, hour_bucket)`.
- One finding per code path per window — not per event — typically collapses ~99% of candidate volume.

---

## 5. Supervisor Pattern Details

The Supervisor is **deterministic code that orchestrates LLM workers**, not itself an LLM. This is the single most important design choice at scale.

- Implemented as a **Temporal workflow**. Each agent invocation is a Temporal activity with retry, timeout, idempotency, and replay.
- **Routing decisions** (which agent runs next) are made by code based on confidence thresholds and finding metadata — not by an LLM. This saves cost, removes a bug class, and makes the flow replayable and auditable.
- **LLMs reason; the Supervisor orchestrates.** Don't conflate them.

### Decision flow (per finding)

```
candidate ──► Triage (Flash) ──► confidence?
                                    ├─ high + matches known pattern → auto-confirm
                                    ├─ low or ambiguous            → Verifier (Pro)
                                    └─ matches known false-positive → drop, ledger
Verifier ──► confirmed? ──► Context (enrich) ──► Notifier (route + send)
                          └─► Remediation (HITL) if severity ≥ high
```

---

## 6. Cost-Aware Model Tiering

| Agent | Model class | Why |
|---|---|---|
| Triage, Context, Notifier, Compliance | Small (Gemini Flash / Claude Haiku / Llama 3.1 8B) | High volume, narrow task |
| Verifier, Chat, Remediation | Strong (Gemini Pro / Claude Sonnet / Llama 3.1 70B) | Reasoning-heavy, low volume |
| Embeddings | Dedicated embedding model (text-embedding-004 / Titan Embed) | Batched at ingest, **per template not per event** |

**Estimated daily LLM cost at the source volume:**

| Strategy | Daily LLM spend (order of magnitude) |
|---|---|
| Naive (LLM on every event) | $3k–$15k |
| Funnel + single model | $300–$1,500 |
| **Funnel + tiered models (D)** | **$30–$120** |

Roughly 1–2 orders of magnitude saved by tiering on top of the funnel.

---

## 7. Memory & Context Strategy (applied to D)

Drawn from `ARCHITECTURE.md §8`, with the patterns that matter most here:

1. **Stateless agents + Temporal-owned state** — the LLM never holds state between turns; each activity rebuilds a minimal context from durable state.
2. **Sub-agent handoff with pointer-only payloads** — Triage hands Verifier a `finding_ref_id`, not full context. Verifier fetches via a tool.
3. **Schema-first tool results** — return `{summary, ref_id}`; agent calls `get_full(ref_id)` only when needed.
4. **Episodic memory** in Postgres, TTL'd to finding lifecycle. **Semantic memory** in pgvector (confirmed PHI patterns + false positives), with importance-decay eviction.
5. **Conversation memory for the Chat agent**: sliding window + hierarchical summarization. Full conversation in Postgres (TTL); audit copy in ledger (immutable).
6. **Embedding dedup** — embed deduped templates, not raw events. Cuts embedding cost ~100×.

Net effect: each agent invocation sees a few hundred tokens of curated context, not tens of thousands. The system scales linearly with findings, not quadratically with history.

---

## 8. Mapping to Bedrock AgentCore and Vertex AI Agent Builder

Both platforms are designed around exactly this multi-agent supervisor shape. The mapping is direct.

| D component | AWS (Bedrock AgentCore) | GCP (Vertex AI Agent Builder) | Local/dev |
|---|---|---|---|
| Supervisor | Temporal workflow on EKS/ECS | Same Temporal workflow on GKE | Temporal local / dev server |
| Triage / Context / Notifier / Compliance agents | Bedrock Agent with Haiku / Llama; action groups = our tool API | Vertex Agent with Gemini Flash; function declarations = our tool API | `DirectLlmRuntime` → Gemini via Replit AI integration |
| Verifier / Chat / Remediation agents | Bedrock Agent with Claude Sonnet | Vertex Agent with Gemini 1.5 Pro | Same |
| Tool execution | AgentCore action group → our Express API (IAM-signed) | Vertex function-calling → our Express API (SA ID-token) | In-process |
| Per-session memory | AgentCore session memory (optional) — **our ledger** remains source of truth | Vertex session memory (optional) — same | Postgres |
| Guardrails | Bedrock Guardrails (PHI patterns, denied topics) | Vertex Safety Filters + Model Armor | Application-level policy layer |
| Vector store | Bedrock Knowledge Bases (OpenSearch Serverless or pgvector on RDS) | Vertex AI Vector Search (or pgvector on Cloud SQL) | pgvector on local Postgres |
| LLM gateway | Direct Bedrock invoke | Direct Vertex invoke | LiteLLM / Replit AI integration |

### Portable runtime abstraction

```
LlmAgentRuntime (interface)
  invokeAgent(agentName, input, tools, context) → AsyncIterable<AgentEvent>

Implementations:
  • BedrockAgentRuntime       (production AWS)
  • VertexAgentRuntime        (production GCP)
  • DirectLlmRuntime          (local dev, on-prem) — Gemini via Replit AI integration for now

ToolRegistry (cloud-neutral)
  register(name, zodSchema, handler)
  exportFor("bedrock")  → AgentCore action group OpenAPI
  exportFor("vertex")   → Vertex function declarations
  exportFor("direct")   → in-process map

Tools are defined ONCE in our code with Zod. The registry compiles them per runtime.
```

**Largest architectural win of D + this abstraction:** tools are written once, exposed everywhere. No re-implementation per cloud.

### Deployment posture

- **AWS-native deploy.** Supervisor (Temporal on EKS) calls Bedrock AgentCore agents. Tools run in our service behind an IAM-authenticated endpoint. PHI never leaves your AWS account. Bedrock + AgentCore covered by AWS BAA.
- **GCP-native deploy.** Supervisor (Temporal on GKE) calls Vertex Agents. Tools run in our service behind service-account-authenticated endpoint. PHI never leaves your GCP project. Vertex covered by Google BAA.
- **Local/dev.** Supervisor runs in-process or via Temporal dev server; agents go through `DirectLlmRuntime` → Gemini. Buildable and testable in Replit without any cloud account.

---

## 9. Chat-Over-Audit Capability (Chat Agent details)

The Chat Agent is one worker among many, but it's the human-facing one.

### Tool surface
| Tool | Purpose | Returns |
|---|---|---|
| `semantic_search(query, k)` | pgvector top-k over redacted finding context + agent reasoning | `{matches: [{finding_id, score, summary}]}` |
| `keyword_search(query, k)` | OpenSearch / Postgres FTS | same shape |
| `structured_query(filter_json)` | Zod-validated typed filter (severity, source, owner, date range, status) | `{count, results: [...]}` |
| `get_finding(id)` | Full redacted finding | `{finding, redacted_snippet, agent_reasoning_trail}` |
| `get_ledger_entries(finding_id)` | All ledger entries for a finding | `{entries: [...]}` |

No raw SQL. No raw PHI. All reads go through the `findings_redacted` view with Postgres RLS bound to the caller's identity.

### Hybrid retrieval
Vector + FTS results merged via **Reciprocal Rank Fusion** before the Chat agent reasons. This consistently outperforms either retriever alone.

### Citations mandatory
Every answer ends with finding IDs / ledger entry IDs the answer used. Post-processor drops messages with no citations. UI renders citations as click-through cards. No citation → "cannot verify" banner.

### Streaming UI
SSE events: `tool_call`, `tool_result`, `evidence`, `token`, `proposed_action`, `done`. Evidence cards render before the answer arrives, so the UI never feels frozen.

### API surface (fits the OpenAPI-first repo conventions)
```
POST /chat/sessions                        → { session_id }
POST /chat/sessions/{id}/messages          → SSE stream (events above)
POST /chat/actions/{proposed_id}/confirm   → executes a gated action
GET  /chat/sessions/{id}                   → conversation history (redacted)
GET  /findings/{id}                        → existing endpoint, cited by chat
```

### Three-pane UI
| Pane | Content |
|---|---|
| Left | Conversation thread |
| Middle | Evidence cards (cited findings + ledger entries) |
| Right | Preview drawer (full finding detail when a card is clicked) |

---

## 10. What Option D Unlocks That B Does Not

1. **Self-reporting compliance gaps.** Source metrics show 304 groups without KMS and 127 with no retention. The Compliance Agent emits these as findings on day one.
2. **Backpressure across stages.** Each stage scales independently. Verifier rate-limited? Triage keeps running, candidates queue in Kafka, no data loss. Bulkhead pattern natively.
3. **Differential model strategy per agent.** Verifier on a fine-tuned clinical model; Chat on a generalist. Hard in B; clean in D.
4. **Independent eval per agent.** Triage accuracy, Verifier precision/recall, Chat answer correctness — each evaluated and improved on its own loop.
5. **Action path is just another worker.** Remediation, Notifier, Compliance — adding them is "register a worker," not "rewrite the agent."

---

## 11. Honest Cons of Option D at This Scale

1. **More code on day one.** ~2× Option B for orchestration. Real but manageable.
2. **Temporal becomes a hard dependency.** Right tool, real operational responsibility (managed via Temporal Cloud or self-hosted).
3. **More moving parts to debug.** Mitigated by Temporal's UI giving you a complete replay of every workflow.
4. **Embedding cost at ingest.** Solvable by batching and embedding only deduped templates, not every candidate.
5. **Inter-service contracts proliferate.** Schema registry + data contracts on Kafka topics become non-optional.

---

## 12. Cross-Cutting Patterns (already in `ARCHITECTURE.md §13`, reaffirmed here)

| Pattern | Where |
|---|---|
| Pipes & Filters | Stage 1 detectors |
| Strategy | Redaction method per source |
| CQRS + Event Sourcing | Ledger is source of truth; projections feed dashboard |
| Saga | Temporal remediation workflows with compensations |
| Outbox | Atomic finding + event write |
| Idempotency Key | `sha256(template_id + detector_version + window)` |
| Circuit Breaker | Per agent, around LLM calls |
| Bulkhead | Per-source resource pools |
| DLQ + Replay | On every async hop |
| Token Vault | KMS / Vault-backed reversible tokenization |
| Break-Glass Access | Time-boxed, justified, ledgered |
| Schema Registry / Data Contracts | Versioned Kafka topic schemas |
| Supervisor + Workers | Agent layer |
| ReAct / Reflexion / RAG | Verifier reasoning |
| MemGPT / virtual memory | Agent memory layer |

---

## 13. Healthcare Guardrails (delta from `ARCHITECTURE.md §14`)

All of `ARCHITECTURE.md §14` applies. Specific to D:

- Every agent's prompts, tool calls, decisions, model name, and confidence are ledgered.
- Verifier and Chat agents see only **redacted** context — raw PHI never enters any prompt.
- Guardrails enforced at three layers: platform (Bedrock Guardrails / Vertex Safety Filters), application policy layer, tool-input validation (Zod).
- Compliance Agent surfaces real compliance gaps from the environment metrics (no-KMS groups, no-retention groups) as first-class findings, not just operational noise.

---

## 14. Suggested Build Sequencing for D v1

Layered, each independently demoable.

| Layer | Contents | Demoable? |
|---|---|---|
| **L0 — Runtime + tool abstractions** | `LlmAgentRuntime` interface, `ToolRegistry`, three adapters: `DirectLlmRuntime` (working with Gemini), `BedrockAgentRuntime` + `VertexAgentRuntime` (deployment-ready stubs with adapter contract tests) | Unit-tested |
| **L1 — Data plane** | pgvector extension, Drizzle schemas (`findings`, `findings_embeddings`, `ledger_entries`, `chat_sessions`, `chat_messages`, `chat_audit`), `findings_redacted` view, RLS policies, seeded realistic findings (incl. KMS/retention gaps from source metrics) | Postgres console |
| **L2 — Chat agent + dashboard** | OpenAPI block, Orval codegen, 5 chat tools, SSE streaming, three-pane React UI, mandatory citations | **End-to-end demo** |
| **L3 — Triage + Verifier agents** | Supervisor Temporal workflow, two agents behind it, processing a stream of seeded candidates | Workflow UI |
| **L4 — Context + Notifier + event router** | Two more agents, configurable router with one Slack-style adapter | Slack-like webhook |
| **L5 — Compliance Agent** | Scans configuration, emits findings for KMS gaps and no-retention groups | Findings appear in UI |
| **L6 — Remediation Agent (HITL)** | Confirm-cards in chat UI; ledgered execution on approval | Approve a redaction proposal |
| **L7 — Hardening** | Bulkheads, DLQs, cost circuit breakers, hash-chain verification job | Chaos test |

**v1 build target:** L0 → L3 working end-to-end with Gemini in dev; L4–L7 stubbed with placeholders; Bedrock + Vertex adapters as deployment-ready stubs.

---

## 15. Open Questions

- Which clinical NER engine for in-VPC PHI detection at Stage 1? (medspaCy vs clinical-BERT fine-tune vs Comprehend Medical when running on AWS.)
- Which template-extraction library? (drain3 is the default; alternatives if multilingual logs.)
- Self-hosted vs managed Temporal in production?
- Single-tenant or multi-tenant initial scope?
- Which OIDC IdP for step-up auth on raw-PHI viewing?
- Confidence thresholds for Triage → Verifier escalation — set empirically from a labeled sample of the source environment's logs.
- Embedding model choice per cloud (Titan vs text-embedding-004 vs a self-hosted model in-VPC)?
