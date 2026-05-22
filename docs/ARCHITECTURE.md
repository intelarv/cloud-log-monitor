# PHI/PII Log Audit Agent — Design Document

> **Status:** Design / RFC. Plan only — no implementation in this document.
> **Scope:** Cloud-agnostic, agentic system that ingests cloud logs, detects PII/PHI, maintains a tamper-evident audit ledger, powers a triage dashboard, and drives configurable event-driven remediation.
> **Domain:** Healthcare (HIPAA-aware; designed so BAA coverage is achievable end-to-end).

---

## 1. Goals & Non-Goals

### Goals
- Detect PII and PHI in log streams from **any** cloud provider (AWS, GCP, Azure, on-prem).
- Maintain a **tamper-evident, searchable audit ledger** of findings and human/agent actions.
- Provide a **triage dashboard** with redacted-by-default views and break-glass un-redaction.
- Support **event-driven, configurable notifications** to any channel (Slack, PagerDuty, Teams, email, webhook).
- **Retain logs for 7 years** with cost-tiered storage; auto-archive or expire after retention.
- Use an **agentic workflow** (LLM-driven reasoning) for ambiguous cases, with deterministic fallbacks for the common path.
- Be **portable** — no hard dependency on a single cloud's proprietary services.

### Non-Goals
- Real-time (<1s) detection. Near-real-time (seconds–minutes) is sufficient.
- Replacing existing SIEM / DLP suites. Complements them; focuses on **log-leak PHI** specifically.
- A general-purpose data-loss-prevention product.

---

## 2. Domain Constraints (Healthcare / HIPAA)

| Requirement | Implication on design |
|---|---|
| BAA coverage end-to-end | Every component must be HIPAA-eligible in its cloud; LLM provider must offer BAA *or* run in-VPC. |
| Minimum necessary (§164.502(b)) | Dashboard redacted by default; raw PHI access requires step-up auth + ledgered justification. |
| Integrity controls (§164.312(c)(1)) | Tamper-evident hash-chained ledger; immutable (WORM) object storage. |
| Access controls (§164.312(a)) | RBAC + ABAC; per-data-classification KMS keys; break-glass is time-boxed and auto-revoked. |
| 7-year retention | Tiered storage with lifecycle policies; legal hold capability via object-lock. |
| Audit logging (§164.312(b)) | Every agent action, tool call, and human action is recorded with model name, prompt hash, decision, confidence. |
| Notifications must not leak PHI | Channel payloads carry IDs + severity + source only; never raw PHI. |

---

## 3. High-Level Architecture

```
┌─────────────── Log Sources (any cloud) ────────────────┐
│  CloudWatch / Cloud Logging / Azure Monitor / Loki      │
└──────────────────────┬──────────────────────────────────┘
                       │  pulled via LogSource adapters
                       ▼
              Kafka / Redpanda / NATS  (topic: raw.logs)
                       │
                       ▼
            ┌──────────────────────┐
            │  Detector Pipeline   │  (deterministic, k8s)
            │  Pipes & Filters:    │
            │   regex → Presidio   │
            │   → MRN/ICD patterns │
            │   → allow-list       │
            └──────────┬───────────┘
                       │ topic: candidates
                       ▼
        ┌───────────────────────────────────────────────┐
        │       AGENT ORCHESTRATOR (Temporal)           │
        │                                               │
        │   Supervisor                                  │
        │     ├─► Triage Agent     (small/local model)  │
        │     ├─► Context Agent    (tool-heavy)         │
        │     ├─► Verifier Agent   (strong model + RAG) │
        │     ├─► Remediation Agent (HITL gated)        │
        │     └─► Notifier Agent   (policy-driven)      │
        └──────────┬────────────────────────────────────┘
                   │ topic: findings.confirmed
                   ▼
   ┌─────────────┬───────────────┬───────────────┬───────────────┐
   ▼             ▼               ▼               ▼               ▼
Postgres     OpenSearch      Object Store    Event Bus      Vector DB
(ledger,     (hot search,    (raw + warm     (Kafka,        (pgvector;
hash-         90 days)        Parquet,        configurable    semantic
chained)                      WORM, KMS)      routing)        memory)
                                                  │
                          ┌───────────────────────┼───────────────────┐
                          ▼                       ▼                   ▼
                    Slack / Teams            PagerDuty           Webhook → ANY
                    adapter                  adapter             (declarative rules)

         Dashboard (React + Express) ──► Postgres + OpenSearch + presigned object URLs
```

---

## 4. Portability Strategy

The system is designed against **four narrow interfaces** so the same code runs on any cloud or on-prem.

| Interface | AWS | GCP | Azure | On-prem |
|---|---|---|---|---|
| `LogSource` | CloudWatch Logs | Cloud Logging | Azure Monitor | Loki / Fluent Bit |
| `ObjectStore` (WORM) | S3 + Object Lock | GCS + Bucket Lock | Blob + Immutable | MinIO + WORM |
| `EventBus` | MSK / Kafka | Pub/Sub or Managed Kafka | Event Hubs (Kafka API) | Kafka / Redpanda / NATS |
| `SecretStore` | Secrets Manager | Secret Manager | Key Vault | HashiCorp Vault |

**Portable runtime layer (the same on every cloud):**
- **Kubernetes** as the universal compute substrate. Avoid Lambda / Cloud Functions / Azure Functions — biggest lock-in.
- **Temporal** as the portable workflow & agent orchestration engine (vs Step Functions / Cloud Workflows / Logic Apps).
- **Postgres** (+ `pgvector`) as the portable transactional + vector store.
- **OpenSearch** as the portable search store.
- **LiteLLM / OpenRouter** as the LLM gateway, with a self-hosted model fallback for in-VPC PHI verification.
- **OpenTelemetry** for the agent's own telemetry.

**Pros:** Portable, no lock-in, in-VPC LLM keeps PHI off third-party providers.
**Cons:** More moving parts than a single-cloud serverless build; you operate Kubernetes, Kafka, Temporal yourself (or pay managed equivalents).

---

## 5. Architecture Options Considered

Five options were evaluated. Summary; full discussion below.

| # | Option | Cost floor | Search latency | Eng burden | Best for |
|---|---|---|---|---|---|
| 1 | Lean Serverless | $ | sec (warm) | Low | Most teams starting out |
| 2 | OpenSearch-centric | $$ | ms | Low–Med | Search-heavy workflows |
| 3 | Stream Processing (Flink) | $$$ | ms, real-time | High | Real-time anomaly detection |
| 4 | Data Lakehouse | $$ | sec | Med–High | Governed, compliance-first data |
| 5 | Hub-and-Spoke (multi-account) | $$$ | varies | High | Multi-account / multi-tenant |

### Option 1 — Lean Serverless (AWS-native baseline)
- CloudWatch → Firehose → Lambda (detectors) → S3 (Object Lock) + Postgres + EventBridge.
- **Pros:** Lowest cost at small/medium volume; fits the existing Express + Postgres stack; few moving parts.
- **Cons:** AWS-only without a portability layer; Lambda cold starts; Athena queries on warm tier are seconds not ms.

### Option 2 — OpenSearch-Centric
- Same ingest, hot tier is OpenSearch Serverless; dashboard searches across millions of findings in ms.
- **Pros:** Sub-second search, built-in alerting, anomaly detection, log clustering.
- **Cons:** ~$700/mo floor even idle; overkill if finding volume is low.

### Option 3 — Stream Processing (Kinesis/Flink/Beam)
- Stateful stream processing for windowed anomaly detection and dedup.
- **Pros:** True real-time aggregations; exactly-once semantics; strong dedup before alerting.
- **Cons:** Flink is a real operational burden (checkpointing, state size, upgrades); higher cost floor.

### Option 4 — Data Lakehouse (Medallion: raw → curated → marts)
- Glue/EMR ETL into Iceberg/Delta on object storage; Athena/Redshift Spectrum for queries.
- **Pros:** Strongest compliance/lineage story; open formats avoid lock-in; column/row-level security via Lake Formation.
- **Cons:** Heavier engineering; minutes-not-seconds ingest latency; dashboard queries are seconds.

### Option 5 — Hub-and-Spoke (Multi-Account)
- Per-tenant/source accounts ship logs cross-account to a hardened audit account.
- **Pros:** Strongest security posture; root in a source account cannot tamper with audit data; per-tenant KMS keys and cost attribution.
- **Cons:** Cross-account IAM complexity; higher cost (data transfer, multiple control planes).

### Selected baseline
**Option 1 (Lean) generalized to be cloud-agnostic via the portability layer in §4**, with a path to graduate the hot tier toward Option 2 (OpenSearch) as volume grows.

---

## 6. PII / PHI Detection Pipeline

**Pattern:** Pipes & Filters. Each detector is a swappable stage.

1. **Regex layer** — SSN, email, phone, IPs, custom MRN / account-ID formats. Always on, cheap.
2. **Open-source NLP** — Presidio (or equivalent) for names, locations, dates, organizations.
3. **Healthcare-specific** — pluggable; AWS Comprehend Medical *or* a self-hosted clinical NER model (e.g. medspaCy, clinical BERT). The interface is identical; the implementation is per-deployment.
4. **Custom domain rules** — your org's MRN format, account IDs, internal patient identifiers.
5. **Allow-list / known-false-positive filter** — last stage; drops noise.

Sampling: stages 3–4 can run on a configurable percentage of traffic to control cost; the agentic layer (§7) handles ambiguous cases that bypass sampling.

**Redaction strategy** is per-source via the **Strategy pattern**: `mask`, `tokenize` (KMS-reversible), or `drop`. Raw PHI never lands in the searchable hot tier — only redacted snippets do.

---

## 7. Agentic Workflow

### Why agents at all
- Regex finds *patterns*; agents find *meaning*. `"the 47yo F with ESRD on 4S"` is PHI under HIPAA Safe Harbor but no regex catches it.
- Agents chain tools across systems: lookup owner → draft redaction PR → notify → wait for ack → re-scan.
- Agent reasoning becomes part of the audit trail — auditors get a documented "why."

### Architecture: Supervisor + Specialist agents

| Agent | Job | Tools | Model tier |
|---|---|---|---|
| **Triage** | Score severity, dedup against known patterns | `vector_search(similar_findings)`, `template_extract` | Small / local |
| **Context** | Enrich finding with code owner, service catalog, recent deploys | `git_blame`, `service_catalog`, `deploy_history` | Small (tool-heavy, low reasoning) |
| **Verifier** | Decide real PHI vs false positive; explain why | `read_log_context`, `safe_harbor_checklist`, `phi_taxonomy` (RAG) | Strong (accuracy matters most here) |
| **Remediation** | Propose redaction strategy, optionally open PR | `read_code`, `propose_patch`, `open_pr` | Strong; HITL gated |
| **Notifier** | Pick channel + draft PHI-stripped message | `lookup_owner`, `channel_registry`, `send` | Small (mostly deterministic) |
| **Supervisor** | Routes between agents; enforces budget & policy | All of the above | Small |

### Design patterns
- **Supervisor / Router** — single orchestrator with narrow specialist workers.
- **ReAct** — Verifier reasons step-by-step; reasoning is ledgered.
- **Reflexion / Self-Critique** — only on low-confidence findings.
- **Tool-Use with typed JSON schemas** — no free-form shell or unrestricted code execution.
- **Human-in-the-Loop gates** — anything touching code or un-redacting PHI pauses for approval (Temporal signals).
- **RAG over a PHI taxonomy** (HIPAA Safe Harbor 18 identifiers + org-specific).
- **Constitutional / Policy guardrails** — a hard policy layer that agents cannot override.
- **Token-budget Circuit Breaker** — per-finding and per-day LLM spend caps; downgrade to cheaper model or deterministic fallback when tripped.
- **Cost-aware routing** — small/local model for ~90% of traffic, strong frontier model only for ambiguous cases.
- **Deterministic workflows** — Temporal records every step; replayable for auditors.

---

## 8. Agent Memory Strategy

Agent context bloat kills these systems in production (cost, latency, accuracy all degrade together). The system applies a layered memory-reduction strategy.

### 8.1 Context compression
- **Sliding window + summarization** — last N turns verbatim; older turns rolled into a digest.
- **Hierarchical summarization** — turn → step → run digests; only highest level survives long term.
- **Semantic compression** — store structured facts `{finding_id, decision, confidence, reason_code}`, not prose. 10–50x smaller.
- **Delta encoding** — store what changed, not full state each step.

### 8.2 Retrieval-over-memory (RAG instead of stuffing)
- **External vector store** (`pgvector`) — agent memory lives outside the context window; top-k retrieved per call.
- **MemGPT / virtual-memory pattern** — context window as RAM, vector store as disk; agent explicitly pages memories in via tools.
- **Episodic vs semantic split** — episodic (per-finding) is short-lived; semantic (confirmed PHI patterns, false-positive library) is long-lived and shared.

### 8.3 Tool-result hygiene
- **Result truncation with pointers** — tools return `{summary, ref_id}`; agent calls `get_full(ref_id)` only if needed.
- **Schema-first tool returns** — tight typed JSON, never raw blobs.
- **Output filtering at the tool boundary** — tools trim fields the agent doesn't need for *this* task (need-to-know).

### 8.4 Workflow-level patterns
- **Supervisor + isolated specialist workers** — each worker sees only the slice it needs.
- **Sub-agent handoff** — spawn a fresh sub-agent with a curated mini-context, get back structured result, discard.
- **Stateless steps in Temporal** — workflow state lives in Temporal, not the LLM. Each activity rebuilds a minimal context.
- **Checkpoint + resume** — long workflows resume with rebuilt minimal context.

### 8.5 Cost-aware routing
- **Tiered models** — triage on small/local, escalate to frontier only when needed, re-summarize before escalation.
- **Confidence-gated reflection** — self-critique only when confidence is low.

### 8.6 Memory lifecycle (forgetting)
- **TTL on episodic memory** tied to finding lifecycle.
- **Importance scoring + decay** — score by access frequency × recency × outcome value; evict bottom percentile on schedule.
- **Consolidation jobs** — nightly batch promotes high-value episodic memories into compressed semantic patterns; drops the rest.
- **Embedding dedup** — before writing a new memory, check cosine similarity; merge instead of duplicate.

### Net effect
Each agent invocation typically sees a few hundred tokens of curated context instead of tens of thousands. The system scales linearly with findings, not quadratically with history. The audit ledger — not the LLM context — is the durable memory.

---

## 9. Audit Ledger & Storage Tiering

The ledger must be searchable, cheap, and retained for 7 years. Tiered design:

| Tier | Store | Window | Purpose | Cost shape |
|---|---|---|---|---|
| Hot | Postgres (+ pg_trgm) or OpenSearch | 0–90 days | Dashboard queries, full-text search | $$ |
| Warm | Object store (Parquet, partitioned by day) + Athena/Trino | 90 days – 2 yrs | SQL on cold data, audit pulls | $ |
| Cold | Object store, archival tier (Glacier IR / Archive Storage) | 2 – 7 yrs | Rare retrieval, retention proof | ¢ |
| Expire | Lifecycle delete (or Deep Archive) | 7+ yrs | Auto-managed | — |

### Tamper evidence
- Each ledger record carries `hash = SHA256(prev_hash || canonical_json(record))`.
- Periodic **checkpoint hashes** are notarized to an immutable, separately-accessed store (different account/project, Object Lock).
- A **quarterly verification job** re-walks the chain and alerts on any mismatch.

### Why not QLDB / DynamoDB-only / single-tier?
- **QLDB:** AWS announced end-of-support; not portable.
- **DynamoDB-only:** not natively searchable; expensive at 7-year scale.
- **Single hot tier for 7 years:** prohibitively expensive; no audit benefit over tiered.

**Pros:** Searchable on the active window, cheap on the long tail, portable across clouds (S3-compatible object stores exist everywhere), legal-hold capable via object lock.
**Cons:** Three storage technologies to operate; query latency is non-uniform across tiers (the dashboard must indicate "warm tier query, may take seconds").

---

## 10. Event Bus & Configurable Notifications

### Bus choice
**Kafka (or Redpanda / NATS JetStream).** Reasons:
- Runs on every cloud (MSK / Confluent Cloud / Managed Kafka / Event Hubs Kafka API / self-hosted).
- Replayable — agents and consumers can re-process.
- Ordered partitions per log source (useful for dedup and rate limiting).
- Avoids SNS / EventBridge AWS lock-in.

| Bus | Portability | Replay | Per-channel routing | Cost floor |
|---|---|---|---|---|
| SNS | AWS-only | No | Manual subs | Lowest |
| EventBridge | AWS-only | Yes (archive) | Native rules | Low |
| **Kafka** | **Any cloud** | **Yes** | **Via router service** | **Med** |
| MSK / managed | One cloud, but Kafka API | Yes | Via router | Med–High |

### Configurable routing
Routing is **data, not code** — declarative rules in Postgres, hot-reloaded by a router service:

```
rule: severity >= high           → PagerDuty adapter
rule: source matches "ehr-*"     → Slack #phi-ehr
rule: owner.team == "billing"    → owner-team webhook
rule: any                        → audit log sink
```

Adapters implement a single `Channel.send(event, config) → receipt` interface. Adding a new channel = ship a new adapter + insert a rule row. **No core redeploy required.**

**Pros:** Truly configurable; new channels without code changes to core; replayable; cloud-portable.
**Cons:** You operate Kafka (or pay for managed); slightly higher latency than SNS-direct.

---

## 11. Dashboard

### Views
- **Findings queue** — Kanban-style triage (severity / source / age / owner / assignee).
- **PHI heatmap** by service / log group — where leakage clusters.
- **Trend lines** — week-over-week direction.
- **Top offending code paths** — grouped by log message template, not raw text.
- **Compliance view** — retention status, ledger verification status, recent break-glass events.
- **Per-finding detail** — redacted snippet, agent reasoning trail, audit ledger entries, "request raw PHI" (step-up auth).

### Patterns
- **CQRS** — write path goes to ledger + object store; dashboard reads a projection in Postgres / OpenSearch.
- **Materialized view** — search index is rebuildable from the object-store source of truth.
- **Redacted-by-default UI** with break-glass un-redaction tied to a ledger entry.

---

## 12. Automations (Saga / Step pattern via Temporal)

- Auto-create ticket (Jira / Linear) when severity ≥ high.
- Auto-redact repeat offenders after N occurrences from the same template.
- Auto-notify service owner via their team's channel (owner lookup from service catalog).
- Daily digest to compliance officer.
- Weekly drift report — new PHI patterns appearing.
- Quarterly ledger hash-chain verification job.
- Break-glass workflows: justification → time-boxed grant → auto-revoke → ledgered.

Each is a Temporal workflow with explicit compensations (e.g., reversing tokenization on a wrongful redaction).

---

## 13. Cross-Cutting Design Patterns

| Pattern | Where |
|---|---|
| Pipes & Filters | Detector pipeline |
| Strategy | Redaction method per source |
| CQRS + Event Sourcing | Ledger is source of truth; projections feed dashboard |
| Saga | Temporal remediation workflows with compensations |
| Outbox | Atomic finding + event write to prevent lost notifications |
| Idempotency Key | `sha256(log_event_id + detector_version)` on every event |
| Circuit Breaker | Around expensive LLM / NER calls |
| Bulkhead | Per-source resource pools so a noisy app cannot starve others |
| DLQ + Replay | On every async hop |
| Token Vault | KMS / Vault-backed reversible tokenization |
| Break-Glass Access | Time-boxed, justified, ledgered |
| Schema Registry / Data Contracts | Versioned event schemas; consumers reject unknown versions |
| Supervisor + Workers | Agent layer |
| ReAct / Reflexion / RAG | Verifier reasoning |
| MemGPT / virtual memory | Agent memory layer |

---

## 14. Healthcare Guardrails

- **BAA / DPA coverage** for every cloud service and the LLM provider, or run the LLM in-VPC.
- **PHI never leaves your VPC.** Detectors run in-cluster; only redacted snippets + structured metadata are sent to the LLM. Verifier reasons over `{type: "possible_MRN", context: "<redacted 200 chars>"}`, never raw logs.
- Prefer **self-hosted models** (Llama / Mistral / clinical-tuned) for the Verifier — eliminates the third-party BAA question.
- **Notifications carry IDs + severity + source only** — no PHI in any channel payload.
- **Every agent action is ledgered**: model name, prompt hash, tool calls, decision, confidence.
- **Per-data-classification KMS keys**, rotation enabled, audit trail on the keys themselves.
- **Step-up auth** for raw PHI viewing; auto-revoking break-glass; mandatory justification text.
- **Retention**: 7 years minimum; legal hold via object-lock.

---

## 15. Deployment Topologies

1. **Single-cluster, single-cloud** — k8s + Postgres + OpenSearch + Kafka + Temporal in one cluster. Cheapest, fastest to ship. **Recommended start.**
2. **Single-cluster + managed services** — same code, cloud-managed Kafka / Postgres / OpenSearch. Lower ops burden.
3. **Multi-region active-passive** — object-store replication + Postgres logical replication. For DR.
4. **Multi-cloud federated** — collectors in each cloud, central agent cluster in one. Expect egress costs.
5. **Edge collectors + central brain** — lightweight collectors at each log source; only candidates ship centrally. Best for data-sovereignty or high-volume cases.

---

## 16. Recommended Baseline

| Concern | Choice |
|---|---|
| Runtime | Kubernetes |
| Workflow / Agent Orchestration | Temporal + supervisor (LangGraph or custom) |
| Event Bus | Kafka (Redpanda for lighter ops) |
| Hot store | Postgres + pgvector (ledger + agent memory in one place) |
| Search | OpenSearch |
| Object store | Any S3-compatible (S3 / GCS / Blob / MinIO) with object lock |
| LLM gateway | LiteLLM or OpenRouter, with self-hosted model fallback for in-VPC PHI verification |
| Secrets | Vault (or cloud-native behind a Vault-compatible interface) |
| Channels | Pluggable adapter pattern, declarative rules in Postgres |
| Detectors | Regex → Presidio → clinical NER (pluggable) → allow-list |
| Retention | Postgres 90d → object store Parquet warm 2y → archival cold 7y → expire |

**Pros:** Portable across all major clouds; BAA-coverable end-to-end; agentic reasoning where it pays, deterministic fallbacks where it doesn't; tiered cost; replayable audit story.
**Cons:** Higher initial operational burden than a single-cloud serverless build; requires comfort with Kubernetes, Kafka, Temporal (or paying for managed equivalents); LLM cost discipline is critical.

---

## 17. Build Sequencing (when greenlit)

1. Define OpenAPI contract for the dashboard (findings, ledger, sources, automations, channels).
2. Stand up ingest end-to-end for **one** log source: collector → Kafka → detectors → Postgres + object store. No agents yet.
3. Build the dashboard against seeded findings (parallel with #2).
4. Add Temporal + Supervisor + Triage/Verifier agents on a single log source.
5. Add configurable channel router + first two adapters (Slack + webhook).
6. Add Context + Remediation + Notifier agents; gate any code-touching action behind HITL.
7. Add semantic memory (pgvector), consolidation jobs, importance-decay eviction.
8. Add tiered storage lifecycle and quarterly hash-chain verification.
9. Add break-glass workflow with step-up auth. *(Demo-scale slice landed in M1.6 — `POST /api/auth/step-up`, `POST /api/admin/break-glass/grants`, `GET /api/admin/findings/:id/raw`, per-access ledger events. Production still needs a real second-factor verifier (TOTP/WebAuthn/IdP) and the §18 second-person rule decision.)*
10. Harden: bulkheads, DLQs, circuit breakers, cost circuit breakers, policy guardrails.

---

## 18. Open Questions

- Which clinical NER engine for in-VPC PHI detection? (Comprehend Medical vs medspaCy vs clinical-BERT fine-tune.)
- Self-hosted LLM size for Verifier role under the latency/cost target?
- Which workflow engine if Temporal cannot be adopted? (Conductor, Cadence, or custom on Postgres.)
- Multi-tenant or single-tenant initial scope?
- Which OIDC IdP for step-up auth?
- **Break-glass second-person rule.** Should a raw-PHI break-glass grant require a second approver (compliance officer / security on-call), or is single-analyst self-grant with mandatory justification + ledgered per-access + weekly review sufficient? Must be decided **before M5** (when raw-PHI view ships). Default proposal: single-analyst for severity ≤ high; two-person for critical and for grants covering > 1 finding.

---

## 19. Chat-Over-Audit Dashboard — Architecture Options

A conversational interface over the audit ledger so analysts can ask questions like:
- "Show me all high-severity MRN leaks from the billing service this week"
- "What did the agent decide about finding F-9182 and why?"
- "Who looked at raw PHI yesterday?"

Two distinct capabilities are involved: **retrieve & explain** (read-only Q&A) and **act** (draft messages, open tickets, kick off remediation). The architecture must keep them separated; action paths are always HITL-gated.

### Options evaluated

| | A: Single-shot RAG | B: Tool-using Agent | C: Text-to-SQL | **D: Multi-Agent Supervisor** |
|---|---|---|---|---|
| LLM calls per turn | 1 | 1–3 | 2 | 3–5 (tiered) |
| Latency | Fastest | Fast | Medium | Medium |
| Handles aggregates / filters | ✗ | ✓ | ✓ | ✓ |
| Safety surface | Smallest | Small | **Large (SQL generation)** | Small |
| Eval complexity | Easy | Medium | Hard | Hard |
| Fits this design | Partially | Cleanly | Partially | **Fully** |
| Build effort | XS | S | M | M |
| Cost at >100k candidates/day | Low (no triage) | Medium | Medium | **Lowest with tiering** |

#### Option A — Single-shot RAG
Embed query → hybrid retrieval (pgvector + FTS, Reciprocal Rank Fusion) → one LLM call with retrieved findings → stream answer with mandatory citations.
- **Pros:** Fastest, cheapest, easiest to evaluate, smallest blast radius.
- **Cons:** Cannot answer aggregate/filter questions ("count high-severity in billing this week"); no multi-step reasoning.
- **Best for:** Pure "find / explain" workloads at low volume.

#### Option B — Tool-using Agent
Tool-use loop with typed JSON tools (Zod-validated): `semantic_search`, `keyword_search`, `structured_query` (typed filter, not raw SQL), `get_finding`, `get_ledger_entries`. Agent decides which tools to call.
- **Pros:** Handles find + filter + aggregate safely; no raw SQL ever generated; every tool call is auditable; matches OpenAPI + Zod repo conventions; maps directly onto Bedrock AgentCore and Vertex Agent Builder.
- **Cons:** 1–3 LLM calls per turn; slightly more code than A.
- **Best for:** Typical chat-over-audit use case.

#### Option C — Text-to-SQL Agent
LLM generates SQL against a read-only `findings_redacted` view; SQL is parsed, validated against an allow-list, and `LIMIT`-enforced before execution.
- **Pros:** Maximum analytic flexibility — can answer questions you didn't anticipate.
- **Cons:** SQL-validation layer is high-stakes code; bigger surface for prompt injection; harder to exhaustively test. **Not recommended as v1 for a PHI system.**
- **Best for:** v2, once Option B is solid and you know what queries analysts actually want.

#### Option D — Multi-Agent Supervisor
Deterministic Supervisor (code, not an LLM) orchestrates specialist workers: Router (cheap model), Retrieval (does Option B's tool loop), Explain (strong model, grounded synthesis with citations), Action (HITL proposals, phase 2). Mirrors §7 of this document.
- **Pros:** Cleanest separation of concerns; tiered model usage (cheap router, strong explainer); future-proof for the Action path; native fit for Bedrock AgentCore and Vertex Agent Builder.
- **Cons:** ~2× the orchestration code on day one; Temporal becomes a hard dependency; more moving parts to debug.
- **Best for:** Production scale (≥100k candidates/day) and when adding write/remediation actions.

### Selected
- **Day-one production for high-volume sources:** Option D. See `DESIGN_OPTION_D.md` for full deep dive with metrics-driven cost analysis.
- **Lower-volume or early-prototype scope:** Option B as a stepping stone to D.

### Cross-cutting requirements for any option
- **Mandatory citations** — answers without finding-ID citations are dropped at the post-processor; UI shows "cannot verify" banner.
- **No raw PHI in prompts** — all reads go through `findings_redacted` view; embeddings computed over redacted text only.
- **ABAC at the data layer** — Postgres RLS binds the connecting role to the user's claims so the model literally cannot see rows the user can't.
- **Action proposals, not executions** — any write tool returns a proposal; the human clicks confirm; both are ledgered.
- **Hybrid retrieval (vector + FTS + structured)** merged via Reciprocal Rank Fusion before generation.
- **Streaming UI (SSE)** with events: `tool_call`, `tool_result`, `evidence`, `token`, `proposed_action`, `done`.
- **Three-pane UI:** conversation | evidence cards (cited findings) | preview drawer (full finding detail).
- **Conversation memory** — sliding window + hierarchical summarization (§8 patterns); full transcript in Postgres (TTL); audit copy in ledger (immutable).

### API surface (fits this repo's OpenAPI-first conventions)
```
POST /chat/sessions                        → { session_id }
POST /chat/sessions/{id}/messages          → SSE stream of agent events
POST /chat/actions/{proposed_id}/confirm   → executes a gated action
GET  /chat/sessions/{id}                   → conversation history (redacted)
GET  /findings/{id}                        → existing endpoint, cited by chat
```

---

## 20. Multi-Cloud Agent Runtime (Bedrock AgentCore + Vertex AI)

The agent layer must run on AWS (Bedrock AgentCore) and GCP (Vertex AI Agent Builder), and locally for dev — without re-implementing agents per cloud. Solved with one narrow interface and three adapters.

### Abstraction

```
LlmAgentRuntime (interface)
  invokeAgent(agentName, input, tools, context) → AsyncIterable<AgentEvent>

AgentEvent: tool_call | tool_result | token | citation | done | error

Implementations:
  • BedrockAgentRuntime       (production AWS — Bedrock AgentCore)
  • VertexAgentRuntime        (production GCP — Vertex AI Agent Builder)
  • DirectLlmRuntime          (local dev / on-prem) — LiteLLM or Replit AI integration

ToolRegistry (cloud-neutral)
  register(name, zodSchema, handler)
  exportFor("bedrock") → AgentCore action group OpenAPI
  exportFor("vertex")  → Vertex function declarations
  exportFor("direct")  → in-process map
```

**Tools are defined ONCE in code with Zod.** The registry compiles them per runtime. No re-implementation per cloud — this is the single biggest win of the abstraction.

### Mapping table

| Component | AWS (Bedrock AgentCore) | GCP (Vertex AI Agent Builder) | Local / dev |
|---|---|---|---|
| Supervisor | Temporal workflow on EKS/ECS | Same Temporal workflow on GKE | Temporal local / dev server |
| Triage / Context / Notifier / Compliance agents | Bedrock Agent with Haiku / Llama | Vertex Agent with Gemini Flash | `DirectLlmRuntime` → Gemini via Replit AI integration |
| Verifier / Chat / Remediation agents | Bedrock Agent with Claude Sonnet | Vertex Agent with Gemini 1.5 Pro | Same |
| Tool execution | AgentCore action group → our Express API (IAM-signed) | Vertex function-calling → our Express API (SA ID-token) | In-process |
| Per-session memory | AgentCore session memory (optional) — our ledger is source of truth | Vertex session memory (optional) — same | Postgres |
| Guardrails | Bedrock Guardrails | Vertex Safety Filters + Model Armor | Application-level policy layer |
| Vector store | Bedrock Knowledge Bases (OpenSearch Serverless or pgvector on RDS) | Vertex AI Vector Search (or pgvector on Cloud SQL) | pgvector on local Postgres |
| LLM gateway | Direct Bedrock invoke | Direct Vertex invoke | LiteLLM / Replit AI integration |

### Deployment posture
- **AWS-native:** Supervisor (Temporal on EKS) → Bedrock AgentCore agents → tools in our service behind IAM-authenticated endpoint. PHI never leaves your AWS account. Covered by AWS BAA.
- **GCP-native:** Supervisor (Temporal on GKE) → Vertex Agents → tools behind service-account-authenticated endpoint. PHI never leaves your GCP project. Covered by Google BAA.
- **Local/dev:** Supervisor in-process or via Temporal dev server; agents via `DirectLlmRuntime` → Gemini. Buildable in Replit with no cloud account.

### Pros / cons
- **Pros:** Same agent definitions deploy to either cloud; tools written once; BAA covered per cloud; can graduate dev → prod without re-architecting.
- **Cons:** Three adapters to maintain; adapter contract tests required to keep behavioral parity; some platform-specific features (e.g. Bedrock Guardrails policies) need per-cloud configuration.

### Adapter contract testing
Every adapter is tested against the same conformance suite: same prompts → same expected tool-call sequence → same answer shape. Differences in token-level output are tolerated; differences in tool calls or citation behavior are failures.

---

## 21. Source Environment Sizing

Real metrics from the target environment that drive sizing decisions:

| Metric | Value | Drives |
|---|---|---|
| Total log groups | 304 | Subscription-filter fan-out |
| Total stored | 3.19 TiB | Tiered storage sizing |
| 7-day ingest | 733.55 GiB | Kafka throughput |
| 7-day events | 1,393,676,547 | Detector sharding |
| Avg daily ingest | 104.79 GiB | ~38 TiB/year |
| Avg daily events | ~199M (~2.3k/s sustained, peaks 5–10k/s) | Funnel mandatory |
| Groups without KMS | 304 | Compliance findings on day one |
| Groups with no retention | 127 | Compliance findings on day one |
| Groups with subscription filters | 1 | Ingest fan-out is task #1 |
| Delivery errors / throttling | 0 | Safe to add subscribers |

### Implications baked into the design
- Funnel: 199M events/day → ~20k–200k candidates/day → ~200–2,000 deduped findings/day before any LLM call.
- Strong-model spend targets ~200 findings/day, not 200M events. Estimated daily LLM cost ~$30–$120 with tiering vs ~$3k–$15k naive.
- Compliance Agent emits findings for the 304 no-KMS and 127 no-retention groups as first-class findings.
- See `DESIGN_OPTION_D.md` §4 for the full funnel math.

---

## 22. Agent Communication Protocols (AG-UI + A2A)

The system adopts two emerging open protocols so that the UI and the agent plane are runtime-agnostic and interoperable.

### 22.1 Why both (and why they don't compete with Temporal)

Temporal and A2A solve different problems and compose cleanly:

| | **Temporal** | **A2A** |
|---|---|---|
| What it is | Workflow orchestration engine | Agent-to-agent communication protocol |
| Owns | Durability, retries, idempotency, replay, timers, signals, sagas | Wire format, capability discovery, task lifecycle, streaming |
| Decision boundary | "When does step N run, what if it fails?" | "How does step N invoke worker X over the network?" |

**A Temporal activity is *implemented* by making an A2A call to a worker.** Temporal still owns orchestration; A2A owns the call shape. They are not alternatives.

### 22.2 AG-UI — UI ↔ Chat Agent

Replaces the custom SSE event vocabulary at the Chat agent's HTTP boundary with the AG-UI event protocol (standardized events for tool calls, tool results, messages, state deltas, and HITL prompts).

| Concern | Decision |
|---|---|
| Transport | SSE (HTTP) carrying AG-UI events |
| Event vocabulary | `RUN_STARTED`, `TEXT_MESSAGE_*`, `TOOL_CALL_*`, `STATE_DELTA`, `HITL_REQUEST`, `RUN_FINISHED`, etc. (AG-UI spec) |
| HITL prompts (proposed actions) | AG-UI HITL request/response; UI renders confirm-cards inline |
| Client | Hand-rolled React hooks or CopilotKit components |

**Pros:** Drop-in clients; interop with any AG-UI-compliant agent runtime; standardized HITL shape; future CLI/mobile clients work without server changes.
**Cons:** Spec is young — some churn risk; adapter shim required between AG-UI's LangGraph-shaped assumptions and our Temporal+Bedrock/Vertex agent runtimes.

### 22.3 A2A — Supervisor ↔ Workers (and external systems)

All agent invocations — Supervisor calling Triage/Verifier/Context/etc., or external systems calling our agents — go over A2A. Each worker exposes an A2A endpoint with an `agent.json` capability card.

| Worker | A2A server hosted by |
|---|---|
| Local TypeScript worker | Our service (A2A server library) |
| Bedrock AgentCore agent | Thin A2A → Bedrock invoke adapter |
| Vertex AI agent | Thin A2A → Vertex invoke adapter |

**Inside the cluster (Supervisor → workers):**
- Temporal activity calls `a2aClient.sendTask(workerUrl, taskMessage)`.
- A2A streaming events (`message`, `task_status_update`, `artifact`) bubble back into the Temporal activity, which records them as workflow events.
- Temporal still provides retry, idempotency (via A2A task IDs), and replay.

**Facing external systems:**
- Same A2A endpoint, same capability cards, different auth scope.
- A third-party SOC bot can invoke the Verifier or Chat agent with the same protocol the Supervisor uses.
- Authorization is enforced at the API gateway via ABAC claims in the A2A `Message` metadata.

### 22.4 How it composes with the multi-cloud runtime (§20)

The `LlmAgentRuntime` interface from §20 is now satisfied by an A2A client:

```
LlmAgentRuntime.invokeAgent(agentName, input, tools, context)
  → a2aClient.sendTask(registry.lookup(agentName), buildA2AMessage(input, context))
  → returns AsyncIterable<AgentEvent> mapped from A2A stream events
```

Adapters become A2A servers:

| Adapter | Underlying execution |
|---|---|
| `BedrockA2AAdapter` | A2A server → Bedrock AgentCore agent invoke |
| `VertexA2AAdapter` | A2A server → Vertex AI agent invoke |
| `DirectA2AAdapter` | A2A server → in-process LLM call via LiteLLM / Replit AI integration |

`ToolRegistry` (§20) still compiles tool definitions per runtime; the A2A layer is orthogonal — it's about *how the agent is invoked*, not *what tools it exposes*.

### 22.5 Trade-offs of the full standards path

**Pros:**
- Workers are drop-in interchangeable (local / Bedrock / Vertex / third-party) without Supervisor code changes.
- UI is runtime-agnostic — any AG-UI client works.
- External integration is free — same protocol facing outward.
- One auth/streaming/error model across the whole agent plane.

**Cons:**
- Two evolving specs to track; lock-in to early versions carries churn risk. Mitigate with a thin internal facade that lets us pin versions and adapt.
- Extra JSON-RPC hop for in-cluster Supervisor → worker calls (small latency cost). Worth it for the interchangeability.
- A2A's discovery/negotiation features are partially unused for trusted in-cluster traffic — accepted cost for uniformity.

### 22.6 Updated layer summary

| Layer | Transport / Protocol |
|---|---|
| UI ↔ Chat Agent | **AG-UI** over SSE |
| Chat Agent ↔ Supervisor | In-process (same service) or **A2A** if Chat Agent is split out |
| Supervisor (Temporal) ↔ Workers | **A2A**, inside Temporal activities |
| External systems ↔ Our agents | **A2A** (same endpoints, scoped auth) |
| Inter-stage data flow | Kafka (events) — unchanged |
| Orchestration | Temporal — unchanged |

---

## 23. Critical Gaps & Mitigations

A critical review of the design surfaced gaps that must be addressed before production. They are listed here with the mitigation that becomes a binding part of the design.

### 23.1 Prompt injection from log content (highest-severity gap)

> **Implementation status (M1.6):** Role-isolated prompting, source-tagged context, per-agent tool allow-list, **tool-arg revalidation**, honeypot canaries, and output PHI scan are all live in this repo. Tool-arg revalidation (`artifacts/api-server/src/lib/policy.ts → validateToolArgs`) runs after Zod parse on every `ToolRegistry.call`: canary-token scan, PHI scan, 8KB arg-size cap, finding-id whitelist (`[A-Za-z0-9_-]{1,64}`). Failures fire a `chat-agent` `onPolicyViolation` hook that creates an incident finding (critical for canary trips, high otherwise) and ledgers `agent.canary_in_tool_args` / `agent.tool_args_policy_violation`. Raw arg values never enter the ledger payload — only violation kind + tool name. Platform guardrails (Bedrock/Vertex/Llama Guard) and the network-policy egress allow-list remain deferred to the production runtime.

We ingest **user-controlled strings** (log content can be influenced by attackers who control any logged input) and pass them — even redacted — into LLM prompts. Attack surfaces:

- **Verifier** reads redacted log context → direct injection.
- **Chat Agent** retrieves findings via RAG → indirect injection via stored content.
- **Notifier** drafts messages from finding content → injection routed into Slack/PagerDuty/etc.
- **Remediation** reads code → injection from poisoned comments.

**Mandatory mitigations:**
- **Role-isolated prompting.** System instructions in a sealed envelope; untrusted content fenced inside explicit tags (e.g. `<untrusted_content>…</untrusted_content>`) with a system instruction to never follow instructions found inside those tags.
- **Source-tagged context.** Every retrieved snippet carries a provenance label (`source=log:billing-svc, trust=untrusted`); prompts instruct the model to treat untrusted content as data only.
- **Tool allow-list per agent.** Each agent's `ToolRegistry` view exposes only the tools it needs. Notifier cannot call `read_raw_phi`; Chat Agent cannot call `open_pr`.
- **Tool-arg revalidation.** Before any tool executes, its arguments are re-validated against the policy layer — not just the Zod schema. Example: `send_notification` rejects payloads containing PHI patterns even if the agent tried to include them.
- **Platform guardrails.** Bedrock Guardrails / Vertex Model Armor / Llama Guard on both input and output of every LLM call.
- **Egress allow-list.** Agents make outbound network calls only via explicit tool handlers; raw HTTP from agent runtimes is blocked at the network policy level.
- **Honeypot canaries.** Seed data includes canary tokens; any tool call that includes a canary in arguments triggers an alert and ledgered incident — detects compromised agents in eval and production.
- **Output PHI scan.** Every LLM output passes back through the detector pipeline before reaching the UI or any channel; PHI in output is a finding *about the agent*, not a leak.

### 23.2 Audit ledger durability and verification

The hash-chained ledger is tamper-evident only if the chain survives operational reality.

- **Append-only Postgres write path** — single writer, advisory lock, transactional `prev_hash → hash` link. No update or delete grants on the role used to write.
- **External notarization.** Every 1,000 entries (or daily, whichever first) the current head hash is written to a separate cloud account / project with Object Lock (`compliance` mode). Re-verification compares against these checkpoints.
- **Backup contract.** PG backup captures only complete checkpoint windows; restore procedure rebuilds verification from the last externally-notarized checkpoint.
- **Verification SLA.** A chain-walk job runs hourly on the last 24h and weekly on the full chain. Mismatch pages on-call within 5 minutes.
- **Key custody.** The notarization key is held in a separate KMS in a separate account, with break-glass rotation procedure documented.

### 23.3 Secrets vs PHI taxonomy

Secrets-in-logs and PHI-in-logs are different problems and need different paths:

| Class | Examples | Severity default | Primary remediation | Notification |
|---|---|---|---|---|
| **PHI** | MRN, patient name + DOB, clinical notes | Per HIPAA classification | Redact at source, tokenize | PHI-stripped notice to owner |
| **Secrets** | API keys, JWTs, AWS keys, DB passwords | Always critical | **Immediate rotation workflow**, redact | Page on-call security |
| **PII (non-PHI)** | Customer email, phone | Medium by default | Mask or tokenize | Owner notified |
| **Internal** | Internal user IDs, customer IDs | Low | Optional masking | Daily digest |

Each class has its own detector family, severity baseline, and remediation playbook. The ledger records the class on every finding.

### 23.4 Threat model — required artifact

A STRIDE threat model must exist before production. The repo's `threat_modeling` skill is the canonical way to produce it. Output: `threat_model.md` covering at minimum:
- Trust boundaries between log source / ingest / detectors / agent plane / dashboard / external channels
- Per-component STRIDE analysis
- Compromised-agent scenarios (prompt injection chain to exfiltration)
- Insider threat (rogue analyst with break-glass)
- Supply-chain (LLM provider, dependencies)
- Mitigations mapped to the controls in this document

### 23.5 Eval harness — concrete definition

"Eval harness" is named in earlier sections without definition. Binding definition:

| Eval | Owns | Inputs | Pass criteria |
|---|---|---|---|
| **Detector eval** | Stage 1 + 2 | Labeled gold set of ~5k log lines per class (PHI/secrets/PII/internal/benign) | Precision ≥ target per class, recall ≥ target per class; fail blocks detector deploy |
| **Triage eval** | Triage Agent | ~500 labeled candidates with expected severity + dedup decision | Severity accuracy ≥ target; dedup F1 ≥ target |
| **Verifier eval** | Verifier Agent | ~500 labeled candidates with expected confirm/refute + reason class | Confirm F1 ≥ target; reasoning rubric score ≥ target |
| **Chat eval** | Chat Agent | ~200 (question, expected_finding_ids, expected_answer_summary) tuples | Citation correctness ≥ target; faithfulness score ≥ target |
| **End-to-end** | Whole funnel | Synthetic stream injected into ingest with known ground truth | Detection latency p95 within SLO; coverage ≥ target |
| **Red-team / injection** | Whole system | Adversarial log lines, prompt-injection payloads, canary tokens | Zero canary exfiltration; injection blocked at guardrail layer |

Gold sets are curated by analysts via the dashboard ("save this as a labeled eval case"). Every prompt change, model change, or detector change runs the relevant evals; regressions block deploy.

### 23.6 LLM/agent observability

The audit ledger records what happened. Observability covers why and how.

| Concern | Tool |
|---|---|
| Distributed tracing | OpenTelemetry — span per workflow / activity / agent invocation / tool call |
| LLM trace store | Langfuse (self-hosted, OSS, BAA-friendly) — full prompt/response/tool-call traces |
| Cost dashboard | Per-agent, per-tenant, per-finding token + dollar tracking |
| Budget alerts | Trip the cost circuit breaker (§ existing) **before** monthly limits, not after |
| Latency SLIs | First-token, full-answer, end-to-end finding-visible |
| Tool-call patterns | Anomaly detection on agent-tool histograms (sudden spike = compromise signal) |

### 23.7 Late, out-of-order, and truncated logs

| Issue | Mitigation |
|---|---|
| CloudWatch 256 KB truncation | Detector tags truncated events; PHI flagged in truncated logs gets a "potentially incomplete" marker |
| Late-arriving logs (hours) | Stage 2 dedup uses event-time hour bucket with watermark + 6-hour grace window |
| Out-of-order events | Idempotency key `sha256(log_event_id + detector_version)` ensures replays merge correctly |
| Clock skew | All timestamps stored as both source-time and ingest-time; ledger uses ingest-time for chain ordering |

### 23.8 Backfill & detector replay

When a new detector or detector fix lands, we want to re-scan historical logs.

- Raw logs in WORM storage are the durable replay source.
- A **replay workflow** (Temporal) takes `{detector_version, time_range, source}` and runs Stage 1+2 over historical Parquet files, emitting candidates with `replay=true` tag.
- Triage Agent dedups against existing findings; only net-new findings reach Verifier.
- Cost-bounded: replay budget per run is enforced.

### 23.9 Disaster recovery (RTO/RPO)

| Component | RPO target | RTO target | Mechanism |
|---|---|---|---|
| Audit ledger | 0 (no data loss tolerable) | 1 hour | PG synchronous replica + external notarization checkpoints |
| Findings (hot) | 5 minutes | 1 hour | PG streaming replica |
| Object store (warm/cold) | 0 | N/A | Cross-region replication on raw + ledger buckets |
| Kafka | 5 minutes | 1 hour | MM2 or cross-region cluster |
| Temporal | 5 minutes | 4 hours | Managed Temporal Cloud (cross-region) or backup of history store |
| Agent runtime | N/A | Minutes | Stateless — redeploy from container registry |

### 23.10 Right-to-be-forgotten vs 7-year retention

These conflict for findings tied to identifiable patients.

- **Policy:** findings store tokenized identifiers via the Token Vault (KMS-reversible). On valid erasure request, the vault entry is deleted; the finding remains for retention but becomes non-re-identifiable.
- Legal hold suspends erasure on specific identifiers; documented procedure.

### 23.11 Tenant isolation (if multi-tenant)

If multi-tenancy is in scope:
- Per-tenant KMS key for at-rest data.
- Per-tenant pgvector namespace; **no shared embeddings across tenants** (cross-tenant retrieval leakage risk).
- Per-tenant LLM context isolation; no prompt caching across tenants.
- RLS policies on every table that holds finding/ledger/conversation data.

**v1 default:** single-tenant, with the table structures and RLS policies in place so multi-tenancy is additive, not a rewrite.

### 23.12 Protocol-stack completeness — adopt MCP for tool exposure

§22 adopted AG-UI (UI↔agent) and A2A (agent↔agent). The missing piece is **MCP (Model Context Protocol)** for **tool exposure**.

- **MCP** = standard for how tools are described to and invoked by LLMs (Bedrock, Claude, OpenAI all speak MCP).
- The current "Zod → per-runtime tool format" compilation is fine, but compiling to MCP gives free interop with any MCP-capable runtime.
- **Decision:** `ToolRegistry` exports tools in MCP format as the canonical wire form; Bedrock/Vertex adapters that don't speak MCP natively translate from MCP, not from Zod directly.

The protocol stack is now:

| Layer | Protocol |
|---|---|
| UI ↔ Chat Agent | **AG-UI** |
| Agent ↔ Agent | **A2A** |
| Agent ↔ Tools | **MCP** |
| Workflow orchestration | Temporal (not a protocol — engine) |
| Inter-stage data | Kafka (not a protocol — message bus) |

### 23.13 pgvector at scale & embedding strategy

- **Index:** HNSW with `m=16, ef_construction=64` as a starting point; reconsider IVF if recall drops at >10M vectors.
- **Embedding granularity:** embed deduped templates, not raw events. Cuts embed cost ~100×.
- **Versioning:** embeddings tagged with model version; new model = parallel index, background backfill, atomic cutover, drop old.
- **Graduation trigger:** if query p95 > 200ms at projected volume, migrate to Qdrant or Vespa behind the same retrieval interface (no agent code changes).

### 23.14 A2A maturity hedge

A2A is young. Mitigation:
- Internal `AgentChannel` facade interface; the A2A implementation lives behind it.
- If A2A spec changes incompatibly, only the implementation behind the facade changes.

### 23.15 SLIs / SLOs

| SLI | SLO (initial) | Error budget |
|---|---|---|
| Ingest event-time → finding visible | p95 ≤ 5 min | 1% of findings exceed |
| Detection coverage (red-team eval) | ≥ 95% recall on labeled set | 5% miss tolerated per quarter |
| Chat first-token latency | p95 ≤ 2 s | 1% of turns exceed |
| Chat full-answer latency | p95 ≤ 10 s | 1% of turns exceed |
| Notification delivery | p99 ≤ 30 s | 0.1% delayed |
| Ledger verification | 100% hourly pass | Any failure pages on-call |
| Agent runaway-cost guard | 100% requests within budget | Any breach pages on-call |

### 23.16 MCP usage rules

§23.12 picks MCP as the canonical wire form for `ToolRegistry`. The rules below pin down *how* it's used so M0 doesn't bake in a shape we'd have to undo.

- **Direction & transport.** For M0–M5, `ToolRegistry` runs **in-process**; the agent runtime's MCP client connects over stdio. Cross-process MCP (Streamable HTTP) is enabled only when a tool category needs its own deployment (e.g. Remediation's `propose_pr` calling out to a GitHub-side service).
- **Scoped views, not a global server.** Each agent gets a **scoped MCP view** that advertises only its allow-listed tools. An agent cannot discover or invoke tools outside its view. Tool allow-lists per agent live in `docs/PROMPTS.md`; the registry compiles them into per-agent MCP descriptors at boot.
- **Native runtime mapping.** Bedrock and Vertex don't speak MCP wire format directly — both consume JSON-Schema tool descriptors. The adapter compiles MCP → Bedrock `Tool` / Vertex `FunctionDeclaration` at runtime-init time. Translation is one-way (MCP is the source of truth); never modify a runtime's native shape and back-port.
- **Tool-arg revalidation placement.** §23.1 mandates a revalidation pass against the policy layer. It runs **after MCP arg deserialization, before the handler executes** — inside the trusted process, never inside the agent runtime. The runtime sees only the validated/rejected outcome.
- **HITL tools are not in any agent's view.** `send_*`, `open_pr`, `apply_config_change`, `read_raw_phi` are **registered but not exposed via MCP to any agent**. Agents call only `propose_*` variants. The HITL approve handler in the API is the sole caller of the real action tools. Periodic audit: a CI check fails if any agent's MCP descriptor contains a non-`propose_` write tool.
- **Third-party MCP servers.** Disabled by default. Enabling one requires: (a) a signed manifest entry in `config/mcp_allowlist.yaml` referenced by code review; (b) the server runs as a separate process with its own egress allow-list; (c) a security-review ticket linked from the manifest. Threat-model rule (Elevation of Privilege) is the source of authority for this.
- **Tool identity in ledger entries.** Every tool invocation in a ledger entry records `{tool_name, tool_version, mcp_descriptor_hash}` so behavior diffs across MCP descriptor changes are reconstructable.
- **Canary in tool args.** §23.1 canary check runs on every tool argument **before** the handler — implemented as an MCP middleware in the registry, not per-tool.

### 23.17 Policy layer — concrete definition

> **Implementation status (M1.6):** Implemented in-process at `artifacts/api-server/src/lib/policy.ts`. `validateToolArgs(toolName, args)` is the v1 ruleset: canary-token scan, PHI-in-args scan, 8KB JSON-size cap, and per-arg finding-id format check. Deny outcome surfaces as `{ ok: false, code: "policy_violation", kind, tool }` from `ToolRegistry.call`; the chat-agent's `onPolicyViolation` hook writes the incident finding + ledger entry. Versioning, full rule-shape (`{id, applies_to, predicate}`), and `policy_hash` in every ledger entry are deferred until rule count grows.

§23.1's "tool-arg revalidation against the policy layer" referenced an undefined component. Specification:

- **Location.** A first-party TypeScript library (`lib/policy/`), in-process with the API and registry. Not OPA / Rego for v1 — overhead and operational cost not justified at our rule count; revisit if rule count exceeds ~50.
- **Rule shape.** Each rule: `{ id, applies_to: [tool_names], predicate(args, ctx) => allow | { deny, reason } }`. Rules are pure TypeScript functions, code-reviewed, version-controlled, eval-tested.
- **What it checks beyond Zod.** Cross-field invariants (`finding_id must belong to ctx.tenant_id`), value-range invariants (`limit ≤ 200`), identity/authorization invariants (`actor must have scope X for tool Y`), deny-list checks (canary tokens, known-bad patterns).
- **Deny outcome.** Returns `{deny, reason}` → handler aborts, ledger entry recorded with `entry_type='tool_arg_denied'`, error returned to agent.
- **Versioning.** Policy bundle has its own semver and `policy_hash`; bundled into every ledger entry alongside `prompt_hash`.
- **Failure mode.** If the policy layer throws, tools fail closed (deny). Tested via the red-team eval.

### 23.18 Ledger writer leadership & failover

§23.2 specifies "single writer holding a Postgres advisory lock". That covers concurrent access; it doesn't specify what happens when the writer dies mid-batch.

- **Leadership.** Exactly one ledger-writer process holds `pg_advisory_lock(LEDGER_LOCK_ID)`; replicas attempt acquisition every 5 s. PG releases the lock automatically on session loss.
- **In-flight batch on failover.** Ledger writes are single-statement transactions per entry, never multi-entry batches. There is no "in-flight batch" to recover — the last committed entry is the last entry.
- **Head-hash cache coherence.** The writer caches `prev_hash` in memory. On startup it reads the head from PG (`SELECT hash FROM ledger_entries ORDER BY seq DESC LIMIT 1`) inside the same transaction that holds the advisory lock; this prevents a stale-cache race after failover.
- **Split-brain protection.** Two writers cannot both hold the advisory lock (PG enforces). If a writer is partitioned from PG (cannot acquire lock) it must not buffer entries — it returns `503` to callers. Callers retry against the elected writer.
- **Notarization lag tolerance.** Notarization is asynchronous to writes. On writer failover, the new writer resumes notarization from the last externally-notarized checkpoint; no entries are lost because all are durably committed in PG before notarization runs.
- **Disaster mode.** If PG primary is lost and replica is promoted, the new writer must verify chain integrity from the last externally-notarized checkpoint forward **before** accepting new writes. Boot-time chain verification (§24) is the same mechanism.

### 23.19 Time, clocks, and ordering

The hash chain orders entries by `seq` (monotonic bigserial), not by wall clock. But several downstream claims depend on times. Specification:

- **Three timestamps per finding.** `event_time` (from the log source; untrusted), `ingest_time` (set by ingest worker on Kafka write; trusted), `finding_time` (set by Triage/Verifier on write; trusted).
- **Late-arriving events.** Events with `event_time` older than 24 h are accepted but flagged; findings derived from them carry `late=true`. The dashboard groups late findings separately so SLO calculations aren't poisoned.
- **Skew tolerance.** All trusted timestamps come from NTP-synced services with ≤ 100 ms expected skew; alert if observed skew exceeds 1 s.
- **Time zone.** All stored timestamps are UTC; the dashboard renders in the analyst's configured TZ; chat questions like "yesterday" resolve against the analyst's TZ, not the server's. Default analyst TZ is set at sign-up.
- **Hash chain monotonicity.** `seq` is the only ordering authority for the chain. Two entries written in the same millisecond have strict `seq` ordering. The notarization checkpoint records `{seq, hash, ingest_time}` — auditors verify by `seq`, not time.
- **Replay determinism.** Detector replay (§23.8) re-derives `event_time` from WORM raw; it does **not** rewrite `ingest_time` on the replayed finding (replay-time is a new `ingest_time`).

### 23.20 Detector evolution & finding stability

A detector improvement (new rule, retrained NER, fixed FP) changes how the same log line would be classified. Findings already in the table must remain stable.

- **Findings are immutable in class/severity** once written. A re-detected event under a new detector creates a **new finding** with `replaces_finding_id` set; the old one is marked `superseded_by` (status transition, ledgered).
- **Detector version on every finding.** `detector_version_at_creation` is part of the finding row; never updated.
- **Replay scope is bounded.** Replay (§23.8) re-runs detectors over WORM. Output is written to a separate `replay_findings` table and reviewed before any are promoted to `findings`. No automatic merge.
- **Eval gate before replay.** A detector version cannot be used for production replay until its eval (§EVALS.md §1) passes the *production* thresholds, not just the *PR* thresholds. The gap exists because nightly-eval thresholds are tighter than per-PR thresholds.
- **Embedding stability.** Same rule applies to embedding model changes (§23.13): new model = new index, no in-place mutation; agents may reference either index via the retrieval interface during cutover.

### 23.21 HIPAA-specific operational gaps

Several HIPAA requirements need named owners and runbooks; the design currently implies them.

- **Accounting of disclosures (§164.528).** Patients can request a 6-year accounting of disclosures of their PHI. The ledger contains the source data; a `compliance_officer` API endpoint MUST exist that, given a tokenized patient identifier, returns the accounting in HIPAA format. Owner: Compliance Agent (M6+); endpoint exists earlier as a manual SQL query against the ledger.
- **Breach notification clock (§164.404).** Covered entities have ≤ 60 days from discovery of an unsecured-PHI breach to notify affected individuals. "Discovery" starts when a confirmed PHI-in-output finding is created. A runbook MUST exist that auto-creates a tracking incident with a 60-day countdown timer on every `phi_in_output` finding above a configured severity threshold.
- **Minimum necessary (§164.502(b)).** The redaction-by-default + step-up-for-raw pattern implements this. Eval gate: red-team eval includes "agent returned more than necessary" cases (analyst can complete the task using the redacted view) — failure rate must be 0.
- **Sub-processor BAA chain.** Every external service that touches PHI or derived data needs BAA coverage: Bedrock (AWS BAA), Vertex (Google Cloud BAA), Temporal Cloud (their BAA), notification channels (none provide BAA for PHI — therefore PHI MUST NOT cross channel boundaries, enforced by §23 Notifier PHI guard). LLM providers used in dev (Replit AI / Gemini) operate **without BAA** — dev environment MUST use synthetic data only, enforced by a tenant flag.
- **Designated security/privacy officer.** HIPAA requires named individuals. Out of scope for this design but in scope for the deployment runbook.
- **Workforce training tracking.** HIPAA-required workforce training is operational, not architectural. Out of scope here; named in `OPEN_QUESTIONS.md` for the deployment phase.

### 23.22 Idempotency on remediation tool calls

HITL approval of a remediation proposal triggers a write to an external system (GitHub PR, Slack message, cloud config change). Network retries on the approval click MUST NOT cause the external action to execute twice.

- **Idempotency key.** Every action tool (`open_pr`, `send_notification`, `apply_config_change`) requires an `idempotency_key` parameter. The key is `proposal_id` (UUID of the `remediation_proposals` row).
- **Server-side dedup.** Before calling the external system, the API checks `remediation_proposals.executed_at` and `external_ref`. If both are set, return the cached `external_ref` as success — never re-invoke the external system.
- **External system idempotency.** Where the provider supports it, pass the key through (GitHub PRs by title+head SHA; Slack via `Idempotency-Key` header / `metadata.event_payload.id`; cloud APIs via their `client-request-token` equivalents). This protects against the API process crashing *between* the external call and the row update.
- **Ledger transitions.** State changes (`pending` → `approved` → `executing` → `executed` | `failed`) are separate ledger entries keyed on `proposal_id`. Replayed approval clicks produce no new ledger entries past `executed`.
- **Test gate.** End-to-end eval includes "approve clicked twice" cases for every action tool; expected = exactly one external invocation.

---

## 24. Revised M0 — Walking Skeleton (gap-aware)

The original M0 (one finding, one agent, one tool, Gemini, AG-UI events, three-pane UI, hash-chained ledger) is the right scope. The revision below bakes in cheap-to-add-now / expensive-to-add-later items from §23.

### 24.1 Scope of Revised M0

| Capability | M0 | Notes |
|---|---|---|
| Drizzle schemas: findings, ledger_entries, chat_sessions, chat_messages | ✓ | Include `classification` enum (PHI/Secrets/PII/Internal) on findings from day one |
| RLS policies on findings + ledger | ✓ | Single placeholder claim (`tenant_id='default'`); structure in place |
| `findings_redacted` view | ✓ | All reads go through view, never table |
| Seed data | ✓ | 5–10 redacted findings + 1 secrets-class + 2 compliance-gap (KMS, no-retention) findings |
| OpenAPI block + Orval codegen | ✓ | `/chat/sessions`, SSE `/messages`, `/findings/{id}` |
| `ToolRegistry` interface + one MCP-shaped tool (`get_finding`) | ✓ | Sets the canonical tool surface |
| Chat Agent calling Gemini via Replit AI integration | ✓ | Single-turn for M0; tool loop in M1 |
| Role-isolated prompting + source-tagged untrusted content | ✓ | Cheap to do now; impossible to retrofit cleanly |
| Tool-arg revalidation pass | ✓ | Even with one tool, the pattern lands |
| Per-request token budget + spend log | ✓ | Hard cap; logs to `chat_audit` |
| Output PHI scan (regex-only) before reaching UI | ✓ | Guard against model echoing PHI |
| AG-UI events on SSE (subset: `RUN_STARTED`, `TEXT_MESSAGE_*`, `TOOL_CALL_*`, `RUN_FINISHED`) | ✓ | Adopt the shape now |
| Hash-chained ledger per chat turn | ✓ | With `{agent_name, agent_version, prompt_hash, model_id}` recorded |
| Ledger chain verification on app startup | ✓ | 10-line check; catches drift instantly |
| Three-pane React UI | ✓ | Conversation / evidence card / preview drawer; minimal styling |
| SSE heartbeat every 15s + `X-Accel-Buffering: no` | ✓ | Defends against Replit proxy buffering |
| Basic session auth (signed cookie) | ✓ | Even in dev — sets the precedent |
| Canary token in seed data | ✓ | Eval-time check that no agent surfaces it |

### 24.2 Explicit deferrals from M0

- pgvector + embeddings → **M1**
- Multi-tool agent + retrieval merging → **M1**
- `LlmAgentRuntime` abstraction with Bedrock/Vertex stubs → **M2**
- A2A protocol → **M3**
- Temporal workflows → **M4**
- Verifier + tiered models → **M5**
- Compliance Agent emitting findings → **M6**
- Channel router + adapters → **M7**
- HITL action path → **M8**
- Real ingest → **M9**
- DR, OpenSearch, tiered storage lifecycle, full eval harness → **M10**
- External notarization of ledger checkpoints → **M10**

### 24.3 What M0 produces (demo)

A URL where an authenticated analyst can ask "show me finding F-001" and watch a Gemini-backed Chat Agent stream an AG-UI response that:
1. Calls `get_finding(F-001)` via the tool registry.
2. Receives the redacted finding through the `findings_redacted` view.
3. Drafts an answer that cites `F-001`.
4. Passes output PHI scan + canary check.
5. Writes a hash-chained ledger entry with full agent/model/prompt identity.
6. Renders in the three-pane UI with the evidence card linking to the preview drawer.

Plus: startup ledger-chain verification passes; per-request token spend logged.

### 24.4 Out-of-scope explicitly for M0

- Real LLM tool-loop reasoning (one tool, one call).
- Real semantic search (retrieve-by-ID only).
- Real ingest (seed data only).
- Real multi-cloud deploy (Replit dev only).
- Bedrock / Vertex code paths.
- Temporal, Kafka, OpenSearch.

---

## 25. Related Documents

- `DESIGN_OPTION_D.md` — full deep dive on the multi-agent supervisor architecture sized to the source-environment metrics, with the Bedrock AgentCore / Vertex AI mapping, build sequencing, and open questions.
- `../threat_model.md` — STRIDE threat model per §23.4.
- `GLOSSARY.md` — canonical terms for data classes, pipeline objects, agents, protocols, versioning.
- `DIAGRAMS.md` — Mermaid sequence diagrams for ingest funnel, chat turn, HITL remediation; ledger entry shape.
- `PROMPTS.md` — per-agent system prompts, tool allow-lists, guardrail config, prompt-change process.
- `EVALS.md` — concrete gold sets and pass/fail thresholds for the 7 eval suites referenced in §23.5.
- `CAPACITY.md` — Kafka partitions, Postgres roles/sizing, Temporal worker pools, pgvector strategy, LLM cost budgets, reliability targets.
