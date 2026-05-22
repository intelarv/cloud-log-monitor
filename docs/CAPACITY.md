# Capacity Plan

Sizing for the source-environment metrics from `DESIGN_OPTION_D.md` §4 (199 M events/day, 304 log groups, 105 GiB/day). All numbers are starting points for production; M0–M9 deploy at fractional scale.

## Headline numbers

| Quantity | Per day | Per hour (peak 2×) | Per second (peak) |
|---|---|---|---|
| Raw log events ingested | 199 M | 16.6 M | ~4,600 |
| Bytes ingested (raw) | 105 GiB | 8.75 GiB | ~2.5 MiB/s |
| Stage 1 candidates (≈1% hit rate) | 1.99 M | 166 K | ~46 |
| Stage 2 confirmed candidates (≈10% of S1) | 199 K | 16.6 K | ~4.6 |
| Net new findings after Triage dedup (≈10× compression) | 20 K | ~1,700 | ~0.5 |
| Verifier invocations (≈30% of confirmed) | 60 K | 5,000 | ~1.4 |
| LLM tokens consumed | ~ 30 M in / ~ 6 M out (rough) | — | — |
| Ledger entries written | ~ 50 K (findings + agent actions + admin) | — | ~0.6 |

These set the floor; bursts will exceed peak factor in real incidents.

---

## Kafka / event bus

**Topics & partition plan:**

| Topic | Producers | Consumers | Partitions | Retention | Reason |
|---|---|---|---|---|---|
| `logs.raw` | Ingest workers (per source) | Stage 1 detectors | 64 | 24 h hot, then WORM | ~4.6 K msg/s; 64 partitions gives ~70 msg/s per partition headroom |
| `logs.candidates` | Stage 1 | Stage 2 | 32 | 24 h | ~46 msg/s; 32 partitions for parallel NER |
| `logs.confirmed` | Stage 2 | Triage activities | 16 | 7 d | ~5 msg/s; partition by source for ordering |
| `findings.events` | Findings writer | Notifier, indexer, dashboard fanout | 16 | 7 d | Event-sourced state changes |
| `proposals.events` | Remediation, Notifier | Dashboard, HITL queue | 8 | 30 d | Low volume, longer retention for audit |
| `ledger.checkpoints` | Ledger writer | Notarization worker | 4 | forever (compact) | One per checkpoint window |

**Partitioning key:**
- `logs.raw` / `logs.candidates` — `source_arn + log_stream` (preserves per-stream ordering).
- `logs.confirmed` — `fingerprint` (dedup neighbors land on same Triage worker).
- `findings.events` — `finding_id` (state transitions stay ordered).

**Bulkheading:**
- Per-source consumer groups for `logs.raw` so a noisy source can't starve detectors for other sources.
- DLQ topic per consumer group; messages exceeding 3 retries land there; ops dashboard tracks DLQ depth as an SLI.

**Cluster sizing (start):** 3 brokers, replication factor 3, `min.insync.replicas=2`. Disk: ~5 TiB per broker (24 h raw retention with headroom).

---

## Postgres

**Roles:**

| Role | Grants | Purpose |
|---|---|---|
| `app_reader` | `SELECT` on `findings_redacted`, `clusters`, `ledger_entries` (read-only) | Dashboard / Chat Agent |
| `agent_writer` | `INSERT` on findings tables; `SELECT` on `findings_redacted` | Triage/Verifier/Compliance agents |
| `ledger_writer` | `INSERT` only on `ledger_entries`; holds advisory lock | The single ledger writer |
| `migrator` | DDL only, used by Drizzle migrations | Schema changes (CI) |
| `vault_op` | Reversible-token operations only | Token Vault facade |

**Table sizing (steady state, 1-year horizon):**

| Table | Rows/day | Bytes/row | Year-1 size | Notes |
|---|---|---|---|---|
| `findings` | ~ 20 K | ~ 2 KB | ~ 14 GB | Partition by `month`; archive cold partitions to object store after 90 d. |
| `ledger_entries` | ~ 50 K | ~ 1 KB | ~ 18 GB | Append-only, no partitioning yet; revisit at 100 GB. |
| `clusters` | ~ 2 K | ~ 1 KB | ~ 0.7 GB | Small; full table cache. |
| `finding_embeddings` (M1+) | ~ 20 K | ~ 1.3 KB at 256 dim (default) / ~ 4 KB at 768 dim | ~ 9 GB at 256 dim / ~ 28 GB at 768 dim | This repo uses `EMBEDDING_DIM=256` (Matryoshka-truncated) with pgvector `ivfflat`. Bump to `768` + HNSW for full-fidelity prod; index ~ 1.5–2× table size. |
| `chat_messages` | ~ 5 K | ~ 1 KB | ~ 1.8 GB | TTL 90 d (configurable per tenant). |

**Index plan:**
- `findings(source_arn, created_at desc)` — dashboard browsing.
- `findings(fingerprint, status)` partial WHERE status='open' — dedup hot path.
- `findings_redacted` is a security-barrier view, not an index target.
- `ledger_entries(seq)` — primary key, monotonic.
- `findings_embeddings` HNSW `(embedding vector_cosine_ops)` `m=16, ef_construction=64`.

**Connection pool:**
- PgBouncer transaction pooling; 200 client conns front-end, 25 server conns to PG.
- Ledger writer runs from a separate pool (max 1 active conn) holding the advisory lock.

**Backup:**
- WAL archive every 60 s to S3-compatible storage with Object Lock.
- Logical dumps daily (encrypted) for PITR independent of WAL.
- Ledger restore procedure: replay WAL to last externally-notarized checkpoint, then verify chain.

---

## pgvector

**Index choice:** HNSW from day one. IVF only if we hit recall issues > 10 M vectors.
- `m=16` — connectivity; balances build time and recall.
- `ef_construction=64` — quality/build trade-off.
- `ef_search=40` (query-time) — recall ~ 0.95 at this size.

**Embedding cadence:**
- Embed per **cluster template** (after Triage dedup), not per finding event. Cuts embed calls ~100×.
- Backfill on classifier or model change runs as a Temporal workflow with rate budget.

**Graduation trigger to dedicated vector DB (Qdrant / Vespa):**
- Query p95 > 200 ms OR index size > 50 GB OR write throughput > 500/s sustained.
- Migration is interface-only: agents call `RetrievalService.semantic_search`, not pgvector directly.

---

## Temporal

**Worker pools:**

| Pool | Workflow types | Workers (start) | Why |
|---|---|---|---|
| `supervisor` | Per-finding supervisor workflow | 3 × 50 slots = 150 concurrent | ~20 K new findings/day; each workflow ~10 s P50 → ~50 concurrent steady |
| `triage-activities` | Triage Agent invocations | 3 × 30 = 90 | Fast model; sub-second median |
| `verifier-activities` | Verifier invocations | 3 × 10 = 30 | Strong model; multi-second |
| `compliance-sweep` | Periodic config sweeps | 1 × 5 = 5 | Cron-driven, low concurrency |
| `notifier-activities` | Proposal drafting | 2 × 10 = 20 | Burst on incident |
| `remediation-activities` | PR drafting | 2 × 5 = 10 | Strong model, low rate |
| `replay` | Detector replay workflows | 1 × 5 = 5 | Manual / scheduled only |

**History service:**
- Managed Temporal Cloud preferred (cross-region durability).
- Self-hosted fallback: Cassandra-backed, 3 nodes, ~ 500 GB starting.

**Workflow code rules:**
- All activities idempotent (keyed on `{finding_id, agent_version, attempt}`).
- Long activities (PR drafting) use heartbeats; timeout 5 min.
- LLM-call activities have explicit `RetryPolicy(initialInterval=2s, maxAttempts=3, backoffCoefficient=2)`.

---

## Object storage (WORM)

| Bucket | Class | Lock mode | Retention | Bytes/day | Year-1 |
|---|---|---|---|---|---|
| `raw-logs` | Standard → IA after 7 d → Glacier after 90 d | compliance | 7 y | 105 GiB | ~ 38 TiB → much less after tiering |
| `findings-archive` | Standard | compliance | 7 y | ~ 0.5 GiB | ~ 180 GiB |
| `ledger-checkpoints` | Standard | compliance | forever | ~ 1 MiB | ~ 0.4 GiB |
| `notarization` (separate account) | Standard | compliance | forever | ~ 1 MiB | ~ 0.4 GiB |

Lifecycle policies enforced by code, audited weekly.

---

## OpenSearch (M10+)

**Hot tier:** 14 days of findings with full evidence (redacted).
- 3 data nodes, 32 GiB RAM, 1 TiB SSD each.
- Shard per index = 6, replicas = 1.
- Index per month: `findings-YYYYMM`; freeze older than 14 d to warm tier.

**Warm tier:** 90 d on slower disks; queryable but not heavily.

**Cold tier:** Object storage Snapshot Repository; restore on demand for investigation.

Until M10, Postgres FTS on `findings.evidence_text` covers search at projected volume (≤ 20 GB FTS index in year 1 — well within PG comfort zone).

---

## LLM cost budget

**Per-request budgets (hard caps, enforced in `LlmAgentRuntime`):**

| Agent | Input tokens | Output tokens | Model tier |
|---|---|---|---|
| Triage | ≤ 2 K | ≤ 500 | cheap |
| Verifier | ≤ 8 K | ≤ 1 K | strong |
| Chat (per turn) | ≤ 16 K | ≤ 2 K | strong |
| Notifier | ≤ 4 K | ≤ 500 | cheap |
| Remediation | ≤ 32 K (incl. code) | ≤ 4 K | strong |
| Compliance | ≤ 2 K | ≤ 500 | cheap |

**Per-agent daily budgets (initial; tune from observed):**

| Agent | Calls/day | Token spend/day (in+out) |
|---|---|---|
| Triage | ~ 200 K | ~ 500 M |
| Verifier | ~ 60 K | ~ 540 M |
| Chat | ~ 5 K | ~ 90 M |
| Notifier | ~ 5 K | ~ 22 M |
| Remediation | ~ 500 | ~ 18 M |
| Compliance | ~ 5 K | ~ 12 M |

**Tenant budgets:** sum of per-agent × tenant share; daily cap with circuit breaker downgrade path:
- Breach soft cap (80 %) → switch Chat to cheaper tier, alert.
- Breach hard cap (100 %) → freeze non-critical agent calls, page on-call, ledgered.

**Observability hooks:** every LLM call emits OTel span `{ agent, tenant, model, in_tokens, out_tokens, ms, cost_usd }`. Cost dashboard aggregates.

---

## Reliability targets (cross-reference SLOs in §23.15)

| Component | Latency target | Throughput target | Failure mode |
|---|---|---|---|
| Ingest → WORM | p95 ≤ 1 s | 5 K msg/s | Backpressure to source; lossless |
| Stage 1 detect | p95 ≤ 50 ms | 5 K msg/s | Bulkhead per source |
| Stage 2 detect | p95 ≤ 200 ms | 50 msg/s | Queue; degrade by skipping low-priority sources |
| Triage Agent | p95 ≤ 1 s | 50 msg/s | Cheaper model fallback |
| Verifier Agent | p95 ≤ 5 s | 5 msg/s | Queue; alert if backlog > 1 K |
| Chat (first token) | p95 ≤ 2 s | 20 RPS | Search-only fallback if LLM down |
| Ledger write | p95 ≤ 50 ms | 100 entries/s | Single writer; failover replica promoted in 1 min |
| Notification send | p99 ≤ 30 s | 50/s | DLQ + retry |

---

## What changes M0 → production

| Dimension | M0 | M9 (full ingest) | Production |
|---|---|---|---|
| Sources | 0 (seed) | 1 | All log groups |
| Kafka | none | 1-broker dev | 3-broker cluster |
| Postgres | dev PG | dev PG | HA cluster + read replica |
| Temporal | none | in-process | Managed Cloud |
| OpenSearch | none | none | M10 cluster |
| Agents | Chat only | + Triage, Verifier | + Notifier, Remediation, Compliance |
| LLM provider | Gemini (Replit) | Gemini (Replit) | Bedrock + Vertex per region |
| Notarization | none | none | Separate account, hourly |

Each milestone replaces one stub from M0; capacity scales additively, not by rewriting.
