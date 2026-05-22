# Glossary

Canonical terms used across `ARCHITECTURE.md`, `DESIGN_OPTION_D.md`, `threat_model.md`, and all code. When in doubt, this file wins.

## Data classes

| Term | Definition | Examples | Notes |
|---|---|---|---|
| **PHI** (Protected Health Information) | Health information that identifies an individual, as defined by HIPAA §164.514 (18 identifiers). | MRN, patient name + DOB, diagnosis tied to identifier, treatment notes | Subject to HIPAA. The system's primary protected asset. |
| **ePHI** | PHI in electronic form. | Any PHI stored or transmitted by this system. | All PHI we handle is ePHI; we use "PHI" for brevity. |
| **IIHI** (Individually Identifiable Health Information) | The broader category from which PHI is derived; only becomes PHI when held by a covered entity or BA. | Same examples as PHI. | Rarely used in our docs; prefer "PHI". |
| **PII** | Personally Identifiable Information that is **not** health-related. | Customer email, phone, billing address (non-clinical) | Lower default severity than PHI; still protected. |
| **PII-S** (Sensitive PII) | PII whose compromise causes elevated harm. | SSN, government ID, financial account | Treated at PHI-equivalent severity. |
| **Secrets** | Machine credentials that grant system access if leaked. | API keys, JWTs, AWS access keys, DB passwords, OAuth tokens | **Highest default severity** — direct exploitation path. Separate class from PHI per ARCHITECTURE.md §23.3. |
| **Internal identifiers** | Non-sensitive internal IDs. | Internal user IDs, trace IDs, request IDs | Lowest severity; optional masking. |
| **Tokenized identifier** | A surrogate value produced by the Token Vault that replaces a sensitive identifier; reversible only with the vault key. | `TKN_a8f2…` standing in for an MRN | Stored in findings; raw value lives only in WORM. |
| **Redacted** | Sensitive substring removed or replaced in-place (e.g. `***`); **not reversible**. | `MRN: ***`, `email: a***@e***.com` | Default for anything shown in dashboards. |
| **Masked** | Partial obfuscation that preserves shape (e.g. last 4 digits). | `SSN: ***-**-1234` | Used when shape matters for analyst recognition. |
| **Raw evidence** | The unredacted source payload for a finding, stored in `findings.raw_evidence` (jsonb, nullable). Reachable only via the break-glass raw endpoint; excluded from `findingSafeColumns` so it cannot enter prompts, SSE, or non-admin API responses. |
| **`findingSafeColumns` / `FindingSafe`** | The Drizzle column whitelist and the `Omit<Finding,'rawEvidence'>` type that together form the compile-time gate keeping `raw_evidence` out of every non-break-glass read of `findings`. |

## Pipeline objects

| Term | Definition | Where it lives |
|---|---|---|
| **Log event** | A single raw log line from a source (CloudWatch / Cloud Logging / Azure Monitor / on-prem). | Source-system; copied to WORM raw tier on ingest. |
| **Candidate** | A potentially-sensitive log event flagged by Stage 1 (regex) or Stage 2 (NER) detectors. | Kafka `candidates` topic; ephemeral. |
| **Finding** | A confirmed, deduped, classified sensitive event with severity, class, source, evidence pointer, and remediation status. | Postgres `findings` table; primary unit of work for agents and analysts. |
| **Evidence** | The minimal supporting context for a finding (redacted snippet + source ref + detector identity). | Postgres `findings.evidence_json`; references raw in WORM. |
| **Cluster** | A group of findings sharing a fingerprint (same template, same source, near in time). | Postgres `clusters` table; reduces analyst alert load. |
| **Incident** | An analyst-promoted cluster + investigation timeline + assigned owner. | Postgres `incidents` table; created from the dashboard. |
| **Remediation proposal** | An agent-generated draft action (open PR, redact-at-source, send notification) that requires HITL approval before execution. | Postgres `remediation_proposals`; surfaced as AG-UI HITL request. |
| **Compliance gap** | A configuration-class finding about the environment (no KMS on log group, no retention policy). | Same `findings` table with `class='config'`. |

## Agent & orchestration

| Term | Definition |
|---|---|
| **Agent** | An LLM-backed component with a sealed prompt, a scoped `ToolRegistry` view, and an identity (`agent_name + agent_version + prompt_hash + model_id`). |
| **Supervisor** | The Temporal workflow that orchestrates worker agents; not itself an LLM. |
| **Worker agent** | An agent invoked by the Supervisor: Triage, Verifier, Remediation, Notifier, Compliance. |
| **Chat Agent** | The analyst-facing agent; serves AG-UI events over SSE; reads-only by default. |
| **Tool** | A typed function callable by an agent; registered in `ToolRegistry`; exposed via MCP. |
| **Tool allow-list** | The subset of registered tools a specific agent is permitted to invoke. |
| **Tool-arg revalidation** | The mandatory pass that re-checks tool arguments against the policy layer (not just the Zod schema) before execution. |
| **HITL** (Human-in-the-Loop) | Required human confirmation before a write/action tool executes. |
| **Break-glass** | A time-boxed, justified, ledgered grant to view raw PHI for a specific finding. In this repo: `POST /api/admin/break-glass/grants`, ≤15-min TTL, per-finding, ≥10-char justification; `break_glass.granted` + `break_glass.raw_phi_accessed` ledger events. |
| **Step-up auth** | A second authentication act, signed independently from the session cookie, required before issuing a break-glass grant. In this repo: `POST /api/auth/step-up` issues the `phia_stepup` cookie (5-min TTL); HMAC input is tagged with a per-purpose label so it cannot be replayed as a session cookie or vice versa. |
| **Hybrid retrieval** | BM25 (lexical) ∪ vector (semantic) candidate sets fused with RRF. The agent context preload for chat. |
| **RRF** (Reciprocal Rank Fusion) | Score-normalization-free fusion of two ranked lists: `score(d) = Σ 1/(k + rank_i(d))`. This repo uses `k=60`. |
| **Embedder** | The component that turns text into a vector for pgvector storage. Pluggable per cloud (Bedrock / Vertex / Azure OpenAI / TEI) with a dev `featurehash` fallback. |
| **PhiGuardEmbedder** | Wrapper that runs `scanForPhi` on every input before delegating to the underlying embedder; defense-in-depth so no PHI-derived vector can be stored even if upstream redaction regresses. |

## Protocols & infrastructure

| Term | Definition |
|---|---|
| **AG-UI** | Standard event protocol for UI ↔ agent communication; carried over SSE. |
| **A2A** | Standard protocol for agent ↔ agent communication; in-cluster via mTLS, cross-cloud via signed JWT. |
| **MCP** (Model Context Protocol) | Standard for tool exposure to LLMs; canonical wire format for `ToolRegistry` per §23.12. |
| **WORM** (Write-Once-Read-Many) | Object storage tier with Object Lock; raw logs and ledger checkpoints stored here. |
| **Notarization** | The act of writing a ledger head hash to the WORM tier in a separate cloud account; basis of external tamper-evidence. |
| **Ledger** | The hash-chained, append-only Postgres table recording every finding, agent action, human action, and break-glass event. |
| **Control-plane ledger** | A separate ledger stream for system-admin actions (RLS changes, role grants, Vault unsealing, KMS rotation). |
| **RLS** | Postgres Row-Level Security policies binding query scope to caller claims. |
| **ABAC** | Attribute-Based Access Control; the authorization model carried in session claims and A2A `Message` metadata. |

## Versioning

| Term | Definition |
|---|---|
| **Detector version** | Semver of the detector bundle (regex pack + NER model + rules); recorded on every candidate and finding. |
| **Prompt hash** | SHA-256 of the canonical prompt template + tool definitions an agent invocation used; recorded in every ledger entry. |
| **Agent version** | Semver of an agent's code + prompt + tool-allow-list bundle; bumped on any of those. |
| **Model id** | Provider + model name + version (e.g. `vertex/gemini-2.5-pro@001`); recorded in every ledger entry. |
