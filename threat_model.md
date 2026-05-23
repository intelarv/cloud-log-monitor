# Threat Model

## Project Overview

A cloud-agnostic, agentic system that ingests cloud-provider logs (CloudWatch, Cloud Logging, Azure Monitor, on-prem), detects PII and PHI inside them, maintains a tamper-evident audit ledger, drives configurable event-based remediation, and exposes a chat-over-audit dashboard for healthcare compliance analysts.

Stack (per `docs/ARCHITECTURE.md`):
- **Runtime:** Kubernetes (EKS / GKE / AKS / on-prem); Replit pnpm monorepo for dev.
- **API:** Express 5 (TypeScript), OpenAPI + Orval codegen, Zod validation.
- **DB:** PostgreSQL + Drizzle ORM, pgvector for semantic memory, RLS for tenant scoping.
- **Search:** OpenSearch (production), Postgres FTS (dev / early milestones).
- **Object store:** S3-compatible with WORM / Object Lock.
- **Event bus:** Kafka / Redpanda / NATS (no SNS/EventBridge lock-in).
- **Workflow orchestration:** Temporal.
- **Agent runtimes:** Bedrock AgentCore (AWS), Vertex AI Agent Builder (GCP), in-process `DirectLlmRuntime` for dev (Gemini via Replit AI integration).
- **Protocols:** AG-UI (UI ↔ agent), A2A (agent ↔ agent), MCP (agent ↔ tools).
- **Secrets:** HashiCorp Vault (or cloud-native behind a Vault-compatible interface).

Users: healthcare compliance analysts, security on-call engineers, service owners, auditors. The system handles PHI subject to HIPAA and is designed so BAA coverage is achievable end-to-end.

## Assets

- **Protected Health Information (PHI) in raw logs and findings.** Subject to HIPAA. Compromise is reportable and carries regulatory penalties; one of the highest-value assets. Stored only in WORM object storage and the Token Vault; never in searchable hot tiers or LLM prompts.
- **Secrets-in-logs.** API keys, JWTs, cloud credentials, DB passwords that leak into logs. Treated as a separate finding class with higher severity than PHI because compromise grants direct system access. See `docs/ARCHITECTURE.md` §23.3.
- **Audit ledger.** Hash-chained record of every finding, agent action, human action, and break-glass event. Its integrity is the basis of every compliance claim the system makes. Tampering is the worst-case compromise.
- **Token Vault.** KMS-backed reversible tokenization keys. Compromise allows re-identification of every tokenized identifier in the system.
- **Notarization keys.** Hold the external checkpoints that prove ledger integrity. Held in a separate KMS in a separate account.
- **Agent prompts, tool definitions, and policy rules.** Modifying these without review changes agent behavior across the fleet; an attack vector for insider-driven exfiltration.
- **Chat conversation history.** May contain analyst queries that reveal PHI patterns or investigative context; tenant-scoped, TTL'd.
- **Application secrets.** Database connection strings, LLM provider keys (when not via cloud BAA-covered runtimes), Kafka credentials, Vault tokens, OIDC client secrets.
- **Compliance findings inventory.** The set of all detected gaps (e.g. 304 log groups without KMS, 127 without retention). Sensitive operationally because it maps the organization's exposure surface.
- **Session tokens / OIDC IDs.** Standard web-session compromise risk plus break-glass scope.

## Trust Boundaries

- **Browser ↔ Chat API.** Analyst-facing UI to Express API over AG-UI/SSE. Every request must carry an authenticated session and pass ABAC checks. The browser is untrusted.
- **API ↔ Postgres.** App role has RLS-enforced access; a separate writer role owns the append-only ledger. SQL injection at the API layer would bypass RLS for the app role.
- **API ↔ Agent Runtime.** Express service invokes agents via the `LlmAgentRuntime` interface (Bedrock / Vertex / Direct). Agent responses are untrusted output that may contain prompt-injection payloads or PHI echoes.
- **Supervisor ↔ Worker Agents (A2A).** In-cluster A2A calls between Temporal activities and worker agents. Workers may be hosted in different runtimes / clouds; A2A messages cross a cloud-account boundary in multi-cloud deployments.
- **Agents ↔ Tools (MCP).** Tool invocations from agents. The boundary where prompt-injection becomes action; tool inputs derived from agent reasoning are partially attacker-influenced.
- **System ↔ Log Sources.** CloudWatch / Cloud Logging / on-prem log groups. Log content is **attacker-controlled** wherever any logged input is influenced by an external user — this is the largest indirect-injection surface.
- **Detector Pipeline ↔ LLM Plane.** Stage 1+2 emit candidates that flow into agents. The deterministic detectors are the only thing that has "seen" raw log content directly; everything downstream sees redacted-only views.
- **Production ↔ Notarization Account.** Ledger checkpoints flow one-way into a separate cloud account with Object Lock. The notarization account is a higher trust zone protecting the lower one.
- **Internal ↔ External A2A.** Same protocol facing internal supervisor traffic and external systems (e.g. SOC investigation bots). Authorization boundary enforced by API gateway via ABAC claims in `Message` metadata.
- **Application ↔ Channel Adapters.** Notifier sends to Slack / PagerDuty / webhooks. Payloads cross to third-party systems that do **not** have BAA coverage; PHI must never cross this boundary.
- **Analyst ↔ Break-Glass PHI View.** Normal dashboard access is redacted; raw-PHI viewing crosses a step-up auth boundary with mandatory justification, time-boxed grant, and ledgered access.
- **Dev ↔ Production.** Dev environments must use synthetic data only; no real PHI is permitted in dev or staging. Replit dev specifically operates without BAA scope.

## Scan Anchors

- **Production entry points:**
  - `artifacts/api-server/` — Express API (chat SSE, findings, ledger endpoints) when implemented per §19 of `docs/ARCHITECTURE.md`.
  - Future: detector pipeline workers, Temporal worker pools, A2A worker endpoints (locations TBD per Milestone in `docs/ARCHITECTURE.md` §17).
- **Highest-risk code areas (when implemented):**
  - Any module that constructs LLM prompts from log/finding content (prompt-injection surface).
  - Tool handler implementations registered in `ToolRegistry` (tool-arg revalidation must run).
  - Ledger writer (single writer, advisory lock, hash chain).
  - `findings_redacted` view definition and RLS policies.
  - A2A endpoint handlers (external-facing authorization).
  - Channel adapter implementations (PHI must never leave via these).
  - Break-glass / raw-PHI endpoint and the corresponding ledger writes.
- **Surfaces:**
  - **Public:** none. The system has no anonymous endpoints in production.
  - **Authenticated:** chat, findings browse, search, evidence cards. Redacted by default.
  - **Step-up authenticated:** raw-PHI view; break-glass actions; compliance officer reports.
  - **Service-to-service:** A2A agent calls (mTLS + ABAC claims), Kafka producer/consumer, Temporal worker registration.
  - **External A2A:** scoped to specifically allow-listed partner services; off by default in v1.
- **Dev-only areas:** `artifacts/mockup-sandbox/` (Canvas component preview server); any seed-data scripts; Replit dev environment as a whole (no real PHI).
- **Reference docs:**
  - `docs/ARCHITECTURE.md` — full system design including critical-gap mitigations in §23.
  - `docs/DESIGN_OPTION_D.md` — multi-agent supervisor deep-dive and build sequencing.

## Threat Categories

### Spoofing

The system has multiple agent identities, multiple human identities, and multiple cross-cloud service identities. Each must be unforgeable.

- **Analyst impersonation.** Every UI request MUST carry a valid OIDC session; sessions MUST be signed cookies with `HttpOnly`, `Secure`, `SameSite=Lax`; tokens MUST be unpredictable and time-boxed. Step-up auth (raw-PHI view) MUST require a second factor and produce a separate ledger entry per access.
- **Agent identity.** Every ledger entry for an agent action MUST include `{agent_name, agent_version, prompt_hash, model_id, tool_versions}`. A compromised or misconfigured agent must be attributable from the ledger alone.
- **A2A caller identity.** A2A requests between Supervisor and workers MUST authenticate via mTLS (in-cluster) or signed JWT (cross-cloud); the called agent MUST verify the caller's ABAC claims before executing.
- **External A2A.** External callers (e.g. SOC bots) MUST be allow-listed by name and bound to a specific scope; capability cards MUST NOT advertise tools outside that scope.
- **Webhook spoofing.** Channel adapter webhooks (inbound channel acks, status callbacks) MUST verify provider signatures (Slack signing secret, PagerDuty webhook secret, etc.).
- **Notarization checkpoint spoofing.** Ledger checkpoint writes MUST be signed with the notarization key and verified on every chain walk; the notarization account credentials MUST be unreachable from the production account.

### Tampering

The ledger is the system's source of truth; its tamper-evidence is foundational. Findings and policy rules are next.

- **Ledger.** Writes MUST be append-only via a single writer role holding a Postgres advisory lock; `prev_hash → hash` link MUST be transactional. The writer role MUST have no `UPDATE` or `DELETE` grant. Every 1,000 entries (or daily) the head hash MUST be externally notarized to a separate cloud account with Object Lock in `compliance` mode. Hourly verification of the last 24h and weekly full-chain verification MUST run; any mismatch MUST page on-call within 5 minutes. See `docs/ARCHITECTURE.md` §23.2.
- **Findings.** `findings_redacted` view is read-only for application roles; updates to underlying tables MUST be limited to the agent-plane service role and MUST themselves emit ledger entries. Severity, classification, and remediation status changes MUST be append-only event-sourced.
- **Policy rules and prompts.** Agent prompts, tool definitions, channel routing rules, and policy guardrails are version-controlled artifacts; deploys MUST require code review and MUST emit a ledger entry recording the change. Hot-reloaded rules (channel router) MUST validate against a schema and reject malformed input.
- **Logs in WORM tier.** Raw and curated logs in object storage MUST be written with Object Lock; the writer role MUST NOT have permissions to disable Object Lock or change retention.
- **Tokenization vault.** Vault entries MUST be append-only; deletion (e.g. right-to-be-forgotten per `docs/ARCHITECTURE.md` §23.10) MUST be a specific, audited operation distinct from normal writes.
- **Agent tool arguments.** Tool argument tampering by a compromised/injected agent is mitigated by the **tool-arg revalidation pass** (§23.1): every tool re-validates inputs against the policy layer, not just the Zod schema.

### Repudiation

A HIPAA audit must be able to reconstruct who did what and why. Every action by a human or agent must be non-repudiable.

- **Every chat turn** MUST write a ledger entry with `{session_id, user_id, prompt, response, tool_calls, agent_identity, citations}`. PHI MUST NOT appear in the ledger payload — references (finding IDs) only.
- **Every agent action** MUST write a ledger entry with full agent/model/prompt identity (§23.1, §24).
- **Every break-glass access** MUST require a justification field, MUST be time-boxed, MUST auto-revoke, and MUST emit a ledger entry on grant and on each subsequent raw-PHI read during the window.
- **Every detector or prompt change** MUST emit a ledger entry referencing the change-management ID (git commit, PR number).
- **Notarization checkpoints** MUST be independently retrievable and verifiable by an auditor without production-system cooperation.
- **System-admin actions** (RLS policy changes, role grants, Vault unsealing, KMS key rotation) MUST emit ledger entries via a separate "control-plane ledger" stream.

### Information Disclosure

PHI exposure is the single highest-impact failure mode. The design pushes PHI into the smallest possible footprint and gates every read.

- **PHI MUST NOT appear in:**
  - LLM prompts (only redacted snippets and structured metadata are sent to any model).
  - Notification channel payloads (Slack/PagerDuty/email/webhook carry IDs + severity + source only).
  - Application logs (the system's own logs go through the same detector pipeline; meta-PHI leakage is itself a finding).
  - Error responses to the dashboard (stack traces, DB error details MUST NOT be returned).
  - Embeddings stored in pgvector (embeddings computed from redacted text only).
  - Searchable hot tiers (Postgres, OpenSearch). Raw PHI lives only in the WORM tier.
  - Cross-tenant retrieval contexts (per-tenant pgvector namespaces; no shared embeddings).
- **Defense-in-depth pattern:** every read of finding data MUST go through `findings_redacted` view; Postgres RLS binds the connecting role to the user's claims so the application code cannot accidentally bypass it.
- **Step-up raw view.** Raw-PHI viewing MUST require step-up auth, MUST be time-boxed, MUST capture a written justification, and MUST be ledgered per-access (not just per-grant).
- **Output PHI scan.** Every LLM output MUST pass back through the detector pipeline before reaching the UI or any channel; PHI detected in agent output is a finding *about the agent*, not a leak. (§23.1)
- **TLS everywhere.** All inter-service traffic (Express ↔ DB, Express ↔ agent runtime, A2A worker calls, Kafka) MUST use TLS; in-cluster service-to-service MUST use mTLS where the platform supports it.
- **Secrets at rest.** Application secrets MUST live in Vault (or cloud-native equivalent), MUST NOT be in environment variables in production, MUST NOT be in git, MUST NOT be in container images.
- **Notification PHI guard.** Channel adapters MUST run an outbound PHI scan on payload bodies as a final guard; matches MUST hard-fail the send and emit a finding.

### Denial of Service

The system has expensive components (LLM calls, embedding generation, OpenSearch queries) and a high-volume ingest path. Both must be defended.

- **LLM cost circuit breaker.** Per-request token budget MUST be enforced; per-agent and per-tenant daily budgets MUST be enforced; breach MUST downgrade to a cheaper model or deterministic fallback, MUST emit an alert, and MUST be ledgered. (§23.15)
- **Rate limiting.**
  - Chat endpoints MUST rate-limit per session and per user.
  - A2A endpoints MUST rate-limit per caller and per tool.
  - Step-up auth MUST be rate-limited (anti-brute-force on the second factor).
  - Login endpoints MUST be rate-limited and MUST have account-lockout on repeated failures.
- **Ingest backpressure.** Detector pipeline stages MUST be bulkheaded (independent Kafka consumer pools per log source) so a noisy source cannot starve others. (§ existing patterns)
- **Tool timeouts.** Every tool handler MUST have a hard timeout; agent loops MUST have a max-iterations and max-cost cap; LLM calls MUST have timeouts.
- **Unbounded retrieval.** All retrieval tools MUST enforce a `LIMIT`; pagination MUST require an explicit token; result sizes MUST be capped at the API boundary.
- **External service failure modes.** LLM provider, Temporal Cloud, Kafka, OpenSearch outages MUST be handled with circuit breakers; chat MUST degrade to deterministic search-only responses, not error pages.
- **Pgvector / OpenSearch.** Expensive queries MUST have statement timeouts; query cost MUST be visible to the rate limiter.

### Elevation of Privilege

The agent plane is the largest privilege-escalation surface in this system because agents take actions on behalf of users (and on behalf of other agents). Prompt injection from log content is the primary vector.

- **Prompt-injection defense.** (Highest-severity gap per §23.1.) MUST implement:
  - Role-isolated prompting with sealed system instructions; untrusted content fenced inside explicit tags with instructions to treat it as data only.
  - Source-tagged context: every retrieved snippet carries provenance (`source=log:billing-svc, trust=untrusted`).
  - Per-agent tool allow-lists: Notifier cannot call `read_raw_phi`; Chat cannot call `open_pr`; Verifier cannot call `send_notification`.
  - Tool-arg revalidation against the policy layer before execution.
  - Platform guardrails (Bedrock Guardrails / Vertex Model Armor / Llama Guard) on input AND output.
  - Egress allow-list: agents make outbound network calls only via explicit tool handlers; raw HTTP from agent runtimes blocked at network policy.
  - Honeypot canaries in seed data; canary in any tool argument MUST trigger alert + ledgered incident.
  - Output PHI scan on every LLM response.
- **Authorization on every endpoint.** Authentication ≠ authorization. Every endpoint that returns finding/ledger/conversation data MUST enforce ABAC via Postgres RLS bound to the caller's identity; service-layer code MUST NOT bypass with a service-role connection except for clearly-scoped maintenance jobs.
- **No raw SQL from LLMs.** The agent plane MUST NOT have a tool that executes LLM-generated SQL. The `structured_query` tool accepts only a Zod-validated typed filter object. (Option C was explicitly rejected for v1.)
- **HITL gates on write actions.** Remediation tools (open PR, redact-at-source, channel send) MUST return *proposals*, not executions. Human confirmation MUST be required and ledgered. Confirmation MUST require the same auth scope as the proposed action.
- **A2A authorization.** A2A worker endpoints MUST verify the caller's ABAC scope; a Triage agent calling a Verifier MUST NOT be able to invoke a Remediation tool.
- **Break-glass scope minimization.** A break-glass grant MUST scope to a specific finding ID and time window; MUST NOT grant blanket raw-PHI access.
- **Insider threat (rogue analyst).** Per-finding break-glass grants, mandatory justification, ledgered per-access, and weekly review of break-glass activity MUST be standard operating procedure. Grants on **critical**-severity findings MUST additionally require a second-person approval — a different user in the same tenant, completing their own fresh step-up, against the specific grant id. Self-approval MUST be refused at the moment of the attempt and MUST itself be ledgered (`break_glass.approval_denied_self_approval`) so the attempt is auditable even though no PHI was disclosed. The `requires_second_approval` flag MUST be captured at grant-creation time from the finding's then-current severity, not re-evaluated at approval time, so an attacker who can flip severity cannot bypass the rule. Double-approval MUST be guarded by a compare-and-swap on `approver_user_id IS NULL`. *(Implemented M1.7; `artifacts/api-server/src/routes/admin.ts`.)*
- **Supply-chain.** Container images MUST be built from pinned base images and scanned for CVEs; dependencies MUST be lock-file pinned; third-party MCP servers MUST NOT be enabled without security review.
- **Cross-tenant escalation (when multi-tenant).** Per-tenant KMS keys, per-tenant pgvector namespaces, per-tenant LLM context isolation, per-tenant RLS — no shared cache, no shared prompt context, no shared embeddings.

### Out-of-scope categories

- **Physical security and data-center controls** are inherited from the underlying cloud (AWS / GCP / Azure) under their BAA; not modeled here.
- **DDoS protection at the network edge** is inherited from the cloud's edge protection (Shield / Cloud Armor) and the proxy layer; the application-layer rate limits above complement it but are not a substitute.
- **End-user device security** (analyst laptops) is outside the application's control; mitigated by short session lifetimes and step-up auth on sensitive actions.
