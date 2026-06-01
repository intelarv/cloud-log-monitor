# Deployment (M9)

Two deployment paths today, both produced by **M9.1** (Helm + Docker) and **M9.4** (Replit). Terraform / per-cloud IaC roots are still scoped under M9.2 + M9.3 (planned, not built).

## Layout

```
deploy/
├── docker/
│   ├── api-server.Dockerfile        # multi-stage; non-root; healthcheck
│   ├── dashboard.Dockerfile         # nginx-served Vite SPA
│   └── dashboard-nginx.conf         # SPA fallback + tight CSP + cache headers
└── helm/phi-audit/
    ├── Chart.yaml                   # appVersion: M8+cloud-llm
    ├── values.yaml                  # cloud-agnostic defaults
    ├── values-aws.yaml              # EKS + RDS + Bedrock + ALB
    ├── values-gcp.yaml              # GKE + Cloud SQL (+ proxy sidecar) + Vertex + GCE Ingress
    ├── values-azure.yaml            # AKS + Azure DB (password) + Azure OpenAI + App Gateway
    └── templates/
        ├── _helpers.tpl             # fail-fast validation
        ├── serviceaccount.yaml      # IRSA / Workload Identity / Azure WI annotations
        ├── api-deployment.yaml      # api-server (+ optional DB sidecar slot)
        ├── dashboard-deployment.yaml
        ├── services.yaml
        ├── ingress.yaml             # /api → api, / → dashboard (order matters)
        ├── hpa.yaml
        ├── networkpolicy.yaml       # egress allow-list (threat_model §EoP)
        └── NOTES.txt                # post-install checklist
```

## Workflow

1. **Build + push images.** Build context is the repo root for both Dockerfiles.

   ```bash
   docker build -f deploy/docker/api-server.Dockerfile -t <registry>/phi-audit-api:<sha> .
   docker build -f deploy/docker/dashboard.Dockerfile  -t <registry>/phi-audit-dashboard:<sha> .
   docker push <registry>/phi-audit-api:<sha>
   docker push <registry>/phi-audit-dashboard:<sha>
   ```

   Always tag with an **immutable SHA**, never `latest`. `_helpers.tpl` will `fail` if `image.api.tag` is empty.

2. **Create the operator-managed Secrets.** The chart enforces a **structural split** between `SESSION_SECRET` and `NOTARIZATION_SECRET` — they must live in two different K8s Secrets so each can be backed by a different KMS / cloud account / Key Vault per threat_model §23.2. Co-locating them defeats the external-notarization half of the tamper-evidence guarantee.

   Production (recommended): mount each from a separate cloud secret store via External Secrets Operator / Secrets Store CSI Driver, with the notarization key's backing KMS in a **separate cloud account / project / tenant** from the session key's.

   Dev shortcut (NOT for production — `NOTES.txt` emits a WARNING when this is detected):

   ```bash
   kubectl -n phi-audit create secret generic phi-audit-session \
     --from-literal=session-secret=$(openssl rand -hex 32)
   kubectl -n phi-audit create secret generic phi-audit-notarization \
     --from-literal=notarization-secret=$(openssl rand -hex 32)
   ```

   Pass both names: `--set secrets.sessionSecret.existingSecret=phi-audit-session --set secrets.notarizationSecret.existingSecret=phi-audit-notarization`.

   `phi-audit-db` likewise — managed by AWS RDS rotation + External Secrets Operator on AWS, by `iam.gke.io` on GCP (when the cloud-sql-proxy sidecar is on, the Secret just needs `database-url=postgres://...@127.0.0.1:5432/phiaudit`), and by Secrets Store CSI on Azure.

3. **Install.**

   ```bash
   helm install phi-audit deploy/helm/phi-audit \
     -n phi-audit --create-namespace \
     -f deploy/helm/phi-audit/values-aws.yaml \
     --set image.api.repository=<registry>/phi-audit-api \
     --set image.api.tag=<sha> \
     --set image.dashboard.repository=<registry>/phi-audit-dashboard \
     --set image.dashboard.tag=<sha> \
     --set secrets.existingSecret=phi-audit-app \
     --set ingress.host=phi-audit.example.com
   ```

   Substitute `values-gcp.yaml` / `values-azure.yaml` for the other clouds. Each overlay sets the right `llm.provider`, `embedder.provider`, sidecar shape, Ingress class, and NetworkPolicy egress baseline.

4. **Verify.** `NOTES.txt` (printed by `helm install`) lists the post-install checklist. The critical lines are:

   ```bash
   kubectl -n phi-audit logs deploy/phi-audit-api | grep "Ledger chain verification"
   # expected: ok: true
   kubectl -n phi-audit logs deploy/phi-audit-api | grep "LLM runtime initialized"
   # expected: provider=bedrock|vertex|azure-openai (not gemini-replit)
   ```

## Nightly eval gate (AI-backed quality suites)

The per-change CI gate (`pnpm run eval:gate`) runs the six deterministic,
credential-free eval suites. The two credentialed suites (`citation-live`,
`agent-agreement`) exercise the live LLM + DB and run on a schedule via
`pnpm run eval:gate:llm`. Two ways to schedule it:

**Kubernetes (Helm CronJob).** The chart ships a CronJob, off by default. It
needs a dedicated image (the slim api runtime image has no pnpm/vitest):

```bash
docker build -f deploy/docker/api-server.Dockerfile --target eval \
  -t <registry>/phi-audit-eval:<sha> .
docker push <registry>/phi-audit-eval:<sha>
```

Then enable it (it reuses the api ServiceAccount + the same
`DATABASE_URL` / `SESSION_SECRET` / `NOTARIZATION_SECRET` / LLM + embedder
config the api Deployment uses). When `database.sidecar.enabled=true` (e.g.
the GCP cloud-sql-proxy overlay), the CronJob carries the same DB sidecar —
declared as a **native sidecar** (`initContainer` with `restartPolicy: Always`)
so the Job still terminates once the eval container exits:

```bash
helm upgrade phi-audit deploy/helm/phi-audit -n phi-audit --reuse-values \
  --set evalGate.nightly.enabled=true \
  --set evalGate.nightly.image.repository=<registry>/phi-audit-eval \
  --set evalGate.nightly.image.tag=<sha> \
  --set evalGate.nightly.schedule="0 3 * * *" \
  --set evalGate.nightly.llmMinScore=0.5     # optional hard-fail floor
```

**Replit (Scheduled Deployment).** In the Replit Deployments panel, create a
Scheduled Deployment that runs `pnpm run eval:gate:llm` nightly with
`DATABASE_URL` + an LLM runtime (`LLM_PROVIDER` + creds) configured. The
per-change gate stays secret-free; only this scheduled job needs them.

**Hard-fail policy** (see `artifacts/api-server/evals/README.md`): deterministic
regressions and live-suite execution failures always fail the job; live-suite
*score* regressions are warnings by default. Set `EVAL_LLM_MIN_SCORE`
(`evalGate.nightly.llmMinScore` in the chart) to an absolute floor (0..1) to
page on catastrophic live-agent regressions without flaky delta-based noise.

**Alerting.** After each run the job posts a concise summary (per-suite scores +
which check tripped) to any configured channel, reusing the same `CHANNEL_*` env
and severity gating as finding alerts. Supported channels:

- **Slack** — `CHANNEL_SLACK_WEBHOOK_URL` [+ `CHANNEL_SLACK_MIN_SEVERITY`].
- **Generic HMAC webhook** — `CHANNEL_WEBHOOK_URL` + `CHANNEL_WEBHOOK_SECRET` +
  `CHANNEL_WEBHOOK_ALLOWED_HOSTS` [+ `CHANNEL_WEBHOOK_MIN_SEVERITY`].
- **PagerDuty (Events API v2)** — `CHANNEL_PAGERDUTY_ROUTING_KEY` (the integration
  routing key; treat as a secret) [+ `CHANNEL_PAGERDUTY_MIN_SEVERITY`,
  `CHANNEL_PAGERDUTY_EVENTS_URL` (EU/custom endpoint),
  `CHANNEL_PAGERDUTY_DEDUP_KEY`]. This pages the on-call rotation directly per
  threat_model §Tampering ("page on-call within 5 minutes"). Severity maps onto
  PagerDuty's enum (`warning→warning`, `high→error`, `critical→critical`); the
  dedup key (defaulting to a single stable key, `eval-gate-nightly`) folds
  re-runs into one incident **and** lets a passing run on a later night resolve
  the incident a prior failing night opened — cross-night recovery works without
  any extra config. (A per-day key would have used a different dedup_key each
  night, so the recovery resolve could never clear yesterday's page.) Set
  `CHANNEL_PAGERDUTY_DEDUP_KEY` explicitly only if you want a distinct incident
  per attempt (e.g. one per CI run id), which forgoes cross-night auto-resolve.

`EVAL_NOTIFY_ON` (`fail` | `warn` | `always`, default `fail`) selects which
outcomes post:

- `fail` (default) — only a hard-fail posts, at `high` severity (prior behavior).
- `warn` — also posts passing-with-warnings runs, at `warning` severity.
- `always` — also posts an all-green confirmation, at `warning` severity, so
  silence is never ambiguous to on-call.

Because success/warning runs map to `warning` severity, the per-channel
`CHANNEL_*_MIN_SEVERITY` gating still applies — a channel pinned to `high` only
ever receives the hard-fail. Inert (logs only) when no channel is configured or
the outcome is below the trigger; the payload carries scores + suite names only,
no PHI. Provide the relevant `CHANNEL_*` vars to the CronJob (for PagerDuty,
`channels.pagerduty.enabled=true` in the chart, with the routing key under
`channel-pagerduty-routing-key` in the channelSecret) / Scheduled Deployment env,
and set the trigger via `EVAL_NOTIFY_ON` (chart value
`evalGate.nightly.notifyOn`, e.g. `--set evalGate.nightly.notifyOn=always`). The
notifier never changes the job's exit code (the gate result is the source of
truth).

`EVAL_NOTIFY_RECOVERY` (default on; opt out with `off` | `false` | `0` | `no`)
controls the **recovery note**. A hard-fail pages PagerDuty (a `trigger`) and the
next passing run auto-resolves that incident — but on Slack/webhook the page just
vanishes silently. So when a passing run follows a prior *failing* run, the
notifier posts one concise `[RECOVERED]` line naming the suites that came back
green (read from the prior run's failing-suite list in the persisted
`score-history.json`). It fires **only** when the normal summary would not
otherwise post (the default `EVAL_NOTIFY_ON=fail`), so a recovery night never
yields both a recovery note and a full confirmation; routine consecutive green
nights never trigger it. The note honors the same `warning`-class
`CHANNEL_*_MIN_SEVERITY` gating and is **never sent to PagerDuty** (which gets the
auto-resolve). When history records the failing streak's start, the note also
appends how long the gate had been failing (e.g. `(was failing for ~3h)`).
Naming the recovered suites (and the duration) requires the run history to
survive across invocations, so mount a durable `evals/score-history.json` (same
volume the trend indicator uses — see `artifacts/api-server/evals/README.md`);
without it the note degrades to naming the current green suites. A gate that
flaps fail→pass repeatedly is muted: at least
`EVAL_NOTIFY_RECOVERY_FLAP_THRESHOLD` (default `3`) recoveries within
`EVAL_NOTIFY_RECOVERY_FLAP_WINDOW_MINUTES` (default `360`) suppresses further
recovery notes (PagerDuty still auto-resolves); set the threshold to `0` to
disable muting. Defaults never trip on the 24h nightly cadence.

**Dead-man's switch (heartbeat).** `EVAL_NOTIFY_ON=always` tells on-call the
suites are healthy with a daily all-green message — but if the nightly CronJob
*silently stops running* (image pull failure, schedule disabled, cluster issue)
it produces **no message at all**, and absence of a message is exactly what
on-call cannot see. The chart ships a second CronJob, off by default, that
closes that gap:

- The nightly job stamps a heartbeat row (`eval_gate_heartbeats`) on **every**
  completed run — pass *or* fail — via `eval-gate-llm.sh` →
  `artifacts/api-server/evals/heartbeat.mjs --record`. (It records run
  *liveness*, not quality; a failed run already pages via the notifier above.)
  The table is created idempotently by the script in the same DB the nightly job
  already connects to — no app schema change.
- A lighter, more-frequent CronJob runs `heartbeat.mjs --check`. If the last
  stamp is older than `EVAL_HEARTBEAT_MAX_AGE_MINUTES` (or there is no stamp at
  all) it posts a `high`-severity *“nightly eval confirmation has gone quiet”*
  alert through the **same** `CHANNEL_*` config + severity gating as the eval
  run alerts, so it lands where on-call already watches. The payload is liveness
  metadata only (gate name, last-success timestamp, age) — no scores, no PHI.
- When the nightly mechanism recovers, a later `--check` finds the stamp fresh
  again and sends a PagerDuty **`resolve`** to clear the open “went quiet”
  incident automatically — the heartbeat parallel of the run notifier's
  cross-night auto-resolve. The staleness trigger and the recovery resolve share
  one **stable** dedup key (default `eval-gate-heartbeat`, distinct from the run
  notifier's `eval-gate-nightly` so a quiet job and a failing suite stay separate
  incidents). The key carries no per-day component on purpose: a date-based key
  would change if an outage straddled UTC midnight, orphaning the page so the
  resolve could never clear it. A still-stale check keeps paging into the one
  open incident; a recovered check folds it closed with no hand-closing. Slack
  and generic webhooks have no resolve concept, so a healthy check posts nothing
  to them. Set `CHANNEL_PAGERDUTY_DEDUP_KEY` to pin a custom key (it applies to
  both the trigger and the resolve so they still match).

Enable it alongside the nightly gate (it reuses the same `eval` image, the same
DB sidecar, and needs no LLM/embedder config):

```bash
helm upgrade phi-audit deploy/helm/phi-audit -n phi-audit --reuse-values \
  --set evalGate.heartbeat.enabled=true \
  --set evalGate.heartbeat.schedule="0 */6 * * *" \
  --set evalGate.heartbeat.maxAgeMinutes=1560   # 26h; must exceed one nightly interval + grace
```

Set `maxAgeMinutes` above one nightly interval + the run's duration + a grace
window (default 26h for a 24h cadence) so the normal gap between two nightly
runs never looks stale. On the Replit Scheduled Deployment path, run
`node artifacts/api-server/evals/heartbeat.mjs --check` as its own scheduled job
with `DATABASE_URL` + the `CHANNEL_*` vars + `EVAL_HEARTBEAT_MAX_AGE_MINUTES`
set.

**External leg (cluster-down coverage).** The two CronJobs above run *inside*
the cluster, so they cover the common silent-failure cases — CronJob disabled,
image pull failure, node pressure, a hung run — but a *total* cluster/scheduler
outage would silence the in-cluster checker too: an in-cluster switch cannot
report that the cluster it lives in is down. To close that gap, the nightly job
also pings an **external** uptime / dead-man's-switch service (healthchecks.io,
Cronitor, etc.) when `HEARTBEAT_PING_URL` is set. That service runs outside your
cluster and fires its own alert when an expected ping is missed — so if the
whole cluster goes dark and the nightly job never runs (and therefore never
pings), on-call is still paged from outside.

- Set `HEARTBEAT_PING_URL` on the **nightly** job (the `eval-gate-llm.sh` /
  `evalGate.nightly` job — *not* the checker). Configure the monitor's expected
  period + grace to match your nightly cadence (e.g. period 24h, grace 2h) so a
  single missed run alerts.
- **Start / success / fail signals.** The nightly job sends a **start** signal
  *before* the eval run (`heartbeat.mjs --start`) and a **success** or **fail**
  signal *after* (`heartbeat.mjs --record --exit-code=$gate_status`). The start
  signal lets the monitor alert **fast** when a run begins but the matching
  completion never arrives — a hung suite, or an LLM call wedged past its
  timeout — instead of waiting out the whole grace window, and lets it tell
  "started but hung" apart from "never scheduled". The fail signal marks a
  *failed-but-alive* run distinctly from a *missed* run. The URL shape follows
  your monitor's convention via `HEARTBEAT_PING_STYLE`:
  - `healthchecks` (default) — start → `<url>/start`, success → `<url>`,
    fail → `<url>/fail` (healthchecks.io's `/start` + `/fail` endpoints).
  - `cronitor` — start → `<url>?state=run`, success → `<url>?state=complete`,
    fail → `<url>?state=fail` (Cronitor's telemetry `state` param).
  In your monitor, enable "started" tracking (healthchecks.io: the run is
  considered started after a `/start` ping; Cronitor: `state=run`) so a missing
  completion after a start pages quickly.
- The ping is **env-gated** (fully inert when `HEARTBEAT_PING_URL` is unset) and
  **best-effort**: a failed/timed-out/non-2xx ping (including the start ping) is
  logged and swallowed and never changes the eval job's exit code — the same
  non-fatal posture as the DB record. Tune the request timeout via
  `HEARTBEAT_PING_TIMEOUT_MS` (default 10000).
- **Misconfiguration is caught, not silently swallowed.** A `HEARTBEAT_PING_URL`
  that is not a valid absolute `http(s)` URL (a typo, a bare host, a non-web
  scheme) would otherwise look like a permanently-down monitor. The pinger
  validates the URL up front: a misconfigured value is logged loudly
  (`console.error`) and the ping is skipped (no fetch attempt, `misconfigured:true`
  in the result) rather than firing a request that could be mistaken for a
  transient blip. This is still non-fatal — it never changes the eval job's exit
  code.
- The external leg and the in-cluster leg are independent: a DB hiccup never
  suppresses the external ping and vice versa. Run both for defense in depth —
  the in-cluster checker gives a fast, channel-native page for the common cases;
  the external monitor is the only thing that can page when the cluster itself
  is down, or when a run hangs mid-flight.

On the Helm path, turn the external ping on by pointing the **nightly** job at a
Secret holding the ping URL (it carries a per-check token, so it's a secret —
same secretKeyRef pattern as the `CHANNEL_*` webhook URLs). Inert until you set
`evalGate.nightly.heartbeatPing.existingSecret`:

```bash
# Create (or reuse) a Secret with the ping URL under key `heartbeat-ping-url`:
kubectl -n phi-audit create secret generic phi-audit-heartbeat-ping \
  --from-literal=heartbeat-ping-url="https://hc-ping.com/<your-uuid>"

helm upgrade phi-audit deploy/helm/phi-audit -n phi-audit --reuse-values \
  --set evalGate.nightly.heartbeatPing.existingSecret=phi-audit-heartbeat-ping
  # optional: --set evalGate.nightly.heartbeatPing.key=heartbeat-ping-url
  # optional: --set evalGate.nightly.heartbeatPing.timeoutMs=10000
```

This injects `HEARTBEAT_PING_URL` (and optional `HEARTBEAT_PING_TIMEOUT_MS`)
into the nightly eval container only — the checker CronJob never pings. On the
Replit Scheduled Deployment path, set `HEARTBEAT_PING_URL` (and optionally
`HEARTBEAT_PING_TIMEOUT_MS`) as env on the nightly `eval-gate-llm.sh` job
instead.

## Per-cloud authentication summary

| Cloud | LLM / embedder auth | DB auth | DB sidecar | Notes |
|---|---|---|---|---|
| **AWS** | IRSA → Bedrock (no key) | RDS IAM via Secrets Manager + External Secrets Operator (default) **or** RDS IAM token sidecar (opt-in) | Off by default; opt-in via `values-aws.yaml` | NOTARIZATION_SECRET in a separate AWS account |
| **GCP** | Workload Identity → Vertex (no key) | Cloud SQL Auth Proxy sidecar w/ `--auto-iam-authn` | **On** — `gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.13.0` | NOTARIZATION_SECRET in a separate GCP project |
| **Azure** | Workload Identity → Azure OpenAI; API key still required by SDK shape | Password from Key Vault via Secrets Store CSI Driver | **Off** — per direction; managed identity to Azure DB is direct | NOTARIZATION_SECRET in a separate Azure tenant or separate Key Vault w/ separate access policy |

## Lexical search backend (M10.1)

The lexical (BM25) leg of hybrid retrieval is pluggable via `SEARCH_PROVIDER`:

- **`postgres`** (default) — Postgres FTS `search_tsv` generated column. Zero extra infra; the dev/early-milestone path. The semantic (pgvector) leg and RRF fusion are identical regardless of provider.
- **`opensearch`** (production) — routes the lexical leg to a managed OpenSearch cluster. Requires `OPENSEARCH_ENDPOINT` (+ optional `OPENSEARCH_INDEX_PREFIX`, `OPENSEARCH_USERNAME`/`OPENSEARCH_PASSWORD`). The SDK (`@opensearch-project/opensearch`) is lazy-loaded; operators must add it before enabling: `pnpm --filter @workspace/api-server add @opensearch-project/opensearch`.

There is **no `DEPLOYMENT_TARGET` shortcut** for search (unlike the embedder/LLM): OpenSearch always needs an explicit endpoint, so a bare cloud target must not silently flip the lexical leg off Postgres. Set `SEARCH_PROVIDER=opensearch` explicitly.

PHI safety: only the redacted projection (snippet/classification/severity/source) plus `tenant_id` is mirrored to OpenSearch — raw PHI never reaches the searchable tier (`threat_model.md §Information Disclosure`). Every query carries a mandatory `tenant_id` term-filter for RLS-equivalent tenant scoping. The index is reconciled at boot (after embedding backfill) and updated best-effort on ingest; a search-backend outage degrades retrieval to the vector leg and never fails ingest.

## Raw-evidence store (M10.2 / M10.3)

Where unredacted raw evidence (PHI / secrets) is persisted is pluggable via `RAW_EVIDENCE_PROVIDER`, behind a `RawEvidenceStore` seam (`raw-evidence-store.ts`) that mirrors the embedder/search factory+registry:

- **`database`** (default) — raw stays inline in the `findings.raw_evidence` jsonb column (`{first, latest}` occurrence snapshots). Zero extra infra; the dev/early-milestone path.
- **`s3`** (AWS WORM) — each occurrence is written as a NEW immutable S3 object under Object Lock. Requires `RAW_EVIDENCE_S3_BUCKET` + `AWS_REGION` (+ optional `RAW_EVIDENCE_S3_PREFIX` default `raw-evidence`, `RAW_EVIDENCE_OBJECT_LOCK_MODE=COMPLIANCE|GOVERNANCE` default `COMPLIANCE`, `RAW_EVIDENCE_RETENTION_DAYS` default `2555` = 7y). The bucket MUST be created with Object Lock enabled. SDK lazy-loaded; add it first: `pnpm --filter @workspace/api-server add @aws-sdk/client-s3`.
- **`gcs`** (GCP WORM) — requires `RAW_EVIDENCE_GCS_BUCKET` (+ optional `RAW_EVIDENCE_GCS_PREFIX`). WORM is enforced by an operator-provisioned **locked bucket retention policy** (the application writer role deliberately cannot weaken retention per `threat_model.md §Tampering`). Auth via ADC. Add the SDK first: `pnpm --filter @workspace/api-server add @google-cloud/storage`.
- **`azure-blob`** (Azure WORM) — requires `RAW_EVIDENCE_AZURE_CONTAINER` + `RAW_EVIDENCE_AZURE_CONNECTION_STRING` (+ optional `RAW_EVIDENCE_AZURE_PREFIX`). WORM is enforced by an operator-provisioned **locked container immutability policy**. Add the SDK first: `pnpm --filter @workspace/api-server add @azure/storage-blob`.

There is **no `DEPLOYMENT_TARGET` shortcut** (same reasoning as search): moving raw PHI to an object store is always explicit — every store needs a bucket/container, and a bare cloud target must never silently start writing unredacted PHI to an unprovisioned location.

How it works: when an external store is active, ingest writes each occurrence's raw payload as an immutable object (key `<prefix>/<tenant>/<finding>/<uuid>.json`) and records `{first, latest}` object URIs in the new `findings.raw_evidence_ref` jsonb column; the `raw_evidence` column stays NULL. The break-glass read path (`GET /api/admin/findings/:id/raw`) resolves the ref through the store, which re-validates tenancy + bucket on the URI before fetching. PHI safety: `raw_evidence_ref` is excluded from `findingSafeColumns` (compile-time gate) and the `findings_redacted` view, so it is reachable only via the step-up-gated break-glass endpoint — exactly like `raw_evidence`. A failed external write leaves the finding committed but the ref NULL (logged at error level); break-glass then reports `raw_unresolved` rather than fabricating a payload. The schema column is additive (`ADD COLUMN IF NOT EXISTS`); switching providers is forward-only (objects already written under one provider are not migrated).

## HPA caveat

The agent supervisor (M5) uses an **in-process queue** with `CONCURRENCY=2` per pod. Scaling api replicas multiplies effective concurrency. The HPA defaults (min=2, max=6) yield 4–12 concurrent agent jobs cluster-wide; tune `AGENT_DAILY_TOKEN_BUDGET` accordingly. If you need single-writer semantics for the supervisor (e.g. exactly-N model calls per finding regardless of replica count), the right fix is to externalize the queue (Temporal / Kafka) — not to pin replica=1 (you lose HA).

## CI: chart lint + render matrix

`deploy/scripts/helm-matrix.sh` lints + renders all three overlays (`values-{aws,gcp,azure}.yaml`) against the prod-like fixtures in `deploy/helm/phi-audit/ci/`. It also renders the optional eval CronJobs to prove they wire up correctly: the nightly eval gate (aws — env wiring; gcp — native DB sidecar) and the heartbeat dead-man's switch (gcp + `evalGate.heartbeat.enabled=true` + channels, asserting the `--check` command, `EVAL_HEARTBEAT_MAX_AGE_MINUTES`, reused nightly image, native DB sidecar, and channel env — plus that neither CronJob renders when disabled). Finally it runs four negative cases proving the `_helpers.tpl` fail-fast validators actually trip:

- missing `image.api.tag`
- `llm.provider=vertex` without `llm.gcp.projectId`
- `database.sidecar.args` containing `--help` (Cloud SQL Proxy placeholder)
- `llm.provider=bedrock` without `llm.aws.region`

Run from repo root: `pnpm run helm:matrix` (or directly `deploy/scripts/helm-matrix.sh`). Requires `helm` v3+; optionally `kubeconform` for K8s schema validation of every rendered manifest. CI fixtures are deliberately minimal — they set only the operator-required fields (image refs, secret names, ingress host, GCP project, sidecar args) and let the overlay defaults stand for everything else. Pass `KUBE_VERSION=1.30.0` to override the `--kube-version` flag (default 1.30.0; needed because the chart pins `kubeVersion: >=1.27.0-0` and old helm clients can't infer one).

## Replit deploy (M9.4)

The Replit deploy path uses Replit's publishing system; no Helm/Docker required. Operator sets these in the Replit Deployments panel:

- `DATABASE_URL`, `SESSION_SECRET` — already in Replit Secrets for dev
- `NOTARIZATION_SECRET` — **add as a separate secret**; co-locating with `SESSION_SECRET` defeats §23.2
- `LLM_PROVIDER` / `EMBEDDING_PROVIDER` / cloud creds — only if you want to hit a cloud model from a Replit deploy; the default `gemini-replit` works zero-config but provides **no BAA** and is dev/demo only (enforced by `threat_model.md §Dev-vs-Production`)

Limitations vs the K8s path:

- No NetworkPolicy / egress allow-list (cluster-level concern; not available)
- No sidecars (single-process)
- No multi-replica supervisor coordination — supervisor must stay in-process

Use Replit deploy for demo / preview environments. Use the Helm chart for production.

## Terraform `modules/postgres` (M9.2)

`deploy/terraform/modules/postgres` is the provider-abstracted Postgres module. One module, four branches (`provider_name = "aws" | "gcp" | "azure" | "self-hosted"`), one uniform output contract so the same Helm wiring works on any cloud.

- **AWS** — `aws_db_instance` PG 17 + custom parameter group (`shared_preload_libraries=pg_stat_statements,vector`, `rds.force_ssl=1`); IAM DB authn for IRSA; Secrets Manager for `DATABASE_URL`.
- **GCP** — `google_sql_database_instance` PG 17 (pgvector preinstalled); `cloudsql.iam_authentication=on` for Workload Identity; Secret Manager. Pod talks to the instance via the Cloud SQL Auth Proxy sidecar (`cloudsqlproxy.enabled=true` in the Helm chart), so the emitted `host=127.0.0.1`.
- **Azure** — `azurerm_postgresql_flexible_server` PG 16 + `azure.extensions=VECTOR` allow-list (required before `CREATE EXTENSION vector` succeeds); AAD admin group; Key Vault reference.
- **self-hosted** — no resources; passes through operator-supplied connection string + secret ref so the downstream Helm wiring stays identical.

Hard preconditions (fail at plan time, not at apply time):
- Production (`deletion_protection=true`) without a customer-managed `kms_key_id` fails on every cloud branch with a pointer to threat_model §Tampering & key-isolation. The provider-managed default key cannot be rotated independently and so cannot anchor the storage-encryption claim.
- `provider_name='aws'` without an `aws = { … }` block fails with a single clear error (and same for the other three branches), instead of N null-deref explosions deeper in the graph.

`kms_key_id` here is the **storage encryption key** for the DB instance. The **notarization key** that signs ledger checkpoints (threat_model §23.2) is a different key, in a different account/project/subscription, and is provisioned by M9.3's per-cloud roots — not by this module.

Runnable examples: `deploy/terraform/examples/{aws,gcp,azure,self-hosted}/main.tf`.

Local validation: `pnpm run tf:fmt` (or `deploy/scripts/tf-fmt-check.sh`) runs `tofu fmt -recursive -check -diff`. The heavier `tofu validate` requires `tofu init`, which downloads ~500 MB of cloud provider plugins; that runs in CI on a cached runner, not on every commit. The script auto-detects `tofu`, `terraform`, or a locally-installed `.local/bin/tofu` in that order; on a runner that has none it exits 0 with a "skipping" log so it doesn't break unrelated CI.

## Not built yet (deferred to M9.3)

- Terraform root modules per cloud (EKS / GKE / AKS + IAM wiring + KMS for `NOTARIZATION_SECRET` in a separate account / project / tenant). M9.2's module becomes a sub-module call from each root.
- CI/CD pipeline definitions (operator policy, deliberately out of scope).
