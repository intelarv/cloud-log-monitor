# Deployment (M9)

Two deployment paths today: container/Kubernetes via **M9.1** (Helm + Docker) and Replit via **M9.4**. Per-cloud IaC is built — **M9.2** ships the provider-abstracted `modules/postgres`, and **M9.3** ships the three per-cloud Terraform roots under `roots/{aws,gcp,azure}/` (each consumes the M9.2 module and emits values for the M9.1 Helm overlays). A repo-level **CI pipeline** (`.github/workflows/ci.yml`) now runs the existing typecheck / eval-gate / test / IaC-lint gates on every push + PR (see "CI/CD pipeline" below). Still deferred (cluster + cloud operator policy, not application code): service-mesh mTLS enforcement and per-tenant KMS-key lifecycle automation.

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
- **In-cluster hung-run detection (fast signal).** The staleness check above only
  fires a full interval after a run *should* have completed. To catch a run that
  *began but wedged* (a hung suite, an LLM call stuck past its timeout, a pod
  killed mid-run) without waiting that long, the nightly job also stamps a
  `last_start_at` marker via `heartbeat.mjs --start` *before* the eval run, and
  `--check` pages a `high`-severity *“eval run hung”* alert when a start is older
  than `EVAL_HEARTBEAT_MAX_RUN_MINUTES` (default 120) with no completion at or
  after it. This is the in-cluster parallel of the external start/success signals
  below, so hung-run coverage no longer depends on an external monitor being
  configured. It reuses the **same** `CHANNEL_*` config + severity gating and the
  **same** PagerDuty liveness dedup key as the staleness alert — a hung run and a
  quiet job are both *“the nightly mechanism is unhealthy”*, so they fold into one
  incident whose summary reflects the current cause, and the same recovery
  `resolve` clears it when a later run completes. The payload is liveness metadata
  only (gate name, start/last-success timestamps, run age) — no scores, no PHI.
  Set `EVAL_HEARTBEAT_MAX_RUN_MINUTES` above the longest legitimate run (the LLM
  suites dominate) plus scheduling slack so a slow-but-healthy run never
  false-pages. Hung detection needs the durable row, so it requires `DATABASE_URL`
  on both the nightly (`--start`) and checker (`--check`) jobs; a pre-upgrade row
  with no `last_start_at`, or any deployment that never calls `--start`, is never
  hung and behaves exactly as before (`ADD COLUMN IF NOT EXISTS` migrates the
  table in place, and the original `last_success_at NOT NULL` is relaxed so a
  start-only row is legal).

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
- **Per-change gate signalling.** The fast, deterministic per-change gate
  (`eval-gate.sh`, the `eval-gate` validation command) also fires the same
  `--start` / `--record --exit-code` pair when `HEARTBEAT_PING_URL` is set, so a
  per-change run that begins but never completes (a hung suite, a killed CI
  runner) pages an external monitor fast, just like the nightly job. It is
  scoped apart from the nightly switch so the two never cross-signal:
  `EVAL_HEARTBEAT_NAME` defaults to **`per-change`** (the nightly job uses
  `nightly`), giving each its own external monitor/check, and because the
  per-change gate is DB-free it runs the heartbeat with `DATABASE_URL` unset — so
  **only** the external ping leg fires and the in-cluster row (owned by the
  nightly job) is never touched. Point a *separate* external monitor — tuned to
  your per-change cadence, not the 24h nightly one — at this gate's
  `HEARTBEAT_PING_URL`. Fully inert when `HEARTBEAT_PING_URL` is unset (local +
  default CI runs page nothing), and every call is best-effort + non-fatal so it
  can never block or change the gate result.

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

How it works: when an external store is active, ingest writes each occurrence's raw payload as an immutable object (key `<prefix>/<tenant>/<finding>/<uuid>.json`) and records `{first, latest}` object URIs in the new `findings.raw_evidence_ref` jsonb column; the `raw_evidence` column stays NULL. The break-glass read path (`GET /api/admin/findings/:id/raw`) resolves the ref through the store, which re-validates tenancy + bucket on the URI before fetching. PHI safety: `raw_evidence_ref` is excluded from `findingSafeColumns` (compile-time gate) and the `findings_redacted` view, so it is reachable only via the step-up-gated break-glass endpoint — exactly like `raw_evidence`. A failed external write leaves the finding committed but does not advance `raw_evidence_ref` for that occurrence (NULL for a first occurrence; the prior `{first, latest}` retained for a later one), logged at error level; break-glass then reports `raw_unresolved` for an unresolvable ref rather than fabricating a payload. The schema column is additive (`ADD COLUMN IF NOT EXISTS`); switching providers is forward-only (objects already written under one provider are not migrated).

### Bringing up an external WORM store (provisioning + verification runbook)

Everything code-side is already built and default-inert; turning it on is an **ops** task. The app is deliberately a least-privileged *writer + reader* — it never provisions, locks, or weakens the WORM policy. That separation is the control (`threat_model.md §Tampering`: "the writer role MUST NOT have permissions to disable Object Lock or change retention"), so the bucket/container and its immutability policy are provisioned out-of-band first, then the app is pointed at it.

**Step 1 — Provision the WORM bucket/container (cloud-side, one-time).** Do NOT grant the app's identity any policy-management permission in any of these.

- **S3** — Create the bucket with **Object Lock enabled at creation** (it cannot be enabled afterward) and versioning on. The app stamps each object's `ObjectLockMode`/`ObjectLockRetainUntilDate` per-PUT from `RAW_EVIDENCE_OBJECT_LOCK_MODE` (default `COMPLIANCE`) + `RAW_EVIDENCE_RETENTION_DAYS` (default 2555 = 7y); a bucket **default retention** is a good backstop but the app does not depend on it. Use **COMPLIANCE** in production — `GOVERNANCE` is bypassable via `s3:BypassGovernanceRetention` and the app logs a WARN at boot if selected.
- **GCS** — Create the bucket, set a **retention policy**, then **lock it** (`gcloud storage buckets update gs://<bucket> --retention-period=<e.g. 7y>` followed by `--lock-retention-policy`; locking is irreversible). The app writes objects normally and never manages the policy.
- **Azure Blob** — Create the container and apply a **locked time-based immutability policy** (a locked policy cannot be shortened or removed). The app writes blobs normally.

**Step 2 — Grant the app least-privilege identity.** Write + read only, never lock-management:

- **S3**: `s3:PutObject` + `s3:GetObject` on `<bucket>/<prefix>/*`, **plus `s3:PutObjectRetention`** — the app sets `ObjectLockMode`/`ObjectLockRetainUntilDate` *on the PUT*, and AWS requires `s3:PutObjectRetention` to accept those headers, so it must be **granted, not denied**. Under `COMPLIANCE` mode the retain-until stamped at write cannot be shortened by anyone (not even root), so granting it does not let the writer weaken WORM. What must be **denied / omitted** is everything that could weaken the lock itself: `s3:BypassGovernanceRetention`, `s3:DeleteObject*`, `s3:PutBucketObjectLockConfiguration`, `s3:PutBucketVersioning`. Region comes from `AWS_REGION`; credentials via the platform's normal AWS auth (IRSA on EKS — no static keys).
- **GCS**: `storage.objects.create` + `storage.objects.get` on the bucket (e.g. a custom role, not `roles/storage.admin`); **omit** `storage.buckets.update`. Auth via ADC / Workload Identity.
- **Azure**: blob read/write scoped to the container (e.g. *Storage Blob Data Contributor* on the container); the connection string in `RAW_EVIDENCE_AZURE_CONNECTION_STRING` must **not** be an account-management credential.

**Step 3 — Install the one SDK + set env, then restart.** Install only the SDK for the store you enable (they are optional deps): `pnpm --filter @workspace/api-server add @aws-sdk/client-s3` (or `@google-cloud/storage` / `@azure/storage-blob`). Set `RAW_EVIDENCE_PROVIDER` + that provider's required vars (see the bullets above). Boot logs `Raw-evidence store initialized {provider, external:true}` — if you see `external:false` the env did not take.

> **On Kubernetes this is a one-location change in the Helm overlay** — set `rawEvidence.provider` + the matching `rawEvidence.{s3,gcs,azure}.*` knobs in `values-{aws,gcp,azure}.yaml` (commented examples ship in each overlay; full reference in `values.yaml`). The chart emits exactly the `RAW_EVIDENCE_*` env above onto the api Deployment, fails fast on a missing bucket/container/region, and wires the Azure connection string from `secrets.rawEvidenceSecret` (S3/GCS use the pod's IRSA / Workload Identity). Default-inert: with `provider` unset the chart emits no `RAW_EVIDENCE_*` env at all. `deploy/scripts/helm-matrix.sh` renders + validates all three providers.

**Step 4 — Verify the full path end-to-end (staging / preview, synthetic findings only — `threat_model.md §Dev-vs-Production` forbids real PHI outside production).**

1. **New ingest lands in the store.** Trigger a synthetic finding (`POST /api/admin/ingest/replay`) and confirm a `<prefix>/<tenant>/<finding>/<uuid>.json` object appears in the bucket/container. In the DB the finding's `raw_evidence_ref` is populated and `raw_evidence` is NULL (the safe projection still hides both).
2. **Break-glass reads it back.** Grant a break-glass grant for that finding, then `GET /api/admin/findings/:id/raw`. The response resolves the payload and the ledger `break_glass.raw_phi_accessed` records `raw_source: "external_store"`, `raw_resolved: true`, `raw_fallback_used: false` (a degraded inline read also emits a separate `break_glass.raw_fallback_used`). A `raw_unresolved` reason instead means the payload could not be produced — most often the object write failed at ingest (check Step 2/3 perms), but also a resolver-side cause: a malformed `raw_evidence_ref`, no/ wrong store configured to resolve it, or a store outage. It is not a reader-auth bug (the grant already passed).
3. **Immutability actually holds.** From the app's own identity, attempt to overwrite or delete one of the written objects and confirm it is **denied** by the WORM policy. This is the real proof that retention is locked and the writer cannot weaken it; do it once per environment.
4. **(Optional) Age inline → WORM.** Only after Steps 1–3 pass, enable `RAW_EVIDENCE_TIER_AGE_DAYS` to migrate pre-existing *inline* raw into the store (see "Operating the two maintenance jobs" below). Tiering verifies get-after-put before nulling the inline copy, so a misconfigured store fails closed (inline preserved, `raw_evidence.tier_failed` ledgered) rather than losing evidence.

**Rollback / caveats.** Switching providers is **forward-only** — objects already written under one provider are not migrated, and the inline read-fallback only covers rows whose inline `raw_evidence` was never tiered away. To revert to `database`, unset `RAW_EVIDENCE_PROVIDER` and restart; new ingests go back inline, but findings whose raw already lives in the WORM store become unreadable via break-glass until the store is re-enabled (the objects are immutable and intact — this is a *config* rollback, not data loss). Never delete the bucket to "clean up": the retention lock will refuse it, by design.

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

## CI/CD pipeline (GitHub Actions)

`.github/workflows/ci.yml` runs the repo's existing gates on every push to `main` and every pull request, in three jobs. It invokes only commands already proven locally — it adds no new check, just wires them to a hosted runner:

- **quality** — `pnpm run typecheck` (all libs + leaf packages), `pnpm run eval:gate` (the six credential-free eval suites + the regression gate vs `evals/baseline.json`), and the dashboard vitest suite. No database, no secrets.
- **api-server-tests** — the api-server vitest suite against a `pgvector/pgvector:pg16` service container; `bootstrap()` creates the `vector` extension + schema idempotently, so a blank database suffices. `DATABASE_URL` points at the service; `SESSION_SECRET` is a CI-only throwaway (never a production key).
- **infra-lint** — `pnpm run tf:fmt` (OpenTofu `fmt -check`) + `pnpm run helm:matrix` (lint + render all three cloud overlays), with `tofu` and `helm` installed via their official setup actions.

The LLM/DB-backed eval suites (`pnpm run eval:gate:llm`) stay opt-in and are **not** run here, keeping CI credential-free and byte-identical to local `eval:gate` runs. Deliberately left to operator policy (they depend on the org's registry, cloud accounts, and release process): branch-protection / required-status-check configuration, signed-image build+publish, and deploy automation.

## Still deferred (cluster + cloud operator policy)

These two remain out of the application repo because they cannot be meaningfully built **or validated** inside it / the dev environment — they are live-cluster and cloud-account concerns:

- **Service-mesh mTLS enforcement.** The *application-layer* A2A mTLS transport seam is already built and default-inert (`A2A_REQUIRE_MTLS` + `A2A_MTLS_*` peer ABAC — see `replit.md` and `threat_model.md §EoP`). What remains is *mesh-level* enforcement: Istio/Linkerd `PeerAuthentication: STRICT`, automatic sidecar injection, and SPIFFE workload identities. That is mesh-specific YAML applied to a running cluster with no in-repo validation path, so it stays an operator deliverable.
- **Per-tenant KMS-key lifecycle.** Per-tenant customer-managed-key provisioning, rotation, and revocation across AWS KMS / GCP KMS / Azure Key Vault. This needs real cloud accounts plus a tenancy + billing model decision, and even `tofu validate` requires `tofu init`'s ~500 MB of provider plugins + cloud auth — none of which exists here. The single-key foundation (storage CMK in `modules/postgres`, notarization key in the M9.3 roots) is built; per-tenant fan-out is operator IaC.

## Operating the two maintenance jobs (runbook)

Two periodic, **leader-locked, default-inert** jobs bound the system's storage footprint. Both are wired at boot (`artifacts/api-server/src/index.ts` Steps 4.7 + 4.8) and stay completely off — nothing scheduled, eval gate byte-identical — until their switch env is set. Their *mechanism* is in `docs/CONFIGURATION.md` ("Optional env (by subsystem)") and `docs/ARCHITECTURE.md`; this is the operator how-to.

### What they do (one line each)

- **Raw-evidence tiering** (M10.4, `raw-evidence-tiering.ts`) — ages already-stored *inline* raw PHI (`findings.raw_evidence`) out into the external WORM store once a finding is older than the age window, verifying the WORM object is readable (get-after-put) before nulling the inline copy. Closes the gap that `RAW_EVIDENCE_PROVIDER` only routes *new* ingests.
- **Memory eviction** (M10.5, `memory-eviction.ts`) — bounds the derived `finding_embeddings` pgvector cache (consolidates old/resolved duplicates + per-tenant top-N count cap), never evicting a critical+open finding, never touching the append-only audit record.

### Preconditions

- **Tiering needs an external WORM store.** It is inert in *two* layers: it schedules only when `RAW_EVIDENCE_TIER_AGE_DAYS` is set **AND** `RAW_EVIDENCE_PROVIDER` is an external store (`s3` / `gcs` / `azure-blob`). With the inline `database` store there is no tier to age into — boot logs a WARN and stays inert. So enable WORM storage first (see the raw-evidence storage section above), confirm new ingests land in the bucket, then turn tiering on.
- **Eviction needs nothing external.** It operates purely on the local pgvector cache; setting the cap is sufficient.

### Enable

Set on the api-server (operator secret store / Helm values / Replit Deployment env), then restart:

| Job | Switch (required) | Tunables (optional, with defaults) |
| --- | --- | --- |
| Raw-evidence tiering | `RAW_EVIDENCE_TIER_AGE_DAYS` (e.g. `30`) | `RAW_EVIDENCE_TIER_INTERVAL_MS` (1h), `RAW_EVIDENCE_TIER_BATCH_SIZE` (100/tenant/run) |
| Memory eviction | `MEMORY_MAX_EMBEDDINGS_PER_TENANT` (e.g. `5000`) | `MEMORY_DECAY_HALF_LIFE_DAYS` (30), `MEMORY_EVICT_INTERVAL_MS` (6h) |

A non-positive / non-numeric value for any of these **throws at boot** (fail-fast, never silently disabled). Both jobs are leader-locked by their own Postgres advisory key, so it is safe to set the env fleet-wide — exactly one pod runs each job per cadence regardless of replica count.

### Verify it's running

Both jobs ledger every run — `raw_evidence.tiered` / `raw_evidence.tier_failed` and `memory.evicted` / `memory.evict_failed`. **None of these payloads ever carries PHI, raw evidence, or object-store URIs.** The two payload shapes differ, and that distinction matters when reading the audit trail vs. the dashboard:

- **Tiering events** carry the `finding_id` (plus the provider name, and on failure an error name) — they record *which* finding was migrated, so a single migration is auditable end-to-end. They do not carry the raw evidence or the WORM object URI (that lives in `raw_evidence_ref`, outside `findingSafeColumns`).
- **Eviction events** carry only counts + policy parameters — never a finding id, snippet, or the embedding content.
- The **dashboard / metrics API aggregates** all four into per-job *counts only* (no finding ids), which is what an operator watches day-to-day.

Where to look:

1. **Dashboard → Admin → "Cache-pruning Maintenance" panel.** Shows per-job run counts, embeddings evicted / findings tiered, failures (red when > 0), and last-run time. "Never run" + zeros means the job has not fired for your tenant yet (expected immediately after enabling, until the first cadence elapses and there is eligible data).
2. **API:** `GET /api/admin/metrics/maintenance` (the panel's data source) — tenant-scoped, requires a session; returns the aggregated counts.
3. **Raw audit trail:** the ledger itself, where each individual `raw_evidence.tiered` entry (with its `finding_id`) and each `memory.evicted` entry (with its counts) is recorded for per-event review.

Because the cadences are long (tiering 1h, eviction 6h by default) and only act on *eligible* rows (findings older than the age window / a cache over the cap), expect the panel to stay at zero until both the cadence has elapsed and there is qualifying data. To observe a run quickly in a non-prod environment, lower `*_INTERVAL_MS` and the age/cap.

### Troubleshoot

- **`failures` climbing on tiering** (`raw_evidence.tier_failed`) — a put/get/verify against the WORM store failed; the inline copy is preserved (nothing lost) and the row retries next cadence. This usually signals the same object-store outage that is also failing ingest writes — check store credentials / bucket policy / Object-Lock config. Break-glass reads are unaffected (they resolve `raw_evidence_ref` first, inline fallback otherwise).
- **`failures` on eviction** (`memory.evict_failed`) — embeddings were left intact and retried next cadence; only the *vector* retrieval leg is affected (BM25 + break-glass still work). Check DB health / the pgvector extension.
- **Panel stays at zero after enabling** — confirm the switch env is actually set on the api-server process (not just declared), that tiering also has an external `RAW_EVIDENCE_PROVIDER` (check boot logs for the inline-store WARN), and that enough wall-clock time + eligible data exist.
