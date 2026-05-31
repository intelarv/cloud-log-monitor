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

## Per-cloud authentication summary

| Cloud | LLM / embedder auth | DB auth | DB sidecar | Notes |
|---|---|---|---|---|
| **AWS** | IRSA → Bedrock (no key) | RDS IAM via Secrets Manager + External Secrets Operator (default) **or** RDS IAM token sidecar (opt-in) | Off by default; opt-in via `values-aws.yaml` | NOTARIZATION_SECRET in a separate AWS account |
| **GCP** | Workload Identity → Vertex (no key) | Cloud SQL Auth Proxy sidecar w/ `--auto-iam-authn` | **On** — `gcr.io/cloud-sql-connectors/cloud-sql-proxy:2.13.0` | NOTARIZATION_SECRET in a separate GCP project |
| **Azure** | Workload Identity → Azure OpenAI; API key still required by SDK shape | Password from Key Vault via Secrets Store CSI Driver | **Off** — per direction; managed identity to Azure DB is direct | NOTARIZATION_SECRET in a separate Azure tenant or separate Key Vault w/ separate access policy |

## HPA caveat

The agent supervisor (M5) uses an **in-process queue** with `CONCURRENCY=2` per pod. Scaling api replicas multiplies effective concurrency. The HPA defaults (min=2, max=6) yield 4–12 concurrent agent jobs cluster-wide; tune `AGENT_DAILY_TOKEN_BUDGET` accordingly. If you need single-writer semantics for the supervisor (e.g. exactly-N model calls per finding regardless of replica count), the right fix is to externalize the queue (Temporal / Kafka) — not to pin replica=1 (you lose HA).

## CI: chart lint + render matrix

`deploy/scripts/helm-matrix.sh` lints + renders all three overlays (`values-{aws,gcp,azure}.yaml`) against the prod-like fixtures in `deploy/helm/phi-audit/ci/`, then runs four negative cases proving the `_helpers.tpl` fail-fast validators actually trip:

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
