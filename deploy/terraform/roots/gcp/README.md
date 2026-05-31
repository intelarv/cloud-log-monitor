# PHI-Audit GCP root

Per-cloud Terraform root for the GCP deploy of PHI-Audit. Consumes
the M9.2 Postgres module and produces the values that the M9.1 Helm
chart's `values-gcp.yaml` overlay needs.

## Scope

**Provisions:**
- GKE Autopilot cluster (private endpoint, Workload Identity enabled)
- Google Service Account `phi-audit-api` + Workload Identity binding to the
  `phi-audit-api` KSA, with `aiplatform.user`, `cloudsql.client`,
  `secretmanager.secretAccessor`, `logging.viewer`
- Postgres via `../../modules/postgres` (Cloud SQL PG 17 + pgvector)
- Secret Manager:
  - `database` — `DATABASE_URL` from the M9.2 module
  - `session` — `SESSION_SECRET`
  - `notarization` — `NOTARIZATION_SECRET` in a **separate GCP project**,
    CMEK-encrypted with that project's Cloud KMS key

**Does NOT provision:**
- VPC + subnets + secondary ranges (BYO)
- DNS + managed certs
- KMS keys themselves
- The notarization project itself (must exist + have a KMS key ring + key
  pre-created by the platform team)

## Why two GCP projects

`threat_model.md` §23.2 requires the notarization signing key to live in a
different trust zone than the workload it attests to. Project boundaries on
GCP are the operative trust unit: IAM, KMS, audit logs, and key access are
project-scoped. Co-locating the notarization key with the workload allows a
project-admin compromise to forge ledger checkpoints retroactively.

This root enforces it via an aliased provider:

```hcl
provider "google" {
  project = "phi-audit-prod"
  region  = "us-central1"
}

provider "google" {
  alias   = "notarization"
  project = "phi-audit-notarization"   # SEPARATE project
  region  = "us-central1"
}

module "phi_audit" {
  source = "../../roots/gcp"
  providers = {
    google              = google
    google.notarization = google.notarization
  }
  # ...
}
```

Pre-create the notarization key ring + key in the notarization project:

```bash
gcloud kms keyrings create phi-audit-notarization \
  --location=us-central1 --project=phi-audit-notarization
gcloud kms keys create signing \
  --keyring=phi-audit-notarization --location=us-central1 \
  --purpose=encryption --project=phi-audit-notarization
```

Pass the full resource id as `notarization_kms_key_id`:
`projects/phi-audit-notarization/locations/us-central1/keyRings/phi-audit-notarization/cryptoKeys/signing`

The Secret Manager service agent in the notarization project must hold
`roles/cloudkms.cryptoKeyEncrypterDecrypter` on that key; grant it
out-of-band before applying this root.

## Operator workflow

```bash
tofu init
tofu plan -var-file=terraform.tfvars
tofu apply -var-file=terraform.tfvars
```

Then for the Helm overlay (`values-gcp.yaml`):

| Output | Helm value |
|---|---|
| `api_service_account_email` | `serviceAccount.api.annotations["iam.gke.io/gcp-service-account"]` |
| `database_secret_name` | sync via ESO into K8s Secret `phi-audit-db`, then `database.existingSecret: phi-audit-db` |
| `gcp_instance_connection_name` | `database.sidecar.args` — `["--auto-iam-authn", "<this>", "--port=5432", "--health-check"]` |
| `session_secret_name` | sync via ESO, mount as `SESSION_SECRET` env |
| `notarization_secret_name` | sync via ESO (cross-project ServiceAccount), mount as `NOTARIZATION_SECRET` env |
