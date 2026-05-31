# `modules/postgres` — cloud-agnostic Postgres for PHI-Audit (M9.2)

Single module, four branches: AWS RDS, GCP Cloud SQL, Azure DB for PostgreSQL
Flexible Server, and self-hosted passthrough. The output contract is uniform
across all branches so the same `helm upgrade` invocation wires up identically
on any cloud.

```hcl
module "phi_audit_db" {
  source        = "github.com/<you>/phi-audit//deploy/terraform/modules/postgres"
  provider_name = "aws"   # | "gcp" | "azure" | "self-hosted"
  name          = "phi-audit-prod"
  tenant_id     = "default"
  kms_key_id    = "arn:aws:kms:..."

  aws = { ... }   # populate only the matching branch
}
```

See `deploy/terraform/examples/{aws,gcp,azure,self-hosted}/main.tf` for one
runnable example per branch.

## Branches at a glance

| Branch       | Resource                            | pgvector 0.8 | IAM authn               | Network                              |
| ------------ | ----------------------------------- | ------------ | ----------------------- | ------------------------------------ |
| `aws`        | `aws_db_instance` (PG 17)           | ✓ built-in   | IRSA (RDS IAM token)    | private subnet group + SG            |
| `gcp`        | `google_sql_database_instance`      | ✓ built-in   | Workload Identity       | Private Service Access + Auth Proxy  |
| `azure`      | `azurerm_postgresql_flexible_server` | ✓ via `azure.extensions=VECTOR` | AAD admin group | delegated subnet + private DNS zone  |
| `self-hosted`| _(none — passthrough)_              | operator     | operator                | operator                             |

## Uniform output contract

Every branch emits the same set:

- `database_url` (sensitive) — the full `postgresql://…` string the app reads
- `host`, `port`, `database`, `username` — components for ad-hoc tooling
- `secret_ref` — provider-native reference (Secrets Manager ARN / Secret
  Manager id / Key Vault path / operator-supplied string) suitable for
  External Secrets Operator
- `vector_enabled` — true if the engine version ships pgvector ≥ 0.8
- `iam_auth_enabled` — true if IRSA / Workload Identity / AAD is wired
- `engine_version`, `instance_id`, `provider_name`
- `gcp_instance_connection_name` — populated only on `gcp`; empty elsewhere

## HIPAA-grade defaults

The module fails plan-time (precondition) if the operator tries production
without a customer-managed key:

```
Error: Production (deletion_protection=true) requires a customer-managed KMS key;
       the AWS-managed default key cannot be rotated independently of AWS, which
       fails the threat_model §Tampering & key-isolation requirement.
```

Other HIPAA-aligned defaults baked in:

- 35-day PITR window (max on AWS & Azure; below GCP's 365 ceiling)
- High availability on (multi-AZ / regional / zone-redundant)
- Deletion protection on
- TLS required (`rds.force_ssl=1` / `ENCRYPTED_ONLY` / private DNS only)
- Public network access off everywhere
- DDL + slow-query logging on
- IAM authentication preferred; static password retained as the bootstrap
  migration fallback (the `db-push` Job in the Helm chart needs it)

## Key isolation note

`kms_key_id` is the *storage encryption* key for the DB instance. The
**notarization key** that signs ledger checkpoints (threat_model §23.2) is a
different key, in a different account/project/subscription, and is **never**
this key. M9.3's per-cloud Terraform roots will provision both — do not
collapse them.

## Validate locally

```sh
deploy/scripts/tf-fmt-check.sh   # tofu fmt -check -recursive
```

Provider-level `tofu validate` requires `tofu init`, which downloads ~500 MB
of cloud provider plugins; CI runs it once per branch on a runner with cache.
The fmt-check script is the lightweight gate that runs on every PR.

## Wiring into the Helm chart

The M9.1 Helm chart consumes the module's outputs via External Secrets
Operator. Minimal example (AWS):

```yaml
externalSecrets:
  enabled: true
  databaseSecret:
    secretStoreRef: aws-secrets-manager
    remoteSecretName: phi-audit-prod-db-credentials   # = module.phi_audit_db.secret_ref last segment
    propertyKey: DATABASE_URL
```

M9.3 will close the loop end-to-end (Terraform root → Helm release → live
URL) per cloud; M9.2 stops at the module boundary on purpose so it remains
reusable outside the PHI-Audit deploy stack.
