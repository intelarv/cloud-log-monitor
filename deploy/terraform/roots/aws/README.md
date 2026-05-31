# PHI-Audit AWS root

Per-cloud Terraform root for the AWS deploy of PHI-Audit. Consumes the
provider-abstracted Postgres module (M9.2) and produces the values that the
M9.1 Helm chart's `values-aws.yaml` overlay needs.

## Scope

**Provisions:**
- EKS cluster (control plane + managed node group; private API endpoint)
- IAM OIDC provider + IRSA role for the `phi-audit-api` ServiceAccount, with
  Bedrock InvokeModel + Secrets Manager read + CloudWatch Logs read
- Postgres via `../../modules/postgres` (RDS with pgvector 0.8)
- Secrets Manager entries:
  - `database` — `DATABASE_URL` from the M9.2 module
  - `session`  — `SESSION_SECRET`
  - `notarization` — `NOTARIZATION_SECRET` in a **separate AWS account**

**Does NOT provision (bring your own):**
- VPC + subnets + NAT (use `terraform-aws-modules/vpc/aws`)
- DNS + ACM certs (ingress-specific)
- RDS security group (must allow :5432 from the EKS node SG)
- The KMS keys themselves (created out-of-band by your platform team)

## Why two AWS accounts

`threat_model.md` §23.2 (External notarization) requires that the key signing
ledger checkpoints lives in a different trust zone than the workload it
attests to. If both the application database and the notarization key share
an AWS account, then any compromise of the production account — root, IAM
pivot, IRSA escape — could forge a checkpoint matching a doctored ledger
head, defeating the tamper-evidence claim retroactively.

This root enforces that by accepting an aliased provider:

```hcl
provider "aws" {
  alias  = "notarization"
  region = "us-east-1"
  # Different account: use a profile, assume_role, or a separate access key.
  assume_role {
    role_arn = "arn:aws:iam::<NOTARIZATION_ACCOUNT_ID>:role/PhiAuditNotarizationProvisioner"
  }
}

module "phi_audit" {
  source = "../../roots/aws"
  providers = {
    aws              = aws
    aws.notarization = aws.notarization
  }
  # ...
}
```

The notarization KMS key (`notarization_kms_key_id`) is created in the
notarization account ahead of time and its key policy must include the
production IRSA role under `kms:Decrypt`:

```json
{
  "Sid": "AllowProductionApiDecrypt",
  "Effect": "Allow",
  "Principal": { "AWS": "<production-IRSA-role-arn>" },
  "Action": "kms:Decrypt",
  "Resource": "*"
}
```

**No chicken-and-egg required.** The IRSA role ARN is deterministic from
`<aws_account_id>` + `<name_prefix>` — specifically
`arn:aws:iam::<PROD_ACCOUNT_ID>:role/<name_prefix>-api`. Pre-compute this and
configure the notarization-account key policy before the first apply; the
key policy doesn't need the role to exist yet, just to know its future ARN.

## Operator workflow

```bash
tofu init
tofu plan -var-file=terraform.tfvars
tofu apply -var-file=terraform.tfvars
```

Take the outputs and apply them to `deploy/helm/phi-audit/values-aws.yaml`:

| Output | Helm value |
|---|---|
| `irsa_role_arn` | `serviceAccount.api.annotations["eks.amazonaws.com/role-arn"]` |
| `database_secret_arn` | sync via ESO into K8s Secret `phi-audit-db`, then `database.existingSecret: phi-audit-db` |
| `session_secret_arn` | sync via ESO, mount as `SESSION_SECRET` env |
| `notarization_secret_arn` | sync via ESO cross-account secret store, mount as `NOTARIZATION_SECRET` env |

## What's out of scope (deferred / operator policy)

- CI/CD pipelines (CodePipeline / GitHub Actions): operator policy, not
  application code.
- Multi-region failover: a separate root invocation per region; cross-region
  ledger replication is a §17.5 deferred concern.
- KMS key rotation runbooks: `NOTARIZATION_RETIRED_KEYS` is the app's
  rotation-grace handle; the operator-side runbook is a docs deliverable.
