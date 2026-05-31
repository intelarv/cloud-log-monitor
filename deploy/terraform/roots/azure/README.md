# PHI-Audit Azure root

Per-cloud Terraform root for the Azure deploy of PHI-Audit. Consumes the
M9.2 Postgres module and produces the values that the M9.1 Helm chart's
`values-azure.yaml` overlay needs.

## Scope

**Provisions:**
- AKS cluster (OIDC issuer + Workload Identity enabled, Azure CNI + Azure
  NetworkPolicy)
- User-Assigned Managed Identity `phi-audit-api` + Federated Identity
  Credential binding to the `phi-audit-api` KSA, with Key Vault Secrets
  User on both the application vault AND the separate notarization vault
- Postgres via `../../modules/postgres` (Flexible Server PG 16 +
  pgvector via `azure.extensions=VECTOR`)
- Key Vault secrets:
  - `<name>-session-secret`     — SESSION_SECRET
  - `<name>-db-url`             — DATABASE_URL
  - `<name>-notarization-secret` — NOTARIZATION_SECRET in the **separate
    notarization Key Vault** (different subscription, ideally different tenant)

**Does NOT provision:**
- VNet + subnets (BYO; including a /28+ delegated subnet for Flexible Server)
- DNS + AGIC + Application Gateway TLS certs
- Azure OpenAI deployment (managed out-of-band; the Helm overlay carries the
  endpoint + deployment name)
- The application Key Vault itself (referenced by name) — assumed
  pre-created by the platform team
- The notarization Key Vault — pre-created in the separate subscription

## Why two subscriptions

`threat_model.md` §23.2 requires the notarization signing key to live in a
trust zone separate from the workload it attests to. On Azure, subscription
boundaries (and ideally Azure AD tenant boundaries) are the operative trust
unit: RBAC, Key Vault access, audit logs are all subscription-scoped.
Co-locating the notarization key with the workload allows a
subscription-admin compromise to forge ledger checkpoints retroactively.

Aliased provider pattern:

```hcl
provider "azurerm" {
  features {}
  subscription_id = "<PROD_SUBSCRIPTION_ID>"
  tenant_id       = "<PROD_TENANT_ID>"
}

provider "azurerm" {
  alias           = "notarization"
  features {}
  subscription_id = "<NOTARIZATION_SUBSCRIPTION_ID>"
  tenant_id       = "<NOTARIZATION_TENANT_ID>"   # ideally distinct
}

module "phi_audit" {
  source = "../../roots/azure"
  providers = {
    azurerm              = azurerm
    azurerm.notarization = azurerm.notarization
  }
  # ...
}
```

Pre-create the notarization Key Vault in the notarization subscription and
pass its resource id as `notarization_key_vault_id`. The vault must have
RBAC authorization mode enabled (`enable_rbac_authorization = true`) so this
root's `Key Vault Secrets User` role assignment for the api MI works.

## Operator workflow

```bash
tofu init
tofu plan -var-file=terraform.tfvars
tofu apply -var-file=terraform.tfvars
```

Then for the Helm overlay (`values-azure.yaml`):

| Output | Helm value |
|---|---|
| `api_managed_identity_client_id` | `serviceAccount.api.annotations["azure.workload.identity/client-id"]` |
| `database_url_secret_name` | Secrets Store CSI Driver `SecretProviderClass.parameters.objects[].objectName`; sync to K8s Secret `phi-audit-db`, then `database.existingSecret: phi-audit-db` |
| `session_secret_name` | same pattern, mount as `SESSION_SECRET` env |
| `notarization_secret_name` | same pattern but with cross-vault `SecretProviderClass` pointing at the notarization vault, mount as `NOTARIZATION_SECRET` env |

The Azure OpenAI deployment name + endpoint are NOT outputs of this root —
they're operator-supplied in `values-azure.yaml` under `llm.azureOpenai`.
