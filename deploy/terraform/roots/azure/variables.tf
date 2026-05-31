variable "name_prefix" {
  description = "Logical name prefix for every resource created by this root."
  type        = string
  default     = "phi-audit"
}

variable "resource_group_name" {
  description = "Existing resource group for AKS + Flexible Server + Key Vault. The notarization Key Vault lives in a SEPARATE subscription (see README)."
  type        = string
}

variable "location" {
  description = "Azure region for AKS + Flexible Server. Azure OpenAI deployment is referenced by Helm overlay, not provisioned here."
  type        = string
}

variable "tenant_id" {
  description = "Application tenant id (NOT the Azure tenant id) propagated as a tag for cost attribution + RLS scoping at the app layer."
  type        = string
}

variable "azure_aad_tenant_id" {
  description = "Azure AD tenant id for AKS + Workload Identity federation. Distinct from `tenant_id` above (application-level)."
  type        = string
}

variable "subnet_id" {
  description = "AKS node subnet id. Must be in a VNet that can reach the Flexible Server delegated subnet."
  type        = string
}

variable "pg_delegated_subnet_id" {
  description = "Subnet delegated to Microsoft.DBforPostgreSQL/flexibleServers for the Postgres instance. Must be /28 or larger and empty before first apply."
  type        = string
}

variable "pg_private_dns_zone_id" {
  description = "Private DNS zone id for `<name>.postgres.database.azure.com` resolution from AKS pods."
  type        = string
}

variable "aad_admin_object_id" {
  description = "Object id of the AAD group that will be the Postgres AAD admin (members can log in as the Postgres admin via AAD token). Operator-managed; not provisioned here."
  type        = string
}

variable "aad_admin_principal_name" {
  description = "Display name of the AAD group identified by `aad_admin_object_id`. Azure Flexible Server validates that this matches the real AD object — if they disagree, the AD admin assignment fails at apply time. Must be the group's actual displayName, not an arbitrary label."
  type        = string
}

variable "kubernetes_version" {
  description = "AKS control-plane version."
  type        = string
  default     = "1.30"
}

variable "node_vm_size" {
  description = "Default AKS node pool VM size."
  type        = string
  default     = "Standard_D4s_v5"
}

variable "node_count" {
  description = "Default AKS node pool count."
  type        = number
  default     = 2
}

variable "key_vault_name" {
  description = "Application Key Vault name (same subscription as AKS). Holds SESSION_SECRET + DATABASE_URL. Notarization secret lives in a different vault (see `notarization_key_vault_id`)."
  type        = string
}

variable "notarization_key_vault_id" {
  description = "Resource id of the Key Vault in the SEPARATE notarization subscription/tenant. The notarization secret is written into it via the azurerm.notarization aliased provider. Threat_model §23.2 requires this vault to be in a different Azure subscription (ideally different tenant) than the workload."
  type        = string
}

variable "k8s_namespace" {
  description = "Kubernetes namespace the api-server pod runs in."
  type        = string
  default     = "phi-audit"
}

variable "k8s_service_account" {
  description = "Kubernetes ServiceAccount name for the api-server pod."
  type        = string
  default     = "phi-audit-api"
}

variable "tags" {
  description = "Tags applied to every resource. `tenant_id` is added automatically."
  type        = map(string)
  default     = {}
}
