variable "provider_name" {
  description = "Which cloud to provision against. `self-hosted` skips provisioning and passes through `self_hosted.connection_string` (e.g. operator-managed Postgres, in-cluster CNPG, RDS Proxy fronting an existing instance)."
  type        = string
  validation {
    condition     = contains(["aws", "gcp", "azure", "self-hosted"], var.provider_name)
    error_message = "provider_name must be one of: aws, gcp, azure, self-hosted."
  }
}

variable "name" {
  description = "Logical name prefix for the instance + its associated secret. Becomes the RDS identifier / Cloud SQL instance id / Flexible Server name."
  type        = string
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,38}$", var.name))
    error_message = "name must be 3-39 chars, start with a lower-case letter, and contain only [a-z0-9-]."
  }
}

variable "tenant_id" {
  description = "Application tenant id propagated as a tag/label across all created resources. Used for cost attribution and RLS scoping at the app layer."
  type        = string
}

variable "engine_version" {
  description = "PostgreSQL major.minor version. Default per provider is the lowest version that ships pgvector >= 0.8 on each managed Postgres surface. Override only if you have a hard reason."
  type        = string
  default     = ""
}

variable "database_name" {
  description = "Initial database created on the instance. The app expects this to match `DATABASE_URL`'s path component."
  type        = string
  default     = "phi_audit"
}

variable "app_username" {
  description = "Application role created on the instance. NOT a superuser. Owns the schema; RLS is enforced at the app layer."
  type        = string
  default     = "phi_audit_app"
}

variable "storage_gb" {
  description = "Initial allocated storage. All three providers expand on demand within their own autogrow limits; this is the floor."
  type        = number
  default     = 100
}

variable "backup_retention_days" {
  description = "PITR window in days. HIPAA-grade default is 35; managed services cap varies per branch (AWS: 35, GCP: 365, Azure: 35)."
  type        = number
  default     = 35
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 365
    error_message = "backup_retention_days must be 7..365."
  }
}

variable "deletion_protection" {
  description = "If true, the managed-service `deletion_protection` / `delete_protection_state` flag is set. Operators MUST keep this true in production; staging tear-down should explicitly override."
  type        = bool
  default     = true
}

variable "high_availability" {
  description = "Enable provider-native HA (multi-AZ on AWS, regional on GCP, zone-redundant on Azure). Required for HIPAA-grade production; ok to disable in non-prod."
  type        = bool
  default     = true
}

variable "kms_key_id" {
  description = "Customer-managed key for storage encryption. Must be in the SAME cloud account/project/subscription as the instance. The `NOTARIZATION_SECRET` KMS key per threat_model §23.2 lives in a SEPARATE account and is NOT this key — do not collapse them."
  type        = string
  default     = ""
}

# --- Per-provider blocks ---------------------------------------------------
# Each block is optional() so callers can pass just the one they need; an
# `unused` block on a different provider is intentionally ignored.

variable "aws" {
  description = "AWS-specific config. Required when provider_name='aws'."
  type = object({
    region                              = string
    instance_class                      = optional(string, "db.t4g.medium")
    vpc_security_group_ids              = list(string)
    db_subnet_group_name                = string
    iam_database_authentication_enabled = optional(bool, true)
    monitoring_role_arn                 = optional(string, "")
    performance_insights_enabled        = optional(bool, true)
    tags                                = optional(map(string), {})
  })
  default = null
}

variable "gcp" {
  description = "GCP-specific config. Required when provider_name='gcp'."
  type = object({
    project_id         = string
    region             = string
    tier               = optional(string, "db-custom-2-7680")
    private_network    = string # full self-link of the VPC
    allocated_ip_range = optional(string, "")
    enable_iam_authn   = optional(bool, true)
    require_ssl        = optional(bool, true)
    labels             = optional(map(string), {})
  })
  default = null
}

variable "azure" {
  description = "Azure-specific config. Required when provider_name='azure'."
  type = object({
    resource_group_name      = string
    location                 = string
    sku_name                 = optional(string, "GP_Standard_D2ds_v5")
    delegated_subnet_id      = string
    private_dns_zone_id      = string
    aad_admin_object_id      = optional(string, "")
    aad_admin_principal_name = optional(string, "")
    aad_admin_tenant_id      = optional(string, "")
    tags                     = optional(map(string), {})
  })
  default = null
}

variable "self_hosted" {
  description = "Required when provider_name='self-hosted'. The module emits these as outputs verbatim; no resources are provisioned."
  type = object({
    connection_string = string
    host              = string
    port              = optional(number, 5432)
    database          = string
    username          = string
    secret_ref        = optional(string, "")
  })
  default   = null
  sensitive = true
}
