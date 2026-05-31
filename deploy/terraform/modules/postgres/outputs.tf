# Uniform output contract across all four branches. Downstream Helm values
# wire these identically — that's the whole point of this module.

output "provider_name" {
  description = "Echo of `var.provider_name` for downstream `provider == 'aws' ? ... : ...` switches."
  value       = var.provider_name
}

# All cloud-arm references use try() to defend against the standard Terraform
# count-index footgun: in `cond ? resources[0].attr : fallback`, some
# tofu/terraform versions eagerly evaluate BOTH arms and error with "Invalid
# index" on the count=0 side before the condition selects the live arm. try()
# falls back to the unselected branch's value without crashing planning.

output "host" {
  description = "Hostname the application connects to. For Cloud SQL with Auth Proxy this is 127.0.0.1 (proxy sidecar)."
  value = (
    local.is_aws ? try(aws_db_instance.this[0].address, "") :
    local.is_gcp ? "127.0.0.1" :
    local.is_azure ? try(azurerm_postgresql_flexible_server.this[0].fqdn, "") :
    try(var.self_hosted.host, "")
  )
}

output "port" {
  description = "TCP port. 5432 unless overridden by self-hosted."
  value = (
    local.is_aws ? try(aws_db_instance.this[0].port, 5432) :
    local.is_gcp ? 5432 :
    local.is_azure ? 5432 :
    try(var.self_hosted.port, 5432)
  )
}

output "database" {
  description = "Initial database name."
  value = (
    local.is_self_hosted ? try(var.self_hosted.database, "") : var.database_name
  )
}

output "username" {
  description = "Application username."
  value = (
    local.is_self_hosted ? try(var.self_hosted.username, "") : var.app_username
  )
}

output "database_url" {
  description = "Fully-formed DATABASE_URL the app can consume directly. Sensitive — pass via secret reference (`secret_ref`), not as a plain Helm value."
  sensitive   = true
  value = (
    local.is_aws ? try(format(
      "postgresql://%s:%s@%s:%d/%s?sslmode=require",
      var.app_username,
      random_password.app[0].result,
      aws_db_instance.this[0].address,
      aws_db_instance.this[0].port,
      var.database_name,
    ), "") :
    local.is_gcp ? try(format(
      "postgresql://%s:%s@127.0.0.1:5432/%s?sslmode=disable",
      var.app_username,
      random_password.app[0].result,
      var.database_name,
    ), "") :
    local.is_azure ? try(format(
      "postgresql://%s:%s@%s:5432/%s?sslmode=require",
      var.app_username,
      random_password.app[0].result,
      azurerm_postgresql_flexible_server.this[0].fqdn,
      var.database_name,
    ), "") :
    try(var.self_hosted.connection_string, "")
  )
}

output "secret_ref" {
  description = "Provider-native reference to the secret holding DATABASE_URL — Secrets Manager ARN (AWS), Secret Manager resource id (GCP), Key Vault secret id (Azure), or operator-supplied string (self-hosted). Wire this into the Helm chart's `databaseSecret.existingSecret` field via External Secrets Operator."
  value = (
    local.is_aws ? try(aws_secretsmanager_secret.db[0].arn, "") :
    local.is_gcp ? try(google_secret_manager_secret.db[0].id, "") :
    local.is_azure ? "kv://${try(var.azure.resource_group_name, "")}/${var.name}-db-credentials" :
    try(var.self_hosted.secret_ref, "")
  )
}

output "vector_enabled" {
  description = "True if the provisioned engine version ships pgvector >= 0.8. The app fails fast at boot if the column dim doesn't match; this lets the deploy pipeline assert before that boot."
  value = (
    local.is_aws ? true :
    local.is_gcp ? true :
    local.is_azure ? true :
    null # self-hosted: operator's responsibility
  )
}

output "iam_auth_enabled" {
  description = "True if cloud-IAM-based DB authn is enabled (IRSA on AWS, Workload Identity on GCP, AAD on Azure). The static password remains as a bootstrap-migration fallback."
  value = (
    local.is_aws ? try(var.aws.iam_database_authentication_enabled, false) :
    local.is_gcp ? try(var.gcp.enable_iam_authn, false) :
    local.is_azure ? try(var.azure.aad_admin_object_id, "") != "" :
    false
  )
}

output "engine_version" {
  description = "Effective Postgres major.minor version provisioned."
  value       = local.effective_engine_version
}

output "instance_id" {
  description = "Provider-native instance identifier; used for ops runbooks and out-of-band rotation."
  value = (
    local.is_aws ? try(aws_db_instance.this[0].id, "") :
    local.is_gcp ? try(google_sql_database_instance.this[0].name, "") :
    local.is_azure ? try(azurerm_postgresql_flexible_server.this[0].id, "") :
    "self-hosted"
  )
}

output "gcp_instance_connection_name" {
  description = "GCP-only: the `project:region:instance` string the Cloud SQL Auth Proxy sidecar needs. Empty for other providers."
  value       = local.is_gcp ? try(google_sql_database_instance.this[0].connection_name, "") : ""
}
