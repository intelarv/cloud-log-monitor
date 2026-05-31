# Azure branch — Azure Database for PostgreSQL Flexible Server with pgvector.
#
# Notes:
# - `azure.extensions = VECTOR` MUST be in the server's `azure_extensions`
#   parameter allow-list before `CREATE EXTENSION vector` will succeed.
#   We set it via the server_configuration resource below; the app's
#   first-boot `CREATE EXTENSION vector` is the activation step.
# - AAD admin (`active_directory_administrator`) lets pods on AKS Workload
#   Identity authenticate without a password; the static password we generate
#   is the bootstrap-migration fallback.

resource "azurerm_postgresql_flexible_server" "this" {
  count = local.is_azure ? 1 : 0

  name                = var.name
  resource_group_name = var.azure.resource_group_name
  location            = var.azure.location
  version             = local.effective_engine_version
  sku_name            = var.azure.sku_name

  storage_mb                   = var.storage_gb * 1024
  auto_grow_enabled            = true
  backup_retention_days        = var.backup_retention_days
  geo_redundant_backup_enabled = var.high_availability

  administrator_login    = var.app_username
  administrator_password = random_password.app[0].result

  delegated_subnet_id           = var.azure.delegated_subnet_id
  private_dns_zone_id           = var.azure.private_dns_zone_id
  public_network_access_enabled = false

  dynamic "high_availability" {
    for_each = var.high_availability ? [1] : []
    content {
      mode                      = "ZoneRedundant"
      standby_availability_zone = "2"
    }
  }

  dynamic "customer_managed_key" {
    for_each = var.kms_key_id != "" ? [1] : []
    content {
      key_vault_key_id = var.kms_key_id
    }
  }

  dynamic "authentication" {
    for_each = var.azure.aad_admin_object_id != "" ? [1] : []
    content {
      active_directory_auth_enabled = true
      password_auth_enabled         = true
      tenant_id                     = var.azure.aad_admin_tenant_id
    }
  }

  lifecycle {
    precondition {
      condition     = !(var.deletion_protection && var.kms_key_id == "")
      error_message = "Production (deletion_protection=true) requires a customer-managed Key Vault key (`kms_key_id`); the Microsoft-managed default key fails the threat_model §Tampering & key-isolation requirement."
    }
    ignore_changes = [
      zone, # Azure sometimes re-balances; don't fight it.
      administrator_password,
    ]
  }

  tags = merge(
    local.common_labels,
    try(var.azure.tags, {}),
  )
}

resource "azurerm_postgresql_flexible_server_configuration" "extensions" {
  count = local.is_azure ? 1 : 0

  name      = "azure.extensions"
  server_id = azurerm_postgresql_flexible_server.this[0].id
  value     = "VECTOR,PG_STAT_STATEMENTS"
}

resource "azurerm_postgresql_flexible_server_configuration" "log_min_duration" {
  count = local.is_azure ? 1 : 0

  name      = "log_min_duration_statement"
  server_id = azurerm_postgresql_flexible_server.this[0].id
  value     = "500"
}

resource "azurerm_postgresql_flexible_server_database" "app" {
  count     = local.is_azure ? 1 : 0
  name      = var.database_name
  server_id = azurerm_postgresql_flexible_server.this[0].id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "this" {
  count = local.is_azure && var.azure.aad_admin_object_id != "" ? 1 : 0

  server_name         = azurerm_postgresql_flexible_server.this[0].name
  resource_group_name = var.azure.resource_group_name
  tenant_id           = var.azure.aad_admin_tenant_id
  object_id           = var.azure.aad_admin_object_id
  principal_name      = var.azure.aad_admin_principal_name
  principal_type      = "Group"
}
