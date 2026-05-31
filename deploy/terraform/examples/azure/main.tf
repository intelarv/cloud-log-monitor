# Example: provision PHI-Audit Postgres on Azure Database for PostgreSQL
# Flexible Server.
#
# Prereqs (out of scope for this module):
#   - A delegated subnet (Microsoft.DBforPostgreSQL/flexibleServers)
#     → `delegated_subnet_id`
#   - A private DNS zone (`*.postgres.database.azure.com`)
#     → `private_dns_zone_id`
#   - A customer-managed Key Vault key                    → `kms_key_id`
#   - An AAD group whose members are DB admins            → `aad_admin_object_id`

terraform {
  required_version = ">= 1.6.0"
}

provider "azurerm" {
  features {}
  subscription_id = "00000000-0000-0000-0000-000000000000"
}

module "phi_audit_db" {
  source = "../../modules/postgres"

  provider_name = "azure"
  name          = "phi-audit-prod"
  tenant_id     = "default"

  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true
  kms_key_id            = "https://phi-audit.vault.azure.net/keys/db/EXAMPLEKEYVERSION"

  azure = {
    resource_group_name      = "phi-audit-prod-rg"
    location                 = "eastus2"
    sku_name                 = "GP_Standard_D4ds_v5"
    delegated_subnet_id      = "/subscriptions/.../subnets/postgres-delegated"
    private_dns_zone_id      = "/subscriptions/.../privateDnsZones/privatelink.postgres.database.azure.com"
    aad_admin_object_id      = "11111111-2222-3333-4444-555555555555"
    aad_admin_principal_name = "phi-audit-db-admins"
    aad_admin_tenant_id      = "00000000-0000-0000-0000-000000000000"
    tags = {
      environment = "prod"
      cost_center = "compliance"
    }
  }
}

output "database_url" {
  value     = module.phi_audit_db.database_url
  sensitive = true
}

output "fqdn" {
  value = module.phi_audit_db.host
}
