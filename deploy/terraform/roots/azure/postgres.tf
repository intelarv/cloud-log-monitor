module "db" {
  source = "../../modules/postgres"

  provider_name         = "azure"
  name                  = "${var.name_prefix}-db"
  tenant_id             = var.tenant_id
  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true

  azure = {
    resource_group_name      = var.resource_group_name
    location                 = var.location
    sku_name                 = "GP_Standard_D2ds_v5"
    delegated_subnet_id      = var.pg_delegated_subnet_id
    private_dns_zone_id      = var.pg_private_dns_zone_id
    aad_admin_object_id      = var.aad_admin_object_id
    aad_admin_principal_name = var.aad_admin_principal_name
    aad_admin_tenant_id      = var.azure_aad_tenant_id
    tags                     = local.tags_all
  }
}
