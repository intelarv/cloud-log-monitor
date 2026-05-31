# Postgres via the M9.2 provider-abstracted module.

module "db" {
  source = "../../modules/postgres"

  provider_name         = "aws"
  name                  = "${var.name_prefix}-db"
  tenant_id             = var.tenant_id
  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true
  kms_key_id            = var.db_kms_key_id

  aws = {
    region                              = var.region
    instance_class                      = "db.m6g.large"
    vpc_security_group_ids              = var.rds_security_group_ids
    db_subnet_group_name                = var.db_subnet_group_name
    iam_database_authentication_enabled = true
    performance_insights_enabled        = true
    tags                                = local.tags_all
  }
}
