module "db" {
  source = "../../modules/postgres"

  provider_name         = "gcp"
  name                  = "${var.name_prefix}-db"
  tenant_id             = var.tenant_id
  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true

  gcp = {
    project_id       = var.project_id
    region           = var.region
    tier             = "db-custom-2-7680"
    private_network  = var.network
    enable_iam_authn = true
    require_ssl      = true
    labels           = local.labels_all
  }
}
