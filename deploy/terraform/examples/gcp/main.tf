# Example: provision PHI-Audit Postgres on Cloud SQL.
#
# Prereqs (out of scope for this module):
#   - A VPC with Private Service Access reserved range    → `private_network`
#   - A customer-managed Cloud KMS key in this region     → `kms_key_id`
#   - Workload Identity bound to a GKE KSA                → set on Helm values
#
# The provisioned instance has no public IP; pods reach it via the Cloud SQL
# Auth Proxy sidecar (wired in the Helm chart's `cloudsqlproxy.enabled`).

terraform {
  required_version = ">= 1.6.0"
}

provider "google" {
  project = "example-project"
  region  = "us-central1"
}

module "phi_audit_db" {
  source = "../../modules/postgres"

  provider_name = "gcp"
  name          = "phi-audit-prod"
  tenant_id     = "default"

  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true
  kms_key_id            = "projects/example-project/locations/us-central1/keyRings/phi-audit/cryptoKeys/db"

  gcp = {
    project_id       = "example-project"
    region           = "us-central1"
    tier             = "db-custom-4-15360"
    private_network  = "projects/example-project/global/networks/phi-audit-vpc"
    enable_iam_authn = true
    require_ssl      = true
    labels = {
      environment = "prod"
      cost_center = "compliance"
    }
  }
}

output "database_url" {
  value     = module.phi_audit_db.database_url
  sensitive = true
}

output "instance_connection_name" {
  value = module.phi_audit_db.gcp_instance_connection_name
}
