# Example: pass through an operator-managed Postgres (CNPG, Crunchy, an
# existing RDS not managed by this module, the Replit dev DB, etc.). The
# module provisions nothing in this branch — the outputs simply echo the
# operator-supplied values so downstream Helm wiring stays uniform across
# all four branches.

terraform {
  required_version = ">= 1.6.0"
}

variable "operator_database_url" {
  description = "DATABASE_URL the operator has already provisioned and stored in their secret store."
  type        = string
  sensitive   = true
}

module "phi_audit_db" {
  source = "../../modules/postgres"

  provider_name = "self-hosted"
  name          = "phi-audit-dev"
  tenant_id     = "default"

  self_hosted = {
    connection_string = var.operator_database_url
    host              = "phi-audit-cnpg-rw.phi-audit.svc.cluster.local"
    port              = 5432
    database          = "phi_audit"
    username          = "phi_audit_app"
    secret_ref        = "vault://secret/phi-audit/db"
  }
}

output "database_url" {
  value     = module.phi_audit_db.database_url
  sensitive = true
}

output "secret_ref" {
  value = module.phi_audit_db.secret_ref
}
