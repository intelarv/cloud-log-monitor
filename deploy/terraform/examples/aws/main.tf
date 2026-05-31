# Example: provision PHI-Audit Postgres on AWS RDS.
#
# Prereqs (out of scope for this module — those live in M9.3's per-cloud
# Terraform roots):
#   - A VPC + private subnets in two AZs                  → `db_subnet_group_name`
#   - A security group permitting :5432 from EKS pods    → `vpc_security_group_ids`
#   - A customer-managed KMS key with rotation enabled   → `kms_key_id`
#
# Usage:
#   tofu init && tofu plan -var-file=terraform.tfvars

terraform {
  required_version = ">= 1.6.0"
}

provider "aws" {
  region = "us-east-1"
}

module "phi_audit_db" {
  source = "../../modules/postgres"

  provider_name = "aws"
  name          = "phi-audit-prod"
  tenant_id     = "default"

  storage_gb            = 200
  backup_retention_days = 35
  high_availability     = true
  deletion_protection   = true
  kms_key_id            = "arn:aws:kms:us-east-1:111122223333:key/EXAMPLE-KMS-KEY-ID"

  aws = {
    region                              = "us-east-1"
    instance_class                      = "db.m6g.large"
    vpc_security_group_ids              = ["sg-0123456789abcdef0"]
    db_subnet_group_name                = "phi-audit-prod"
    iam_database_authentication_enabled = true
    performance_insights_enabled        = true
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

output "secret_ref" {
  value = module.phi_audit_db.secret_ref
}
