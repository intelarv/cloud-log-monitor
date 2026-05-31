# AWS branch — RDS for PostgreSQL with pgvector.
#
# Notes:
# - `shared_preload_libraries = vector` is set via a custom parameter group;
#   the operator must still `CREATE EXTENSION vector;` against the DB (the
#   app does this on first boot via `lib/db/setup-sql.ts`).
# - `iam_database_authentication_enabled = true` lets pods on the IRSA role
#   exchange a token for a short-lived DB password; the static password we
#   generate is the fallback for the bootstrap migration job.
# - CMEK (`kms_key_id`) is required by HIPAA-grade defaults; pass an empty
#   string to fall back to the default AWS-managed key (NOT recommended).

resource "aws_db_parameter_group" "this" {
  count = local.is_aws ? 1 : 0

  name        = "${var.name}-pg17-vector"
  family      = "postgres17"
  description = "PHI-Audit pgvector + force-SSL"

  parameter {
    name         = "shared_preload_libraries"
    value        = "pg_stat_statements,vector"
    apply_method = "pending-reboot"
  }

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }

  parameter {
    name  = "log_statement"
    value = "ddl"
  }

  parameter {
    name  = "log_min_duration_statement"
    value = "500"
  }

  tags = merge(
    local.common_labels,
    try(var.aws.tags, {}),
  )
}

resource "aws_db_instance" "this" {
  count = local.is_aws ? 1 : 0

  identifier     = var.name
  engine         = "postgres"
  engine_version = local.effective_engine_version
  instance_class = var.aws.instance_class

  allocated_storage     = var.storage_gb
  max_allocated_storage = var.storage_gb * 5
  storage_type          = "gp3"
  storage_encrypted     = true
  kms_key_id            = var.kms_key_id != "" ? var.kms_key_id : null

  db_name  = var.database_name
  username = var.app_username
  password = random_password.app[0].result
  port     = 5432

  vpc_security_group_ids = var.aws.vpc_security_group_ids
  db_subnet_group_name   = var.aws.db_subnet_group_name
  publicly_accessible    = false

  multi_az                = var.high_availability
  backup_retention_period = var.backup_retention_days
  backup_window           = "03:00-04:00"
  maintenance_window      = "Mon:04:30-Mon:05:30"
  copy_tags_to_snapshot   = true

  iam_database_authentication_enabled = var.aws.iam_database_authentication_enabled

  parameter_group_name = aws_db_parameter_group.this[0].name

  performance_insights_enabled    = var.aws.performance_insights_enabled
  performance_insights_kms_key_id = var.aws.performance_insights_enabled && var.kms_key_id != "" ? var.kms_key_id : null
  monitoring_interval             = var.aws.monitoring_role_arn != "" ? 30 : 0
  monitoring_role_arn             = var.aws.monitoring_role_arn != "" ? var.aws.monitoring_role_arn : null

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  deletion_protection       = var.deletion_protection
  delete_automated_backups  = false
  skip_final_snapshot       = !var.deletion_protection
  final_snapshot_identifier = !var.deletion_protection ? null : "${var.name}-final-${formatdate("YYYYMMDDhhmmss", timestamp())}"

  apply_immediately = false

  lifecycle {
    ignore_changes = [
      final_snapshot_identifier,
      password, # Rotated out-of-band via Secrets Manager rotation lambda.
    ]
    precondition {
      condition     = !contains(["", "alias/aws/rds"], var.kms_key_id) || !var.deletion_protection
      error_message = "Production (deletion_protection=true) requires a customer-managed KMS key; the AWS-managed default key cannot be rotated independently of AWS, which fails the threat_model §Tampering & key-isolation requirement."
    }
  }

  tags = merge(
    local.common_labels,
    try(var.aws.tags, {}),
  )
}

# Secret stored alongside the instance; the Helm chart's `existingSecret`
# reference points at this ARN via the External Secrets Operator.
resource "aws_secretsmanager_secret" "db" {
  count = local.is_aws ? 1 : 0

  name        = "${var.name}-db-credentials"
  description = "PHI-Audit DB credentials (provisioned by deploy/terraform/modules/postgres)"
  kms_key_id  = var.kms_key_id != "" ? var.kms_key_id : null
  tags = merge(
    local.common_labels,
    try(var.aws.tags, {}),
  )
}

resource "aws_secretsmanager_secret_version" "db" {
  count = local.is_aws ? 1 : 0

  secret_id = aws_secretsmanager_secret.db[0].id
  secret_string = jsonencode({
    host     = aws_db_instance.this[0].address
    port     = aws_db_instance.this[0].port
    database = var.database_name
    username = var.app_username
    password = random_password.app[0].result
    DATABASE_URL = format(
      "postgresql://%s:%s@%s:%d/%s?sslmode=require",
      var.app_username,
      random_password.app[0].result,
      aws_db_instance.this[0].address,
      aws_db_instance.this[0].port,
      var.database_name,
    )
  })
}
