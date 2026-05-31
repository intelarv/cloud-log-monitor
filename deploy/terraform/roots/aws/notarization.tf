# Application secrets.
#
# Three Secrets Manager entries:
#   - database         : populated from the M9.2 module's output (rotated by RDS)
#   - session          : SESSION_SECRET — encrypted with the in-account DB key
#   - notarization     : NOTARIZATION_SECRET — encrypted with the SEPARATE
#                        ACCOUNT KMS key passed via the aws.notarization
#                        provider alias. Threat_model §23.2:
#                        the notarization key MUST live in a different cloud
#                        account so a production-account compromise (root,
#                        IRSA pivot, KMS key policy edit) cannot forge
#                        ledger checkpoints retroactively.

# Database secret — same-account, holds the DATABASE_URL emitted by the module.
resource "aws_secretsmanager_secret" "database" {
  name        = "${var.name_prefix}-db"
  description = "Postgres DATABASE_URL for the api-server pod (IRSA-readable)."
  kms_key_id  = var.db_kms_key_id
  tags        = local.tags_all
}

resource "aws_secretsmanager_secret_version" "database" {
  secret_id = aws_secretsmanager_secret.database.id
  secret_string = jsonencode({
    "database-url" = module.db.database_url
  })
}

# Session secret — same-account.
resource "random_password" "session" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "session" {
  name        = "${var.name_prefix}-session"
  description = "SESSION_SECRET for the api-server pod."
  kms_key_id  = var.db_kms_key_id
  tags        = local.tags_all
}

resource "aws_secretsmanager_secret_version" "session" {
  secret_id = aws_secretsmanager_secret.session.id
  secret_string = jsonencode({
    "session-secret" = random_password.session.result
  })
}

# Notarization secret — CRITICAL: created via the aws.notarization provider
# alias so the secret itself lives in the separate notarization account
# (alongside its KMS key). The IRSA role above gets cross-account read via the
# resource policy below + the matching cross-account KMS key policy (operator
# wires the latter out-of-band; documented in README).
resource "random_password" "notarization" {
  length  = 64
  special = false
}

resource "aws_secretsmanager_secret" "notarization" {
  provider    = aws.notarization
  name        = "${var.name_prefix}-notarization"
  description = "NOTARIZATION_SECRET — lives in a separate AWS account (threat_model §23.2). DO NOT copy or cache in the production account."
  kms_key_id  = var.notarization_kms_key_id

  # Cross-account read grant for the api IRSA role.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowProductionApiRead"
      Effect    = "Allow"
      Principal = { AWS = aws_iam_role.api_irsa.arn }
      Action    = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
      Resource  = "*"
    }]
  })

  tags = local.tags_all
}

resource "aws_secretsmanager_secret_version" "notarization" {
  provider  = aws.notarization
  secret_id = aws_secretsmanager_secret.notarization.id
  secret_string = jsonencode({
    "notarization-secret" = random_password.notarization.result
    # active_key_id rotates here when the operator rolls a new secret; the
    # app's NOTARIZATION_RETIRED_KEYS env carries the prior ones.
    "active-key-id" = "v1"
  })
}
