locals {
  is_aws         = var.provider_name == "aws"
  is_gcp         = var.provider_name == "gcp"
  is_azure       = var.provider_name == "azure"
  is_self_hosted = var.provider_name == "self-hosted"

  # Per-provider pgvector-0.8-capable minimums (as of 2025-Q4).
  # - RDS PG 16.4+/17.1+ ship pgvector 0.8.
  # - Cloud SQL PG 17 ships pgvector 0.8 via `database_flags = ["cloudsql.enable_pg_cron"]` not required;
  #   `vector` extension is built-in on 16/17 images.
  # - Azure Flexible PG 16 supports pgvector 0.8 once `azure.extensions` allow-lists VECTOR.
  default_engine_version = {
    # Major-only on AWS so RDS auto-resolves to the latest available minor
    # (pinning "17.2" would break the day AWS deprecates that exact minor).
    aws   = "17"
    gcp   = "POSTGRES_17"
    azure = "16"
  }

  effective_engine_version = (
    var.engine_version != ""
    ? var.engine_version
    : lookup(local.default_engine_version, var.provider_name, "")
  )

  # Common tags / labels across providers — keep keys lowercase + snake_case
  # so they survive Azure's tag-key restrictions and the GCP label charset.
  common_labels = {
    app        = "phi-audit"
    tenant_id  = var.tenant_id
    managed_by = "terraform"
    module     = "deploy/terraform/modules/postgres"
  }
}

# Required-block guard: each cloud branch needs its block. Validate at plan
# time so the operator sees a single clear error instead of N null-deref
# explosions deeper in the resource graph.
resource "null_resource" "validate_aws_block" {
  count = local.is_aws ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.aws != null
      error_message = "provider_name='aws' requires the `aws` variable block."
    }
  }
}

resource "null_resource" "validate_gcp_block" {
  count = local.is_gcp ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.gcp != null
      error_message = "provider_name='gcp' requires the `gcp` variable block."
    }
  }
}

resource "null_resource" "validate_azure_block" {
  count = local.is_azure ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.azure != null
      error_message = "provider_name='azure' requires the `azure` variable block."
    }
  }
}

resource "null_resource" "validate_self_hosted_block" {
  count = local.is_self_hosted ? 1 : 0
  lifecycle {
    precondition {
      condition     = var.self_hosted != null
      error_message = "provider_name='self-hosted' requires the `self_hosted` variable block."
    }
  }
}

# Application password — generated once per state, surfaced via the
# provider-native secret store (Secrets Manager / Secret Manager / Key Vault).
# Self-hosted skips this because the operator hands us a connection string
# that already encodes their own credential rotation strategy.
resource "random_password" "app" {
  count            = local.is_self_hosted ? 0 : 1
  length           = 32
  special          = true
  override_special = "_-=+"
}
