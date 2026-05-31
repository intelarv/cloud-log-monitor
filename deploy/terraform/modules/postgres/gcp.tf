# GCP branch — Cloud SQL for PostgreSQL with pgvector.
#
# Notes:
# - `database_flags { name = "cloudsql.iam_authentication"; value = "on" }`
#   lets pods on a GKE Workload-Identity-bound KSA exchange ADC for a DB
#   token; the static password we generate is the fallback for the bootstrap
#   migration job.
# - pgvector is preinstalled on Cloud SQL PG 16/17; the app's first-boot
#   `CREATE EXTENSION vector;` in `lib/db/setup-sql.ts` is the activation step.
# - Cloud SQL Auth Proxy is the recommended connection path (sidecar in the
#   pod). The Helm chart already wires the sidecar when `cloudsqlproxy.enabled
#   = true`.

resource "google_sql_database_instance" "this" {
  count = local.is_gcp ? 1 : 0

  project          = var.gcp.project_id
  region           = var.gcp.region
  name             = var.name
  database_version = local.effective_engine_version

  deletion_protection = var.deletion_protection

  settings {
    tier              = var.gcp.tier
    availability_type = var.high_availability ? "REGIONAL" : "ZONAL"
    disk_type         = "PD_SSD"
    disk_size         = var.storage_gb
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      start_time                     = "03:00"
      backup_retention_settings {
        retained_backups = var.backup_retention_days
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.gcp.private_network
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = var.gcp.require_ssl ? "ENCRYPTED_ONLY" : "ALLOW_UNENCRYPTED_AND_ENCRYPTED"

      # `allocated_ip_range` is a string attribute on `ip_configuration`,
      # NOT a nested block — an earlier draft used a dynamic block which
      # generated empty `allocated_ip_range {}` and silently no-op'd.
      allocated_ip_range = var.gcp.allocated_ip_range != "" ? var.gcp.allocated_ip_range : null
    }

    database_flags {
      name  = "cloudsql.iam_authentication"
      value = var.gcp.enable_iam_authn ? "on" : "off"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "500"
    }

    database_flags {
      name  = "log_statement"
      value = "ddl"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = false # PHI hygiene: don't log client IPs alongside queries.
    }

    maintenance_window {
      day          = 1
      hour         = 4
      update_track = "stable"
    }

    user_labels = merge(
      local.common_labels,
      try(var.gcp.labels, {}),
    )
  }

  encryption_key_name = var.kms_key_id != "" ? var.kms_key_id : null

  lifecycle {
    precondition {
      condition     = !(var.deletion_protection && var.kms_key_id == "")
      error_message = "Production (deletion_protection=true) requires a customer-managed Cloud KMS key (`kms_key_id`); the Google-managed default key fails the threat_model §Tampering & key-isolation requirement."
    }
  }
}

resource "google_sql_database" "app" {
  count    = local.is_gcp ? 1 : 0
  project  = var.gcp.project_id
  instance = google_sql_database_instance.this[0].name
  name     = var.database_name
  # Cloud SQL default; explicit for clarity.
  charset   = "UTF8"
  collation = "en_US.UTF8"
}

resource "google_sql_user" "app" {
  count    = local.is_gcp ? 1 : 0
  project  = var.gcp.project_id
  instance = google_sql_database_instance.this[0].name
  name     = var.app_username
  password = random_password.app[0].result
}

resource "google_secret_manager_secret" "db" {
  count     = local.is_gcp ? 1 : 0
  project   = var.gcp.project_id
  secret_id = "${var.name}-db-credentials"

  replication {
    auto {
      dynamic "customer_managed_encryption" {
        for_each = var.kms_key_id != "" ? [1] : []
        content {
          kms_key_name = var.kms_key_id
        }
      }
    }
  }

  labels = merge(
    local.common_labels,
    try(var.gcp.labels, {}),
  )
}

resource "google_secret_manager_secret_version" "db" {
  count  = local.is_gcp ? 1 : 0
  secret = google_secret_manager_secret.db[0].id
  secret_data = jsonencode({
    host                     = google_sql_database_instance.this[0].private_ip_address
    port                     = 5432
    database                 = var.database_name
    username                 = var.app_username
    password                 = random_password.app[0].result
    instance_connection_name = google_sql_database_instance.this[0].connection_name
    # Cloud SQL Auth Proxy sidecar listens on 127.0.0.1:5432 inside the pod;
    # the DATABASE_URL the app sees never includes the cloud-private IP.
    DATABASE_URL = format(
      "postgresql://%s:%s@127.0.0.1:5432/%s?sslmode=disable",
      var.app_username,
      random_password.app[0].result,
      var.database_name,
    )
  })
}
