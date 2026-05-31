# Application secrets in Secret Manager.
#
# Notarization secret lives in the SEPARATE notarization project, created via
# the google.notarization provider alias. The api GSA needs cross-project
# secretAccessor on that secret; we grant it here so the apply produces a
# working end-to-end binding. The KMS key itself is pre-created in the
# notarization project by the platform team (see README).

resource "random_password" "session" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "session" {
  project   = var.project_id
  secret_id = "${var.name_prefix}-session"
  replication {
    auto {}
  }
  labels = local.labels_all
}

resource "google_secret_manager_secret_version" "session" {
  secret      = google_secret_manager_secret.session.id
  secret_data = random_password.session.result
}

# Database URL (from the M9.2 module).
resource "google_secret_manager_secret" "database" {
  project   = var.project_id
  secret_id = "${var.name_prefix}-db"
  replication {
    auto {}
  }
  labels = local.labels_all
}

resource "google_secret_manager_secret_version" "database" {
  secret      = google_secret_manager_secret.database.id
  secret_data = module.db.database_url
}

# Notarization secret in the SEPARATE notarization project.
resource "random_password" "notarization" {
  length  = 64
  special = false
}

resource "google_secret_manager_secret" "notarization" {
  provider  = google.notarization
  secret_id = "${var.name_prefix}-notarization"

  # CMEK with the notarization-project KMS key. user-managed replication is
  # required to specify CMEK per-replica.
  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = var.notarization_kms_key_id
        }
      }
    }
  }

  labels = local.labels_all
}

resource "google_secret_manager_secret_version" "notarization" {
  provider    = google.notarization
  secret      = google_secret_manager_secret.notarization.id
  secret_data = random_password.notarization.result
}

# Cross-project grant: api GSA can read the notarization secret.
resource "google_secret_manager_secret_iam_member" "api_notarization" {
  provider  = google.notarization
  secret_id = google_secret_manager_secret.notarization.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.api.email}"
}
