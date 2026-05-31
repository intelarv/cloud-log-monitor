# PHI-Audit GCP root.
#
# What this provisions:
#   - GKE Autopilot cluster (private endpoint + Workload Identity enabled)
#   - Google Service Account for the api-server + Workload Identity binding
#     to the K8s ServiceAccount, with Vertex AI + Cloud SQL Client +
#     Secret Manager + Cloud Logging Viewer
#   - Postgres via the M9.2 modules/postgres module (Cloud SQL with pgvector)
#   - Secret Manager entries for SESSION_SECRET and (CMEK-encrypted from a
#     SEPARATE project) NOTARIZATION_SECRET
#
# What this does NOT provision:
#   - VPC + subnets + secondary ranges (BYO)
#   - DNS + managed certs
#   - The KMS keys themselves
#   - Notarization-project resources beyond the secret itself (KMS key,
#     project itself, key ring — out of scope; documented in README)

locals {
  labels_all = merge(var.labels, {
    "phi-audit_tenant" = var.tenant_id
    "phi-audit_root"   = "gcp"
  })
}

# --- GKE Autopilot ---------------------------------------------------------

resource "google_container_cluster" "this" {
  name                = "${var.name_prefix}-gke"
  location            = var.region
  project             = var.project_id
  enable_autopilot    = true
  deletion_protection = true

  network    = var.network
  subnetwork = var.subnetwork

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_secondary_range_name
    services_secondary_range_name = var.services_secondary_range_name
  }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block
  }

  # Workload Identity is auto-enabled on Autopilot; explicit for clarity.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  resource_labels = local.labels_all
}

# --- GSA + Workload Identity binding for the api pod -----------------------

resource "google_service_account" "api" {
  project      = var.project_id
  account_id   = "${var.name_prefix}-api"
  display_name = "PHI-Audit API"
}

# Bind the KSA → GSA via Workload Identity.
resource "google_service_account_iam_member" "api_wi" {
  service_account_id = google_service_account.api.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account}]"
}

# Project-level grants for the GSA. Tighten in production (per-resource
# bindings on Cloud SQL instance + per-secret IAM on Secret Manager).
resource "google_project_iam_member" "api_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_cloudsql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_secrets" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.api.email}"
}

resource "google_project_iam_member" "api_logs_view" {
  project = var.project_id
  role    = "roles/logging.viewer"
  member  = "serviceAccount:${google_service_account.api.email}"
}
