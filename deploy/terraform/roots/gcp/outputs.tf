output "gke_cluster_name" {
  description = "GKE cluster name; feed to `gcloud container clusters get-credentials <this>`."
  value       = google_container_cluster.this.name
}

output "gke_cluster_endpoint" {
  description = "GKE API server endpoint (private)."
  value       = google_container_cluster.this.endpoint
  sensitive   = true
}

output "api_service_account_email" {
  description = "Google Service Account for the api-server pod. Wire into values-gcp.yaml under `serviceAccount.api.annotations[\"iam.gke.io/gcp-service-account\"]`."
  value       = google_service_account.api.email
}

output "database_secret_name" {
  description = "Secret Manager resource name for DATABASE_URL. Sync into K8s Secret `phi-audit-db` via External Secrets Operator."
  value       = google_secret_manager_secret.database.id
}

output "session_secret_name" {
  description = "Secret Manager resource name for SESSION_SECRET."
  value       = google_secret_manager_secret.session.id
}

output "notarization_secret_name" {
  description = "Secret Manager resource name for NOTARIZATION_SECRET in the SEPARATE notarization project."
  value       = google_secret_manager_secret.notarization.id
}

output "database_url" {
  description = "Pass-through from the M9.2 module. Sensitive."
  value       = module.db.database_url
  sensitive   = true
}

output "gcp_instance_connection_name" {
  description = "Cloud SQL Auth Proxy connection string `project:region:instance`. Wire into the Helm overlay's sidecar args: `--auto-iam-authn`, `<this>`, `--port=5432`."
  value       = module.db.gcp_instance_connection_name
}
