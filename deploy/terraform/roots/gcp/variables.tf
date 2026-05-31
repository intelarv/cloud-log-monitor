variable "name_prefix" {
  description = "Logical name prefix for every resource created by this root."
  type        = string
  default     = "phi-audit"
}

variable "project_id" {
  description = "GCP project id for GKE + Cloud SQL + Secret Manager. The notarization KMS key lives in a SEPARATE project (see `notarization_kms_key_id`)."
  type        = string
}

variable "region" {
  description = "Primary GCP region. Vertex AI endpoint defaults here; pgvector embedder Titan-equivalent (text-embedding-005) is regional too."
  type        = string
}

variable "tenant_id" {
  description = "Tenant id propagated as a label across all resources for cost attribution + RLS scoping at the app layer."
  type        = string
}

variable "network" {
  description = "Full self-link of the VPC the cluster + Cloud SQL private IP live in. BYO networking — out of scope for this root."
  type        = string
}

variable "subnetwork" {
  description = "Subnet for GKE nodes."
  type        = string
}

variable "pods_secondary_range_name" {
  description = "GKE-style secondary range name for pod IPs on the subnetwork above."
  type        = string
}

variable "services_secondary_range_name" {
  description = "GKE-style secondary range name for service IPs."
  type        = string
}

variable "master_ipv4_cidr_block" {
  description = "Private control-plane CIDR for GKE. /28."
  type        = string
}

variable "notarization_kms_key_id" {
  description = "Cloud KMS key resource id in the SEPARATE notarization project — used to CMEK-encrypt the notarization Secret Manager entry. Threat_model §23.2 requires this to be in a different GCP project than the workload so a workload-project compromise cannot forge ledger checkpoints. Provided via the `google.notarization` aliased provider."
  type        = string
}

variable "k8s_namespace" {
  description = "Kubernetes namespace the api-server pod runs in. Must match the Helm release namespace."
  type        = string
  default     = "phi-audit"
}

variable "k8s_service_account" {
  description = "Kubernetes ServiceAccount name for the api-server pod. Must match `serviceAccount.api.name` in the Helm release."
  type        = string
  default     = "phi-audit-api"
}

variable "labels" {
  description = "Labels applied to every resource. `tenant_id` is added automatically."
  type        = map(string)
  default     = {}
}
