variable "name_prefix" {
  description = "Logical name prefix for every resource created by this root."
  type        = string
  default     = "phi-audit"
}

variable "region" {
  description = "Primary AWS region for EKS + RDS + Secrets Manager. Bedrock and Titan embedder default to the same region."
  type        = string
}

variable "tenant_id" {
  description = "Tenant id propagated as a tag across all resources for cost attribution and RLS scoping at the app layer."
  type        = string
}

variable "vpc_id" {
  description = "Existing VPC the cluster + DB live in. Out of scope for this root — bring your own networking module (terraform-aws-modules/vpc/aws is the usual pick)."
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet ids (>=2 AZs) for EKS node groups + the RDS subnet group. Public subnets are an anti-pattern here — the cluster + DB MUST stay private."
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Need >=2 subnets across distinct AZs for EKS + RDS HA."
  }
}

variable "eks_version" {
  description = "EKS control-plane version. Helm chart pins kubeVersion >=1.27; default tracks the latest LTS-ish."
  type        = string
  default     = "1.30"
}

variable "node_instance_types" {
  description = "Managed node group instance types. Default sized for the api-server + dashboard pods, not for the LLM workload (Bedrock is fully managed)."
  type        = list(string)
  default     = ["m6i.large"]
}

variable "node_desired_size" {
  description = "Initial node count for the managed node group."
  type        = number
  default     = 2
}

variable "db_kms_key_id" {
  description = "Customer-managed KMS key in THIS account for RDS storage encryption. Created by your platform team; not collapsed with the notarization key (different account, different blast radius)."
  type        = string
}

variable "notarization_kms_key_id" {
  description = "Customer-managed KMS key in the SEPARATE notarization account (passed via the aws.notarization provider alias) used to encrypt the NOTARIZATION_SECRET in Secrets Manager. Threat_model §23.2 requires this to be in a different AWS account than the production workload so a production-account compromise cannot forge ledger checkpoints."
  type        = string
}

variable "rds_security_group_ids" {
  description = "Security groups attached to the RDS instance. The cluster's node security group MUST be allowed in via :5432; that rule belongs in the SG definition (out of scope here)."
  type        = list(string)
}

variable "db_subnet_group_name" {
  description = "Pre-existing DB subnet group covering the private subnets above. Conventionally `<name_prefix>-db`."
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

variable "tags" {
  description = "Tags applied to every resource. `tenant_id` is added automatically."
  type        = map(string)
  default     = {}
}
