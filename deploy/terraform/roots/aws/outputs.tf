output "eks_cluster_name" {
  description = "EKS cluster name; feed to `aws eks update-kubeconfig --name <this>`."
  value       = aws_eks_cluster.this.name
}

output "eks_cluster_endpoint" {
  description = "EKS API server endpoint (private; reachable from the VPC only)."
  value       = aws_eks_cluster.this.endpoint
}

output "irsa_role_arn" {
  description = "IRSA role for the api-server pod. Wire into values-aws.yaml under `serviceAccount.api.annotations[\"eks.amazonaws.com/role-arn\"]`."
  value       = aws_iam_role.api_irsa.arn
}

output "database_secret_arn" {
  description = "Secrets Manager ARN for DATABASE_URL. Sync into K8s Secret `phi-audit-db` via External Secrets Operator and reference it in values-aws.yaml under `database.existingSecret`."
  value       = aws_secretsmanager_secret.database.arn
}

output "session_secret_arn" {
  description = "Secrets Manager ARN for SESSION_SECRET. Sync into K8s Secret and mount as env."
  value       = aws_secretsmanager_secret.session.arn
}

output "notarization_secret_arn" {
  description = "Secrets Manager ARN for NOTARIZATION_SECRET in the SEPARATE notarization account. The IRSA role has cross-account read; ESO can sync this with the cross-account secret store."
  value       = aws_secretsmanager_secret.notarization.arn
}

output "database_url" {
  description = "Pass-through from the M9.2 module. Sensitive."
  value       = module.db.database_url
  sensitive   = true
}
