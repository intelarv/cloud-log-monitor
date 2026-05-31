output "aks_cluster_name" {
  description = "AKS cluster name; feed to `az aks get-credentials --resource-group <rg> --name <this>`."
  value       = azurerm_kubernetes_cluster.this.name
}

output "aks_oidc_issuer_url" {
  description = "AKS OIDC issuer URL; needed for any additional Federated Identity Credentials you create out-of-band."
  value       = azurerm_kubernetes_cluster.this.oidc_issuer_url
}

output "api_managed_identity_client_id" {
  description = "Client id of the user-assigned MI for the api-server pod. Wire into values-azure.yaml under `serviceAccount.api.annotations[\"azure.workload.identity/client-id\"]`."
  value       = azurerm_user_assigned_identity.api.client_id
}

output "api_managed_identity_principal_id" {
  description = "Principal id of the same MI; used by anyone adding additional role assignments out-of-band."
  value       = azurerm_user_assigned_identity.api.principal_id
}

output "session_secret_name" {
  description = "Key Vault secret name for SESSION_SECRET. The Helm overlay's Secrets Store CSI Driver SecretProviderClass references this."
  value       = azurerm_key_vault_secret.session.name
}

output "database_url_secret_name" {
  description = "Key Vault secret name for DATABASE_URL."
  value       = azurerm_key_vault_secret.database_url.name
}

output "notarization_secret_name" {
  description = "Key Vault secret name (in the SEPARATE notarization vault) for NOTARIZATION_SECRET."
  value       = azurerm_key_vault_secret.notarization.name
}

output "database_url" {
  description = "Pass-through from the M9.2 module. Sensitive."
  value       = module.db.database_url
  sensitive   = true
}
