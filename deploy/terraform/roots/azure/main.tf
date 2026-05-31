# PHI-Audit Azure root.
#
# What this provisions:
#   - AKS cluster (OIDC issuer + Workload Identity enabled)
#   - User-Assigned Managed Identity for the api-server pod + Federated
#     Identity Credential binding it to the `phi-audit-api` KSA
#   - Postgres via the M9.2 modules/postgres module (Azure Flexible Server)
#   - Key Vault role assignments for SESSION_SECRET, DATABASE_URL
#   - NOTARIZATION_SECRET written to the SEPARATE notarization Key Vault
#     via the azurerm.notarization aliased provider
#
# What this does NOT provision:
#   - VNet + subnets (BYO; subnets passed in)
#   - DNS + AGIC + Application Gateway TLS certs
#   - Azure OpenAI deployment (managed out-of-band; values-azure.yaml carries
#     the deployment name + endpoint)
#   - The notarization Key Vault itself

locals {
  tags_all = merge(var.tags, {
    "phi-audit:tenant" = var.tenant_id
    "phi-audit:root"   = "azure"
  })
}

# --- AKS -------------------------------------------------------------------

resource "azurerm_kubernetes_cluster" "this" {
  name                = "${var.name_prefix}-aks"
  resource_group_name = var.resource_group_name
  location            = var.location
  dns_prefix          = var.name_prefix
  kubernetes_version  = var.kubernetes_version

  # Workload Identity requires both flags.
  oidc_issuer_enabled       = true
  workload_identity_enabled = true

  default_node_pool {
    name           = "system"
    node_count     = var.node_count
    vm_size        = var.node_vm_size
    vnet_subnet_id = var.subnet_id
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags_all
}

# --- User-Assigned MI for the api pod + WI federation ----------------------

resource "azurerm_user_assigned_identity" "api" {
  name                = "${var.name_prefix}-api"
  resource_group_name = var.resource_group_name
  location            = var.location
  tags                = local.tags_all
}

resource "azurerm_federated_identity_credential" "api" {
  name                = "${var.name_prefix}-api-fed"
  resource_group_name = var.resource_group_name
  parent_id           = azurerm_user_assigned_identity.api.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = azurerm_kubernetes_cluster.this.oidc_issuer_url
  subject             = "system:serviceaccount:${var.k8s_namespace}:${var.k8s_service_account}"
}

# --- Key Vault role assignments (application vault) ------------------------

data "azurerm_key_vault" "app" {
  name                = var.key_vault_name
  resource_group_name = var.resource_group_name
}

resource "azurerm_role_assignment" "api_kv_secret_user" {
  scope                = data.azurerm_key_vault.app.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}

# Cross-vault grant for the notarization vault.
resource "azurerm_role_assignment" "api_kv_notarization_secret_user" {
  provider             = azurerm.notarization
  scope                = var.notarization_key_vault_id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.api.principal_id
}
