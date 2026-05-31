# Application secrets.
#
# SESSION_SECRET + DATABASE_URL live in the application Key Vault (same
# subscription as AKS). NOTARIZATION_SECRET lives in a SEPARATE Key Vault
# in a different subscription (ideally a different Azure AD tenant) per
# threat_model §23.2 — co-locating it defeats the second-half tamper
# evidence claim.

resource "random_password" "session" {
  length  = 64
  special = false
}

resource "azurerm_key_vault_secret" "session" {
  name         = "${var.name_prefix}-session-secret"
  value        = random_password.session.result
  key_vault_id = data.azurerm_key_vault.app.id
  tags         = local.tags_all
}

resource "azurerm_key_vault_secret" "database_url" {
  name         = "${var.name_prefix}-db-url"
  value        = module.db.database_url
  key_vault_id = data.azurerm_key_vault.app.id
  tags         = local.tags_all
}

# Notarization secret in the SEPARATE vault.
resource "random_password" "notarization" {
  length  = 64
  special = false
}

resource "azurerm_key_vault_secret" "notarization" {
  provider     = azurerm.notarization
  name         = "${var.name_prefix}-notarization-secret"
  value        = random_password.notarization.result
  key_vault_id = var.notarization_key_vault_id
  tags         = local.tags_all
}
