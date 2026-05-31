terraform {
  required_version = ">= 1.6.0"

  required_providers {
    azurerm = {
      source                = "hashicorp/azurerm"
      version               = "~> 4.10"
      configuration_aliases = [azurerm.notarization]
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}
