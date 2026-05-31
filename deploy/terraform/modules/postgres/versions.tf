terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 5.40.0"
      configuration_aliases = []
    }
    google = {
      source                = "hashicorp/google"
      version               = ">= 5.30.0"
      configuration_aliases = []
    }
    azurerm = {
      source                = "hashicorp/azurerm"
      version               = ">= 4.0.0"
      configuration_aliases = []
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
  }
}
