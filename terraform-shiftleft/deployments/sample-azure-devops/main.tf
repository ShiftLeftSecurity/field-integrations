terraform {
  required_version = ">= 0.12"
}

// Some common variables can be stored and referred from this module
module "shiftleft" {
  source          = "../../modules/shiftleft"
  sl_org_id       = var.sl_org_id
  sl_access_token = var.sl_access_token
  sl_api_token    = var.sl_api_token
}

module "azure" {
  source                = "../../modules/azure-devops"
  sl_org_id             = module.shiftleft.sl_org_id
  sl_access_token       = module.shiftleft.sl_access_token
  sl_api_token          = module.shiftleft.sl_api_token
  org_service_url       = var.org_service_url
  personal_access_token = var.personal_access_token
  project_name          = var.project_name
}
