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

module "gitlab" {
  source          = "../../modules/gitlab"
  gitlab_token    = var.gitlab_token
  group_name      = var.group_name
  sl_org_id       = module.shiftleft.sl_org_id
  sl_access_token = module.shiftleft.sl_access_token
  sl_api_token    = module.shiftleft.sl_api_token
}
