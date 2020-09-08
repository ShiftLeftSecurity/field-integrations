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

module "github" {
  source          = "../../modules/github"
  token           = var.github_token
  poc_repo        = module.shiftleft.poc_repo
  sl_branch       = module.shiftleft.sl_branch
  sl_org_id       = module.shiftleft.sl_org_id
  sl_access_token = module.shiftleft.sl_access_token
  sl_api_token    = module.shiftleft.sl_api_token
}
