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

module "bitbucket" {
  source          = "../../modules/bitbucket"
  username        = var.bitbucket_username
  password        = var.bitbucket_app_password
  owner           = var.bitbucket_owner
  sl_org_id       = module.shiftleft.sl_org_id
  sl_access_token = module.shiftleft.sl_access_token
  sl_api_token    = module.shiftleft.sl_api_token
  repos           = var.repos
}
