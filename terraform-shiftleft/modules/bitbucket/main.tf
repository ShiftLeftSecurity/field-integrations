provider "bitbucket" {
  version  = "~> 1.2"
  username = var.username
  password = var.password
}

resource "bitbucket_repository_variable" "sl_org_id_secret" {
  for_each   = toset(var.repos)
  key        = "SHIFTLEFT_ORG_ID"
  value      = var.sl_org_id
  repository = each.key
  secured    = true
}

resource "bitbucket_repository_variable" "sl_access_token_secret" {
  for_each   = toset(var.repos)
  key        = "SHIFTLEFT_ACCESS_TOKEN"
  value      = var.sl_access_token
  repository = each.key
  secured    = true
}

resource "bitbucket_repository_variable" "sl_api_token_secret" {
  for_each   = toset(var.repos)
  key        = "SHIFTLEFT_API_TOKEN"
  value      = var.sl_api_token
  repository = each.key
  secured    = true
}
