provider "gitlab" {
  version = "~> 2.10"
  token   = var.gitlab_token
}

data "gitlab_group" "mygroup" {
  full_path = var.group_name
}

/*
data "gitlab_projects" "group_projects" {
  group_id          = data.gitlab_group.mygroup.id
  order_by          = "name"
  include_subgroups = true
  with_shared       = false
}

data "gitlab_projects" "java_projects" {
  with_programming_language = "java"
}
*/

resource "gitlab_group_variable" "sl_org_id_secret" {
  group     = data.gitlab_group.mygroup.id
  key       = "SHIFTLEFT_ORG_ID"
  value     = var.sl_org_id
  protected = true
  masked    = false
}

resource "gitlab_group_variable" "sl_access_token_secret" {
  group     = data.gitlab_group.mygroup.id
  key       = "SHIFTLEFT_ACCESS_TOKEN"
  value     = var.sl_access_token
  protected = true
  masked    = false
}

resource "gitlab_group_variable" "sl_api_token_secret" {
  group     = data.gitlab_group.mygroup.id
  key       = "SHIFTLEFT_API_TOKEN"
  value     = var.sl_api_token
  protected = true
  masked    = false
}
