provider "github" {
  version      = "~> 2.8"
  organization = var.organization
  token        = var.token
}

// All JavaScript repos. Duplicate the js_ data and resources for other languages
// NOTE: It might be possible to code with one map and a complex logic to support all languages
data "github_repositories" "js_repos" {
  query = "org:${var.organization} language:JavaScript"
}

data "github_repositories" "csharp_repos" {
  query = "org:${var.organization} language:c#"
}

data "github_repositories" "python_repos" {
  query = "org:${var.organization} language:python"
}
// ------------------------------------------------------------

// A single poc repo
data "github_repository" "poc" {
  full_name = var.poc_repo
}

// Create secrets in a single poc repo
resource "github_actions_secret" "sl_org_id_secret" {
  repository      = data.github_repository.poc.name
  secret_name     = "SHIFTLEFT_ORG_ID"
  plaintext_value = var.sl_org_id
}

resource "github_actions_secret" "sl_access_token_secret" {
  repository      = data.github_repository.poc.name
  secret_name     = "SHIFTLEFT_ACCESS_TOKEN"
  plaintext_value = var.sl_access_token
}

resource "github_actions_secret" "sl_api_token_secret" {
  repository      = data.github_repository.poc.name
  secret_name     = "SHIFTLEFT_API_TOKEN"
  plaintext_value = var.sl_api_token
}
// ------------------------------------------------------------

// Create secrets in all js repos
resource "github_actions_secret" "sl_js_org_id_secret" {
  for_each = toset(data.github_repositories.js_repos.names)

  repository      = each.key
  secret_name     = "SHIFTLEFT_ORG_ID"
  plaintext_value = var.sl_org_id
}

resource "github_actions_secret" "sl_js_access_token_secret" {
  for_each = toset(data.github_repositories.js_repos.names)

  repository      = each.key
  secret_name     = "SHIFTLEFT_ACCESS_TOKEN"
  plaintext_value = var.sl_access_token
}

resource "github_actions_secret" "sl_js_api_token_secret" {
  for_each = toset(data.github_repositories.js_repos.names)

  repository      = each.key
  secret_name     = "SHIFTLEFT_API_TOKEN"
  plaintext_value = var.sl_api_token
}
// ------------------------------------------------------------

// Create a branch in a single poc repo
resource "github_branch" "sl_integration_branch" {
  repository = data.github_repository.poc.name
  branch     = var.sl_branch
}

// ------------------------------------------------------------
// Create branches in all js repos
resource "github_branch" "sl_js_integration_branch" {
  for_each = toset(data.github_repositories.js_repos.names)

  repository = each.key
  branch     = var.sl_branch
}
// ------------------------------------------------------------

// Create ShiftLeft NG SAST workflow file in a single repo
resource "github_repository_file" "inspect_workflow" {
  repository = data.github_repository.poc.name
  file       = var.workflow_file
  content    = file("${path.module}/data/java.tmpl")
  branch     = var.sl_branch

  depends_on = [github_branch.sl_integration_branch]
}
// ------------------------------------------------------------

// Create ShiftLeft NG SAST workflow files in all js repo
resource "github_repository_file" "inspect_js_workflow" {
  for_each = toset(data.github_repositories.js_repos.names)

  repository = each.key
  file       = var.workflow_file
  content    = file("${path.module}/data/js.tmpl")
  branch     = var.sl_branch

  depends_on = [github_branch.sl_js_integration_branch]
}
