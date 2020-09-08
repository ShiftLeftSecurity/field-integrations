provider "azuredevops" {
  version               = ">= 0.0.1"
  org_service_url       = var.org_service_url
  personal_access_token = var.personal_access_token
}

data "azuredevops_project" "ado_project" {
  project_name = var.project_name
}

data "azuredevops_git_repositories" "all_repos" {
  project_id = data.azuredevops_project.ado_project.id
}

resource "azuredevops_variable_group" "sl_vargroup" {
  project_id   = data.azuredevops_project.ado_project.id
  name         = var.sl_var_group
  description  = "ShiftLeft Org Id and Tokens"
  allow_access = true

  variable {
    name      = "SHIFTLEFT_ORG_ID"
    value     = var.sl_org_id
    is_secret = true
  }

  variable {
    name      = "SHIFTLEFT_ACCESS_TOKEN"
    value     = var.sl_access_token
    is_secret = true
  }

  variable {
    name      = "SHIFTLEFT_API_TOKEN"
    value     = var.sl_api_token
    is_secret = true
  }
}

// Refer: https://github.com/terraform-providers/terraform-provider-azuredevops/blob/master/website/docs/r/serviceendpoint_github.html.markdown
/*
resource "azuredevops_serviceendpoint_github" "github_serviceendpoint" {
  project_id            = azuredevops_project.project.id
  service_endpoint_name = "GithHub Grant"
  description = ""
}
*/

// For GitHub integration, refer to: https://github.com/terraform-providers/terraform-provider-azuredevops/blob/master/examples/github-based-cicd-simple/main.tf
resource "azuredevops_build_definition" "build_definition" {
  count = length(data.azuredevops_git_repositories.all_repos.repositories)

  project_id = data.azuredevops_project.ado_project.id
  name       = "ShiftLeft.${data.azuredevops_git_repositories.all_repos.repositories[count.index].name}"
  path       = "\\"
  ci_trigger {
    use_yaml = true
  }
  repository {
    repo_type   = "TfsGit" // change to GitHub when integrating with GitHub repo
    repo_id     = data.azuredevops_git_repositories.all_repos.repositories[count.index].id
    branch_name = data.azuredevops_git_repositories.all_repos.repositories[count.index].default_branch
    yml_path    = "azure-pipelines.yml"
    // service_connection_id = azuredevops_serviceendpoint_github.github_serviceendpoint.id
  }

  variable_groups = [
    azuredevops_variable_group.sl_vargroup.id
  ]
}
