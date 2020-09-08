output "all_repos" {
  value = data.azuredevops_git_repositories.all_repos.repositories
}