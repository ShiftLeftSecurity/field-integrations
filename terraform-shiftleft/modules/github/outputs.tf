output "poc_repo" {
  value = var.poc_repo
}

output "js_repos" {
  value = data.github_repositories.js_repos.names
}

output "csharp_repos" {
  value = data.github_repositories.csharp_repos.names
}

output "python_repos" {
  value = data.github_repositories.python_repos.names
}
