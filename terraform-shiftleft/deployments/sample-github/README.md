# Introduction

This repo contains sample terraform scripts required to deploy ShiftLeft NG SAST to your organization's GitHub repositories. A new GitHub action workflow for ShiftLeft will be created for integration in a branch called `feature/shiftleft`. See the module `shiftleft` for customizing the branch name.

## Who should use this script?

The user should have administration access to the GitHub organization. Please create a new organization with GitHub for teams plan to experiment with this script before deploying to your main account.

## Known limitations

- GitHub currently doesn't support deployments to personal accounts via terraform.
- Terraform state files would include sensitive information such as GitHub and ShiftLeft tokens in plaintext by design. Care should be taken not to commit this file to git repositories or shared openly in public.

## Pre-requisites

### ShiftLeft account

Visit https://shiftleft.io/register to signup for a free trial. Then visit the `Account Settings` page and copy the following values.

- Org ID
- Access Token
- Public API Token ( Beta ) - Optional

### GitHub Personal Access Token

Create a personal access token with the following scopes.

- repo
- workflow

## Sample deployment

```bash
cd deployments/sample-github
terraform init
```

Create a file called `terraform.tfvars` inside `sample-github` directory. The file should have following contents. This file should not be committed to the git repository or made public.

```terraform
sl_org_id       = "Org ID"
sl_access_token = "Access Token"
sl_api_token    = "Public API Token"
github_token    = "GitHub personal access token"
```

Proceed with terraform plan and apply commands.

```bash
terraform plan --out=gh.plan
terraform apply gh.plan
```
