# Introduction

This repo contains sample terraform scripts required to deploy ShiftLeft NG SAST to your organization's Azure DevOps. A new variable group and pipelines will be created with ShiftLeft tokens for git repositories in Azure Repos.

## Who should use this script?

The user should have administration access to the Azure DevOps organization.

## Known limitations

- Repos should be enabled and repositories should be present for the project.
- Repos should contain the file azure-pipelines.yml with ShiftLeft build steps. The terraform provider doesn't support creating a file dynamically yet.

## Pre-requisites

### ShiftLeft account

Visit https://shiftleft.io/register to signup for a free trial. Then visit the `Account Settings` page and copy the following values.

- Org ID
- Access Token
- Public API Token ( Beta ) - Optional

### Azure DevOps Personal Access Token

Create a personal access token with either Full Access Scope or with the below list.

- Build - Read/Execute
- Code - Full
- Service Connections - Read/Query/Manage
- Variable Groups - Read/Create/Manage

## Sample deployment

```bash
cd deployments/sample-azure-devops
terraform init
```

Create a file called `terraform.tfvars` inside `sample-azure-devops` directory. The file should have following contents. This file should not be committed to the git repository or made public.

```terraform
sl_org_id       = "Org ID"
sl_access_token = "Access Token"
sl_api_token    = "Public API Token"
org_service_url = "https://dev.azure.com/<org>"
personal_access_token = "Personal Access Token"
project_name = "Project name"
```

Proceed with terraform plan and apply commands.

```bash
terraform plan --out=az.plan
terraform apply az.plan
```
