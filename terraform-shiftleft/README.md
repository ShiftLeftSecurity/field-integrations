# Introduction

This repo contains sample terraform modules and scripts required to deploy ShiftLeft NG SAST to your organization. Following providers are supported: 

| Provider     | Create Secrets | Create Pipeline definition | Commit config to repo |
| ------------ | -------------- | -------------------------- | --------------------- |
| GitHub       | Y              | Y                          | Y                     |
| GitLab       | Y              | N                          | N                     |
| Bitbucket    | Y              | N                          | N                     |
| Azure DevOps | Y              | Y                          | N                     |

## Who should use this script?

The user should have administration access to the organization accounts with the provider such as GitHub or GitLab.

## Prerequisites

### ShiftLeft account

Visit https://shiftleft.io/register to signup for a free trial. Then visit the `Account Settings` page and copy the following values.

- Org ID
- Access Token
- Public API Token ( Beta ) - Optional

## Sample deployment (GitHub)

There are a handful of sample deployments available within `deployments` directory.

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
