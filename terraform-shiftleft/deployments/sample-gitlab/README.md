# Introduction

This repo contains sample terraform scripts required to deploy ShiftLeft NG SAST to your organization's GitLab repositories. Currently, only group variables containing the ShiftLeft tokens are created by this module.

## Who should use this script?

The user should have administration access to the GitLab organization.

## Known limitations

- GitLab terraform provider is a bit basic supporting only a handful of api
- Terraform state files would include sensitive information such as GitLab and ShiftLeft tokens in plaintext by design. Care should be taken not to commit this file to git repositories or shared openly in public.

## Pre-requisites

### ShiftLeft account

Visit https://shiftleft.io/register to signup for a free trial. Then visit the `Account Settings` page and copy the following values.

- Org ID
- Access Token
- Public API Token ( Beta ) - Optional

### GitLab Personal Access Token

Create a personal access token with the following scopes.

- api

## Sample deployment

```bash
cd deployments/sample-gitlab
terraform init
```

Create a file called `terraform.tfvars` inside `sample-gitlab` directory. The file should have following contents. This file should not be committed to the git repository or made public.

```terraform
sl_org_id       = "Org ID"
sl_access_token = "Access Token"
sl_api_token    = "Public API Token"
gitlab_token    = "GitLab personal access token"
group_name      = "GitLab group name"
```

Proceed with terraform plan and apply commands.

```bash
terraform plan --out=gl.plan
terraform apply gl.plan
```
