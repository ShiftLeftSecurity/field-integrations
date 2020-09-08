# Introduction

This repo contains sample terraform scripts required to deploy ShiftLeft NG SAST to your organization's Bitbucket repositories. The official Bitbucket provider is quite basic so this example merely adds some secrets to existing repositories that are referred by ids.

## Who should use this script?

The user should have administration access to the Bitbucket organization.

## Known limitations

- Terraform Bitbucket provider only support adding repository variables at this point
- Repositories should be referred by their ids! There is no data block support for repository yet

## Pre-requisites

### ShiftLeft account

Visit https://shiftleft.io/register to signup for a free trial. Then visit the `Account Settings` page and copy the following values.

- Org ID
- Access Token
- Public API Token ( Beta ) - Optional

### Bitbucket app password

Create a new app password with the following scope

- Workspace membership - Read/Write
- Repositories - Read/Write/Admin
- Pipelines - Read/Write/Edit variables

## Sample deployment

```bash
cd deployments/sample-bitbucket
terraform init
```

Create a file called `terraform.tfvars` inside `sample-bitbucket` directory. The file should have following contents. This file should not be committed to the git repository or made public.

```terraform
sl_org_id       = "Org ID"
sl_access_token = "Access Token"
sl_api_token    = "Public API Token"
bitbucket_app_password    = "Bitbucket app password"
bitbucket_username     = "Bitbucket username"
bitbucket_owner        = "Bitbucket owner"
repos                  = List of repository slug prefixed by owner. Eg: ["prabhusl/helloshiftleft", "prabhusl/webgoat"]
```

Proceed with terraform plan and apply commands.

```bash
terraform plan --out=bit.plan
terraform apply bit.plan
```
