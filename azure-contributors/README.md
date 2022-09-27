## Description
Count contributing developers to an Azure DevOps organization in the last 90 days.

## Usage
Install virtual environment with:
`pipenv install`

To create access token: https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=Windows

Then run the script with:
`pipenv run python3 azure-contributors.py --org=[Azure DevOps Organization] --username=[Azure DevOps Username] --accessToken=[Azure DevOps Personal Access Token] --top=[The top n number of projects to retrieve, if not set default is 100]`

(Or use alternate Python 3 environment as required)
