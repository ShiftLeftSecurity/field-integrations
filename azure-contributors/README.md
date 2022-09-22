## Description
Count contributing developers to an Azure DevOps organization in the last 90 days.

## Usage
Install virtual environment with:
`pipenv install`


Then run the script with:
`pipenv run python3 azure-contributors.py --org=[Azure DevOps Organization] --username=[Azure DevOps Username] --accessToken=[Azure DevOps Personal Access Token] --top=[The top n number of projects to retrieve, if not set default is 100]`

(Or use alternate Python 3 environment as required)


python3 azure-contributors.py --org=jsarabi --username=jsarabi@hotmail.com --accessToken=24nrx4vmida5ytau6fs25z4kpzadkiohyd7w56lndrmavrlycxlq --top=[The top n number of projects to retrieve, if not set default is 100]`