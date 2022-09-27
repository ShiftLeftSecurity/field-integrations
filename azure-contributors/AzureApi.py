import requests
import datetime
import base64

username = ''
accessToken = ''
_azure_auth_header = None
daysLookback = 90

# The top argument from the user (or default to 100)
top = ''

def base64Encode(originalValue):
    bytesValue = bytes(originalValue, 'ascii')
    bytesEncoded = base64.b64encode(bytesValue)
    return str(bytesEncoded, 'ascii')

def azureDateFormat(str_azure_datetime):
    str_modified_azure_style_timestamp = str_azure_datetime.replace('Z', '')
    return datetime.datetime.fromisoformat(str_modified_azure_style_timestamp)

def azureAuthHeader():
    global _azure_auth_header
    if not _azure_auth_header:
        thing_to_encode_str = '%s:%s' % (username, accessToken)
        encoded_thing_str = base64Encode(thing_to_encode_str)

        azure_auth_header = {
            'Authorization': 'Basic %s' % encoded_thing_str
        }
        _azure_auth_header = azure_auth_header
        return azure_auth_header
    else:
        return _azure_auth_header

def isWithinLookback(dt_event, dt_now):
    diffLookbackTime = datetime.timedelta(daysLookback)
    timedelta_since_event = dt_now - dt_event
    return timedelta_since_event <= diffLookbackTime

# https://docs.microsoft.com/en-us/rest/api/azure/devops/git/commits/get%20commits?view=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repositoryId}/commits?api-version=7.0
def azureCommits(organization, project, repositoryId):
    diffLookbackTime = datetime.timedelta(daysLookback)
    dt_from_date = datetime.datetime.now() - diffLookbackTime
    str_from_date = dt_from_date.strftime("%Y-%m-%d %H:%M:%S")
    azure_auth_header = azureAuthHeader()
    all_commit_pages = []

    page_size = 100
    page = 0

    while page == 0 or 'next' in resp.links:
        num_skip = page * page_size
        full_api_url = 'https://dev.azure.com/%s/%s/_apis/git/repositories/%s/commits?searchCriteria.fromDate=%s&searchCriteria.$skip=%s&api-version=7.0' % \
                    (organization, project, repositoryId, str_from_date, num_skip)

        resp = requests.get(full_api_url, headers=azure_auth_header)

        all_commit_pages.append(resp.json())
        page += 1

    all_commits = []
    for next_page in all_commit_pages:
        all_commits.extend(next_page['value'])

    return all_commits

# https://docs.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-6.0&tabs=HTTP&viewFallbackFrom=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories?api-version=7.0
def azureRepos(organization, project):
    full_api_url = 'https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.0' % (organization, project)

    azure_auth_header = azureAuthHeader()
    resp = requests.get(full_api_url, headers=azure_auth_header)
    resp_json_obj = resp.json()
    return resp_json_obj

# https://docs.microsoft.com/en-us/rest/api/azure/devops/core/projects/list?view=azure-devops-rest-6.0&tabs=HTTP&viewFallbackFrom=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/_apis/projects?api-version=7.0
# Added the top argument at the end of the URI
def azureProjects(organization, top):
    azure_auth_header = azureAuthHeader()
    full_api_url = 'https://dev.azure.com/%s/_apis/projects?api-version=7.0&$top=%s' % (organization, top)

    resp = requests.get(full_api_url, headers=azure_auth_header)
    return resp.json()
