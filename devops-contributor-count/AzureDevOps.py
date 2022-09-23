import requests
import datetime
import base64

username = ''
token_str = ''
_azure_auth_header = None
lookback_days = 90

# The top argument from the user (or default to 100)
top = ''


def easy_base_64_encode(original_string):
    original_bytes = bytes(original_string, 'ascii')
    encoded_bytes = base64.b64encode(original_bytes)
    encoded_string = str(encoded_bytes, 'ascii')
    return encoded_string


def get_azure_auth_header():
    global _azure_auth_header
    if not _azure_auth_header:
        thing_to_encode_str = '%s:%s' % (username, token_str)
        encoded_thing_str = easy_base_64_encode(thing_to_encode_str)

        azure_auth_header = {
            'Authorization': 'Basic %s' % encoded_thing_str
        }
        _azure_auth_header = azure_auth_header
        return azure_auth_header
    else:
        return _azure_auth_header


# TODO: Figure out the proper way to do this
def get_datetime_from_azure_devops_format(str_azure_datetime):
    str_modified_azure_style_timestamp = str_azure_datetime.replace('Z', '')
    dt = datetime.datetime.fromisoformat(str_modified_azure_style_timestamp)
    return dt


def time_delta_since_event_seconds(dt_event, dt_reference):
    if dt_reference is None:
        dt_reference = datetime.datetime.utcnow()

    time_delta_since_event = dt_reference - dt_event
    print(time_delta_since_event)
    return time_delta_since_event


def is_within_90_days(dt_event, dt_now):
    timedelta_90_days = datetime.timedelta(lookback_days)
    timedelta_since_event = dt_now - dt_event
    is_within = timedelta_since_event <= timedelta_90_days
    return is_within


# https://docs.microsoft.com/en-us/rest/api/azure/devops/core/projects/list?view=azure-devops-rest-6.0&tabs=HTTP&viewFallbackFrom=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/_apis/projects?api-version=7.0
# Added the top argument at the end of the URI
def azure_devops_list_projects(organization, top):
    azure_auth_header = get_azure_auth_header()
    full_api_url = 'https://dev.azure.com/%s/_apis/projects?api-version=7.0&$top=%s' % (organization, top)

    resp = requests.get(full_api_url, headers=azure_auth_header)
    resp_json_obj = resp.json()
    return resp_json_obj


# https://docs.microsoft.com/en-us/rest/api/azure/devops/git/repositories/list?view=azure-devops-rest-6.0&tabs=HTTP&viewFallbackFrom=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories?api-version=7.0
def azure_devops_list_repos(organization, project):
    full_api_url = 'https://dev.azure.com/%s/%s/_apis/git/repositories?api-version=7.0' % (organization, project)

    azure_auth_header = get_azure_auth_header()
    resp = requests.get(full_api_url, headers=azure_auth_header)
    resp_json_obj = resp.json()
    return resp_json_obj


# https://docs.microsoft.com/en-us/rest/api/azure/devops/git/commits/get%20commits?view=azure-devops-rest-7.0
# GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/{repositoryId}/commits?api-version=7.0
def azure_devops_get_commits(organization, project, repositoryId):
    timedelta_90_days = datetime.timedelta(lookback_days)
    dt_from_date = datetime.datetime.now() - timedelta_90_days
    str_from_date = dt_from_date.strftime("%Y-%m-%d %H:%M:%S")
    azure_auth_header = get_azure_auth_header()
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
