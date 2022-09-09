#! env python3
import json
import os
import sys
from os.path import abspath, exists

import requests
from requests.structures import CaseInsensitiveDict

SHIFTLEFT_COOKIE_ENV_VAR_NAME = "SHIFTLEFT_COOKIE"
SHIFTLEFT_ORG_ID_ENV_VAR_NANE = "SHIFTLEFT_ORG_ID"
PLS_SET_ERR = "is not set in the environment, please set it before continuing"
HTTP_DELETE = "DELETE"
FAILED_DELETES_FILE = "failed_deletes.txt"


class ErrReqFailed(Exception):
    """
    ErrReqFailed will be raised when the initial DELETE request is not successful.
    """

    def __init__(self, code):
        self.code = code


class ErrConfirmationReqFailed(Exception):
    """
    ErrConfirmationReqFailed will be raised when the confirmation DELETE (the actual deletion) request is not
    successful.
    """

    def __init__(self, code):
        self.code = code


def _delete_project(cookie, resource_url):
    """
    Deletion in APIv2, as it is done in this script requires a two-step process:
    First we issue a `DELETE` on the resource and retrieve a confirmation token, then we issue a second `DELETE` on the
    same resource adding the token as the body.
    """
    print(f"Will initiate deletion of {resource_url}")
    headers = CaseInsensitiveDict()
    headers["Cookie"] = cookie
    res = requests.delete(url=resource_url, headers=headers)
    print(f"got response {res.text}")
    if res.status_code != 200:
        raise ErrReqFailed(res.status_code)

    res_map = json.loads(res.text)

    confirmation_token = json.dumps({"response": res_map})

    print(f"Will confirm deletion of {resource_url} with token {confirmation_token}")
    headers["content-type"] = "application/json"
    res = requests.delete(url=resource_url, headers=headers, data=confirmation_token)
    if res.status_code != 200:
        raise ErrConfirmationReqFailed(res.status_code)


def delete_project(cookie, org_id, project_id=None):
    """
    delete_project will trigger deletion of the passed project in the specified org using the cookie provided
    """
    if project_id is None:
        print("received an empty project ID, this deletion will not take place")
        return
    _delete_project(
        cookie,
        f"https://app.shiftleft.io/api/v2/organizations/{org_id}/projects/{project_id}".strip(),
    )


def bulk_delete_projects():
    """
    bulk_delete_projects is the entry point for this script, it will check that appropriate variables are set
    and that the project list exists then trigger one by one the deletions.
    """
    cookie = os.environ.get(SHIFTLEFT_COOKIE_ENV_VAR_NAME, None)
    if cookie is None:
        sys.exit(f"{SHIFTLEFT_COOKIE_ENV_VAR_NAME} {PLS_SET_ERR}")
    org_id = os.environ.get(SHIFTLEFT_ORG_ID_ENV_VAR_NANE, None)
    if org_id is None:
        sys.exit(f"{SHIFTLEFT_ORG_ID_ENV_VAR_NANE} {PLS_SET_ERR}")

    project_list_file_name = abspath(sys.argv[1])
    if not exists(project_list_file_name):
        sys.exit(f"cannot find the specified project id list: {project_list_file_name}")

    with open(project_list_file_name) as project_file:
        lines = project_file.readlines()
        for line in lines:
            if line == "":
                continue
            try:
                delete_project(cookie, org_id, line)
            except ErrReqFailed as e:
                print(
                    f"Failed to initiate deletion for project: {line} with HTTP code: {e.code}"
                )
                with open(FAILED_DELETES_FILE, "a") as f:
                    print(f"{line}\n", file=f)
            except ErrConfirmationReqFailed as e:
                print(
                    f"Failed to complete deletion for project: {line} with HTTP code: {e.code}"
                )
                with open(FAILED_DELETES_FILE, "a") as f:
                    print(f"{line}\n", file=f)


if __name__ == "__main__":
    bulk_delete_projects()
