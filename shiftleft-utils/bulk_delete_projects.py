#! env python3
import json
import os
import sys
from os.path import exists, abspath

import requests

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
    res = requests.delete(url=resource_url,
                          headers={"Cookie": cookie})
    if res.status_code != 200:
        raise ErrReqFailed(res.status_code)

    res_map = json.loads(res.text)
    confirmation_token = res_map["response"]
    res = requests.delete(url=resource_url,
                          headers={"Cookie": cookie, "content-type": "application/json"},
                          data=confirmation_token)
    if res.status_code != 200:
        raise ErrConfirmationReqFailed(res.status_code)


def delete_project(cookie, org_id, project_id=None):
    """
    delete_project will trigger deletion of the passed project in the specified org using the cookie provided
    """
    if project_id is None:
        print("received an empty project ID, this deletion will not take place")
        return
    _delete_project(cookie, F"https://app.shiftleft.io/api/v2/organizations/{org_id}/projects/{project_id}")


def bulk_delete_projects():
    """
    bulk_delete_projects is the entry point for this script, it will check that appropriate variables are set
    and that the project list exists then trigger one by one the deletions.
    """
    cookie = os.environ.get(SHIFTLEFT_COOKIE_ENV_VAR_NAME, None)
    if cookie is None:
        print(F"{SHIFTLEFT_COOKIE_ENV_VAR_NAME} {PLS_SET_ERR}")
        sys.exit(1)
    org_id = os.environ.get(SHIFTLEFT_ORG_ID_ENV_VAR_NANE, None)
    if org_id is None:
        print(F"{SHIFTLEFT_ORG_ID_ENV_VAR_NANE} {PLS_SET_ERR}")
        sys.exit(1)

    project_list_file_name = abspath(os.args[1])
    if not exists(project_list_file_name):
        print(F"cannot find the specified project id list: {project_list_file_name}")
        sys.exit(1)

    with open(project_list_file_name) as project_file:
        line = project_file.readline()
        try:
            delete_project(cookie, org_id, line)
        except ErrReqFailed as e:
            print(F"Failed to initiate deletion for project: {line} with HTTP code: {e.code}")
            with open(FAILED_DELETES_FILE, "a") as f:
                print(F"{line}\n", f)
        except ErrConfirmationReqFailed as e:
            print(F"Failed to complete deletion for project: {line} with HTTP code: {e.code}")
            with open(FAILED_DELETES_FILE, "a") as f:
                print(F"{line}\n", f)


if __name__ == "__main__":
    bulk_delete_projects()
