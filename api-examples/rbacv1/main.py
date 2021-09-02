# !/usr/bin/env python3
import csv
import json
import os
import urllib

import requests

try:
    SHIFTLEFT_ORG_ID = os.environ["SHIFTLEFT_ORG_ID"]
    SHIFTLEFT_ACCESS_TOKEN = os.environ["SHIFTLEFT_ACCESS_TOKEN"]
except KeyError:
    raise SystemExit("Oops! Do not forget to set both SHIFTLEFT_ORG_ID and SHIFTLEFT_ACCESS_TOKEN!")

API_V4_BASE_URL = "https://www.shiftleft.io/api/v4/"
API_V4_ORG_PATH = "orgs/{organization_id}/"


class SLAPIError:
    """
    SLAPIError represents API error details returned by SL API v4
    """

    def __init__(self, ok=False, code=0, message="", validation_errors=()):
        self.ok = ok
        self.code = code
        self.message = message
        self.validation_errors = validation_errors

    def as_string(self):
        """
        as_string composes the most descriptive error it can with the available data.
        :return: string containing a descriptive error.
        """
        if len(self.validation_errors) != 0:
            return "found the following validation errors in the request: {}".format(", ".join(self.validation_errors))

        if len(self.message) != 0:
            return "server responded: {}".format(self.message)

        return "server returned {} code without further information".format(self.code)


def handle_status_code(resp=None):
    """
    handle_status_code intercepts the response and raises an appropriate error if it's not a 200

    :param resp: an http response as returned from requests library
    :return: None in case of success or raises an exception with details otherwise
    """
    if resp is None:
        return
    if resp.status_code == 200:
        return
    try:
        json_decoded_body = resp.json()
    except json.JSONDecodeError:
        raise Exception(resp.text)
    e = SLAPIError(**json_decoded_body)
    raise Exception(e.as_string())


class SLResponse:
    """
    Is an implementation of the base 200 response provided by all ShiftLeft API v4 endpoints.
    """

    def __init__(self, ok=True, response=None):
        if response is None:
            response = {}
        self.ok = ok
        self.response = response


class SLTeamMembership:
    """
    SLTeamMembership contains the membership details for a user in a team.
    """

    def __init__(self, team_name="", team_id="", role="", role_name="", role_aliases=[]) -> None:
        self.team_name = team_name
        self.team_id = team_id
        self.role = role
        self.role_name = role_name
        self.role_aliases = role_aliases


class SLUser:
    """
    SLUser holds the information for one user as returned from ListUsers endpoint in ShiftLeft APIv4
    https://docs.shiftleft.io/api/#operation/ListOrgRBACUsers
    """

    def __init__(self, name="", email="", id_v2="", team_membership=()):
        self.name = name
        self.email = email
        self.id_v2 = id_v2
        self.team_membership = [SLTeamMembership(**t) for t in team_membership]

    def is_member(self, team=""):
        for tm in self.team_membership:
            if tm.team_name == team:
                return True
        return False


class SLListUsersResponse:
    """
    SLListUsersResponse represents the response for the ListUsers endpoint in ShiftLeft API v4
    https://docs.shiftleft.io/api/#operation/ListOrgRBACUsers
    """

    def __init__(self, users=()):
        self.users = [SLUser(**u) for u in users]

    def id_for_email(self, user_email=""):
        user_email = user_email.lower()
        for u in self.users:
            if u.email.lower() == user_email:
                return u.id_v2

    def user_for_id(self, user_id=""):
        for u in self.users:
            if u.id_v2 == user_id:
                return u


class SLTeamInfo:
    """
    SLTeamInfo represents the information returned in one item of ListTeams endpoint in ShiftLeft API v4
    https://docs.shiftleft.io/api/#operation/ListTeams
    """

    def __init__(self, team_id="", team_name=""):
        self.team_id = team_id
        self.team_name = team_name


class SLTeams:
    """
    SLTeams represents a group of teams, typically of a same organization.
    """

    def __init__(self, teams=()):
        self.teams = [SLTeamInfo(**team) for team in teams]

    def __contains__(self, item):
        for tm in self.teams:
            if tm.team_name == item:
                return True

    def append(self, team):
        self.teams.append(team)


class SLAPIClient:
    """
    SLAPIClient handles communications with ShiftLeft API v4 for the purposes of this script.
    It is very limited and bound to be obsoleted of Schema changes.
    """

    def __init__(self, access_token="", organization_id=""):
        self.__access_header = {'Authorization': 'Bearer {}'.format(access_token)}
        self.__organization_id = organization_id

    def _do_get(self, api_path):
        u = API_V4_BASE_URL + API_V4_ORG_PATH.format(organization_id=self.__organization_id) + api_path
        resp = requests.get(u, headers=self.__access_header)
        handle_status_code(resp)
        return resp.json().get('response', None)

    def _do_post(self, api_path, payload=None):
        u = API_V4_BASE_URL + api_path
        resp = requests.post(u, headers=self.__access_header, data=payload)
        handle_status_code(resp)
        return resp.json().get('response', None)

    def _do_put(self, api_path, payload=None):
        u = API_V4_BASE_URL + api_path
        resp = requests.put(u, headers=self.__access_header, data=payload)
        handle_status_code(resp)
        return resp.json().get('response', None)

    def list_users(self):
        """
        list_users implements a GET request to https://docs.shiftleft.io/api/#operation/ListOrgRBACUsers
        :return:
        """
        return SLListUsersResponse(self._do_get("rbac/users"))

    def list_teams(self):
        """
        list_teams implements a GET request to https://docs.shiftleft.io/api/#operation/ListTeams
        :return:
        """
        resp = self._do_get("rbac/teams")
        return SLTeams(resp)

    def list_roles(self):
        """
        list_roles implements a GET request to https://docs.shiftleft.io/api/#operation/ListTeams
        :return:
        """
        return self._do_get("rbac/roles")

    def create_team(self, name=""):
        """
        create_team implements a POST request to https://docs.shiftleft.io/api/#operation/CreateTeam
        :param name: the name of the team to be created, must be unique
        :return:
        """
        team_payload = {
            "name": name
        }
        resp = self._do_post("rbac/teams", team_payload)
        return SLTeamInfo(team_id=resp["team_id"], team_name=name)

    def assign_user_organization_role(self, user_id="", role=""):
        """
        assign_user_organization_role will assign the role passed to the user at an organization level

        :param user_id: the id v2 of the user
        :param role: the role id or alias the user will have at an organization level
        :return: a dictionary of the json response from the call.
        """
        user_org_role_payload = {"org_role": role}
        self._do_put("rbac/users/{user_id}".format(user_id=user_id), user_org_role_payload)

    def assign_user_team_role(self, user_id="", team="",  role=""):
        """
        assign_user_team_role will assign a single user to a team
        :param user_id: the id v2 of the user to add to the team
        :param team: the team where we want to add the user
        :param role: the role that user will have on that team
        :return: a dictionary of the json response from the call.
        """
        version = self.current_team_version(team)
        payload = {
            "version": version,
            "add_team_membership": [
                {
                    "user_id_v2": user_id,
                    "team_role": role
                }
            ]
        }
        self._do_put("rbac/teams/{team}".format(team=team), payload)

    def current_team_version(self, team=""):
        """
        current_team_version returns the version of the passed team on the server

        :param team: the name of the team whose version we want
        :return: an integer representing the current team version
        """
        r = self._do_get("rbac/teams/{team}".format(team=team))
        return r["version"]

    def assign_users_to_teams(self, team="", user_role_pairs=[]):
        """
        assign_users_to_teams will assign the passed users to the passed team taking care of fetching new version.

        :param team: the name of the team where the users will be added
        :param user_role_pairs: a list of (user_id_v2, role_id_or_alias) to know users and capacity to add to team.
        :return: a dictionary of the json response from the call.
        """
        add_to_team = []
        for user_id, role in user_role_pairs:
            add_to_team.append({"user_id_v2": user_id,
                                "team_role": role})
        version = self.current_team_version(team)
        payload = {
            "version": version,
            "add_team_membership": [
                add_to_team
            ]
        }
        self._do_put("rbac/teams/{team}".format(team=team), payload)


class CSVUser:
    """
    CSVUser represents user information as present in each row of the sample csv.
    """

    def __init__(self, email="", team="", orgrole="", teamrole=""):
        self.email = email
        self.team = team
        self.organization_role = orgrole  # NOTE: These values are not yet stable and might change.
        self.team_role = teamrole  # NOTE: These values are not yet stable and might change.


def main():
    api_v4 = SLAPIClient(SHIFTLEFT_ACCESS_TOKEN, SHIFTLEFT_ORG_ID)

    teams = api_v4.list_teams()
    users = api_v4.list_users()

    add_to_teams = {}

    with open("rbac.csv", "r") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            # Read one user from CSV
            user = CSVUser(**row)
            # Create the team this user should belong to if it doesn't exist
            if user.team in teams:
                print("Team {} exists for this organization".format(user.team))
            else:
                print("Team '{}' does not exist for this organization;"
                      " creating it and assigning '{}' to it".format(user.team, user.email))
                teams.append(api_v4.create_team(user.team))

            # Assign the user organization wide role.
            user_id = users.id_for_email(user.email)
            api_v4.assign_user_organization_role(user_id, user.organization_role)
            print("Updated organization role for {email} to {org_role}.".format(email=user.email,
                                                                                org_role=user.organization_role))

            # Queue the users to add for each team to economize requests
            add_to_teams[user.team] = (user_id, user.team_role)

    # Process team membership changes
    for team, info in add_to_teams.items():
        api_v4.assign_users_to_teams(team, info)
        print("Updated team membership for '{}'".format(team))
        for user_id, team_role in info:
            u = users.user_for_id(user_id)
            # is_member works because users info was obtained before making any changes so it depicts initial state.
            action = "Updated team membership of" if u.is_member(team) else "Added membership of"
            print('* {action} {email} with role {teamrole}.'.format(action=action, email=u.email, teamrole=team_role))


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
