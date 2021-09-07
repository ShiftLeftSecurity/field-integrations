# RBAC API v4 Example

This example takes a list of users from the csv file and:

* Sets their organization level roles.
* Creates the team they need to be assigned to if necessary
* Assigns them to the specified team with the specified role

### Caveats:

* Unless you are an organization owner, you will not be able to modify other users with role SuperAdmin in the organization.
* The CSV filename and format are constrained to what is shown in the example.
* You will need your ShiftLeft ORG ID and Access Token (personal access token not CI token) exported in your environment as:
  * `SHIFTLEFT_ORG_ID`
  * `SHIFTLEFT_ACCESS_TOKEN` 
respectively.

