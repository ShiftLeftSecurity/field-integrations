### Create the ShiftLeft NG SAST application in Okta

These step-by-step instructions explain how to configure Single Sign-On (SSO)
for ShiftLeft with your organization's Identity Provider.  Service Provider 
Entities are unique to each ShiftLeft organization, and there is a maximum of
one per organization.

Pre-requisites:
- Okta Admin Role
- ShiftLeft Admin Role
- Network access to ShiftLeft API servers
- environment variables (get values from **Avatar** (upper-right) > **Account Settings**):
  - `SHIFTLEFT_ORG_ID`
  - `SHIFTLEFT_ACCESS_TOKEN` (not API token)

1. In **Okta**, **Applications** > **Add application** > **Create New App** > **SAML**

2. In the **App name** tab, enter "ShiftLeft NG SAST"

3. Create a SAML configuration for your organization with the `saml_configs`
   endpoint:

   ```shell
   $ BASE_URL = "https://www.shiftleft.io/api/v4/orgs/${SHIFTLEFT_ORG_ID}"
   $ POST_BODY = '{ \
   >   "name":"saml_config", \
   >   "allow_implicit_invites" : true, \
   >   "allow_idp_initiated_logins" : true \
   > }'
   $ curl -XPOST -d ${POST_BODY} \
   >   -H "Content-Type: application/json" \
   >   -H "Authorization: Bearer ${SHIFTLEFT_ACCESS_TOKEN}" \
   >   "${BASE_URL}/saml_configs"
   ```
   **_NOTE: Currently only one SAML configuration can be created per
   organization.  Subsequent calls to `saml_configs` will fail._**

   Copy the value for `<RELAY_STATE>` from the response and enter it in Okta:

   ```json
   {
     "ok": true,
     "response": {
       "name": "config",
       "idp_default_relay_state": "<RELAY_STATE>",
       "sp_metadata_url": "https://www.shiftleft.io/api/v2/organizations/<SHIFTLEFT_ORG_ID>/saml/config/metadata",
       "sp_login_url": "https://www.shiftleft.io/login/saml/<SHIFTLEFT_ORG_ID>/config",
       "allow_implicit_invites": true,
       "sign_authn_requests": true,
       "allow_idp_initiated_logins": true
     }
   }
   ```

4. Enter the "first_name" and "last_name" attributes.  Acceptable values are:
   - "first_name" + "last_name"
   - "http://schemas.xmlsoap.org/claims/CommonName",
   - "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"
   - "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
   - "displayname", "display_name", "display name",
   - "username", "user_name", "user name",
   - "login", "uid"

5. Get your organization's `<AUDIENCE_URI>` and `<SINGLE_SIGN_ON_URL>` from
   the `saml/config/metadata` endpoint:
   ```shell
   $ curl "https://www.shiftleft.io/api/v2/organizations/${SHIFTLEFT_ORG_ID}/saml/config/metadata"
   ```
   Copy the values for `<AUDIENCE_URI>` and `<SINGLE_SIGN_ON_URL>` from the
   response and enter them in Okta:
   ```xml
   <?xml version="1.0" encoding="UTF-8"?>
   <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="<AUDIENCE_URI>">
      <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
         <md:KeyDescriptor {...omitted for brevity...} />
         <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
         <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="<SINGLE_SIGN_ON_URL>" index="0" isDefault="true" />
      </md:SPSSODescriptor>
   </md:EntityDescriptor>
   ```

6. 
6. **_TEST_** the integration by assigning yourself to the ShiftLeft NG SAST application and logging in.
   **_NOTE: The web UI login (https://www.shiftleft.io/login) currently requires users to enter their passwords even if they're already logged in._** 
