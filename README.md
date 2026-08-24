## OIDC Extended

🚨 **BREAKING CHANGE:** This app has been refactored to natively use **Role Profiles** and **Module Profiles** instead of mapping individual Roles and Modules. When upgrading, you must recreate your mappings using Frappe Profiles. 🚨

An extension to the ERPNext Social Login authentication method (OIDC) that incorporates new features designed to meet the needs of enterprises.

Features:

- Group Multi-Mapping: natively assign multiple roles and modules by mapping OIDC *groups* to Frappe **Role Profiles** and **Module Profiles**.
- Customizable claim names.
- Specify the default Fallback Profiles (Role and Module) for users matching no specific groups.
- Verification of the id token against the signing keys of the identity provider.
- A choice of what happens to users the identity provider no longer places in any mapped group.
- Automatic user creation, following the site's signup settings or overriding them deliberately.
- An endpoint that starts a login, so the identity provider can link straight into the site.

<img width="1001" height="1258" alt="image" src="https://github.com/user-attachments/assets/ffd51abb-82e1-4b99-940c-d24cfe88b548" />

#### *Social Login Key* Configuration

This app extends the functionality of Social Login Key, that is why it is important to configure the latter correctly to get this app work properly. Below is a simple functional configuration for Social Login Key module, which can be imported directly as a document in ERPNext.

```json
{
    "name": "keycloak",
    "enable_social_login": 1,
    "social_login_provider": "Custom",
    "client_id": "erpnext",
    "provider_name": "keycloak",
    "client_secret": "{{ erpnext_idp_client_secret }}",
    "icon": "",
    "base_url": "https://idp.{{ domain_name }}/realms/{{ keycloak_realm }}",
    "authorize_url": "/protocol/openid-connect/auth",
    "access_token_url": "/protocol/openid-connect/token",
    "redirect_url": "/api/method/oidc_extended.callback.custom/keycloak",
    "api_endpoint": "https://idp.{{ domain_name }}/realms/{{ keycloak_realm }}/protocol/openid-connect/userinfo",
    "custom_base_url": 1,
    "auth_url_data": "{\"response_type\": \"code\", \"scope\": \"openid profile email\"}",
    "user_id_property": "preferred_username",
    "doctype": "Social Login Key"
}
```

Notes:

- The last part of your `redirect_url` must match the name of the identity provider.
- Replace the `{{ variable }}`s with real values.

#### *OIDC Extended Configuration*

One document per provider, named after the Social Login Key it extends.

**ID Token Verification**

| Setting | Meaning |
| --- | --- |
| Verify ID Token Signature | On by default. The id token is verified against the keys the provider publishes, its audience against the client id of the Social Login Key, and its issuer against the one below. Turn it off only to debug a provider whose keys cannot be reached - the `groups` claim of an unverified token decides the user's roles. |
| JWKS URL | The provider's JWKS endpoint, for example `https://auth.example.com/application/o/erpnext/jwks/`. Leave it empty to read it from the OpenID discovery document, which is cached for a day. |
| Issuer | The expected `iss` claim, and the base the discovery document is read from. Defaults to the base URL of the Social Login Key. |

Providers that sign the id token symmetrically (an `HS*` algorithm) are verified against the client secret. Only asymmetric algorithms are accepted from the JWKS path.

**Users**

| Setting | Meaning |
| --- | --- |
| User Provisioning | Whether a login by someone without a Frappe account creates one. Follows the Sign-ups field of the Social Login Key by default, which is what Frappe's own social logins do; can be set to always or never create users. |
| User Type For New Users | The User Type new users are given, `Website User` by default. Frappe replaces either standard type on every save with one derived from the desk access of the user's roles (`User.set_system_user`), so on a site where System Users are billed seats, the role profiles you map are what decides the cost. A custom User Type is honoured as set. |

**Roles and modules**

Group mappings carry a **Priority**, lowest number first. It decides which profile wins on Frappe versions that store a single role profile per user (v15 stores one in `role_profile_name`; the `role_profiles` child table that holds several arrived in v16), and which module profile wins, since the User doctype holds only one.

**When No Group Matches** decides what happens when the token carries no group that matches a mapping and no fallback role profile is configured:

| Value | Meaning |
| --- | --- |
| Keep Existing Roles | The default. The user's roles are left as they are. |
| Remove All Roles | The roles and the module profile are stripped, so that removing someone from every group in the identity provider de-provisions them in Frappe. |
| Deny Login | The login is refused. |

#### Starting a login from the identity provider

Frappe renders the authorize URL only into its own login page, so there is no address an application tile in the identity provider can point at. This app adds one:

```
https://erp.example.com/api/method/oidc_extended.callback.start/<provider name>
```

It accepts an optional `redirect_to` parameter for where the user should land once logged in, restricted to this site.

#### Supported Frappe versions

| Frappe | Supported |
| --- | --- |
| v15 | 15.116.0 and newer |
| v16 | 16.30.0 and newer |
| v17 (develop) | expected to work; not released |

Those are the releases in which Frappe replaced the base64 `state` blob with a
single-use token (`frappe.utils.oauth.consume_oauth_state`). Older releases send a
`state` that cannot be validated at all, so the app refuses to run on them and says
which release is needed rather than accepting an unvalidated login.

The role assignment adapts to the running version: v16 holds several role profiles in
the `role_profiles` Table MultiSelect, v15 holds one in `role_profile_name`, and the
Priority column decides which profile wins where only one fits.

#### Upgrading

- Users are matched by their social login userid, then by email address, then by `username`. Earlier versions matched by `username` only, which found nobody on a site whose users predate the app.
- Id token verification is on after upgrading. A provider whose JWKS endpoint cannot be discovered will refuse logins until the JWKS URL is filled in.
- Existing configurations keep creating users automatically: a patch sets their User Provisioning to "Always Create Users", which is what they did before the setting existed. New configurations follow the Social Login Key.

#### Tests

The tests run without a bench, against a stand-in for the parts of Frappe the callback uses:

```bash
cd apps/oidc_extended
python -m unittest discover -s tests -t .
```

#### License

MIT
