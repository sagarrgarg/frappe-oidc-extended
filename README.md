## OIDC Extended

An extension to the ERPNext Social Login authentication method (OIDC) that incorporates
new features designed to meet the needs of enterprises.

Frappe's built-in social login authenticates a user and stops there. This app takes the
id token that comes back from the identity provider, verifies it, decides which Frappe
user it belongs to, and turns the provider's group membership into Frappe roles.

Features:

- Group Multi-Mapping: assign roles and modules by mapping OIDC *groups* to Frappe **Role Profiles** and **Module Profiles**.
- Verification of the id token against the signing keys, audience and issuer of the identity provider.
- Customizable claim names.
- Fallback profiles (role and module) for users matching no mapped group, and a choice of what to do when there is no fallback either.
- Automatic user creation, following the site's signup settings or overriding them deliberately.
- An endpoint that starts a login, so the identity provider can link straight into the site.

#### Installation

```bash
bench get-app https://github.com/sagarrgarg/frappe-oidc-extended
bench --site <site> install-app oidc_extended
bench --site <site> migrate
```

`PyJWT[crypto]` is installed with the app; it is what verifies the id token.

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

Role assignment adapts to the running version: v16 holds several role profiles in the
`role_profiles` Table MultiSelect, v15 holds one in `role_profile_name`, and the
Priority column decides which profile wins where only one fits.

#### *Social Login Key* Configuration

This app extends the functionality of Social Login Key, that is why it is important to
configure the latter correctly to get this app work properly. Below is a simple
functional configuration for Social Login Key module, which can be imported directly as
a document in ERPNext.

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
    "user_id_property": "sub",
    "doctype": "Social Login Key"
}
```

Notes:

- The last part of your `redirect_url` must match the name of the identity provider.
- Replace the `{{ variable }}`s with real values.
- `client_id` is the audience the id token is checked against.
- `user_id_property` is the claim that identifies the account at the identity provider. It is stored as the user's social login userid and is what later logins are matched on, so it should be a claim that is never reassigned - `sub` rather than `preferred_username` or an email address.
- The `groups` claim must be in the id token, not only in the userinfo endpoint. Roles are decided from the id token.

#### *OIDC Extended Configuration*

One document per provider, named after the Social Login Key it extends.

**Claims**

The claim names to read the given name, family name, email address and groups from.
Each falls back to the standard OIDC name (`given_name`, `family_name`, `email`,
`groups`) when left empty.

The groups claim is normally a JSON array. A string is accepted too: it is split on
commas if it contains any, otherwise taken as a single group name, so a group name may
contain spaces. Mappings are matched against group names exactly.

**ID Token Verification**

| Setting | Meaning |
| --- | --- |
| Verify ID Token Signature | On by default. The id token is verified against the keys the provider publishes, its audience against the client id of the Social Login Key, and its issuer against the one below. Turn it off only to debug a provider whose keys cannot be reached - the `groups` claim of an unverified token decides the user's roles. |
| JWKS URL | The provider's JWKS endpoint, for example `https://auth.example.com/application/o/erpnext/jwks/`. Leave it empty to read it from the OpenID discovery document, which is cached for a day. |
| Issuer | The expected `iss` claim, and the base the discovery document is read from. Defaults to the base URL of the Social Login Key. |

Providers that sign the id token symmetrically (an `HS*` algorithm) are verified against
the client secret. Only asymmetric algorithms are accepted from the JWKS path, so
neither an unsigned token nor one forged with the published public key is accepted. An
expiry is required.

**Users**

| Setting | Meaning |
| --- | --- |
| User Provisioning | Whether a login by someone without a Frappe account creates one. Follows the Sign-ups field of the Social Login Key by default, which is what Frappe's own social logins do; can be set to always or never create users. |
| User Type For New Users | The User Type new users are given, `Website User` by default. Frappe replaces either standard type on every save with one derived from the desk access of the user's roles (`User.set_system_user`), so on a site where System Users are billed seats, the role profiles you map are what decides the cost. A custom User Type is honoured as set. |

**Roles and modules**

Map a group to a Role Profile, and optionally to a Module Profile. Fallback profiles
apply when no mapped group matches.

Mappings carry a **Priority**, lowest number first. It decides which profile wins where
only one can be stored: the role profile on Frappe v15, and the module profile on every
version, since the User doctype holds a single one.

**When No Group Matches** decides what happens when the token carries no group that
matches a mapping and no fallback role profile is configured:

| Value | Meaning |
| --- | --- |
| Keep Existing Roles | The default. The user's roles and module profile are left as they are. |
| Remove All Roles | The roles and the module profile are stripped, so that removing someone from every group in the identity provider de-provisions them in Frappe. |
| Deny Login | The login is refused. |

#### How a login is handled

1. The `state` returned by the provider is consumed through Frappe's single-use token. An unknown, expired or already-used one is refused.
2. The authorization code is exchanged for tokens at the provider's token endpoint.
3. The id token is verified: signature, audience, issuer and expiry.
4. The Frappe user is resolved - by social login userid first, so an address changed at the identity provider keeps the account; then by email address, lowercased, which is what Frappe names User records by; then by `username`, for users provisioned by earlier versions of this app.
5. `Administrator` and `Guest` can never be logged into this way, and a disabled user is refused.
6. Role profiles and the module profile are assigned from the groups in the token.
7. If the assignment changed, the user's permission cache is cleared and their other sessions are ended, so a reduced set of roles takes effect immediately rather than at the next session.

#### Starting a login from the identity provider

Frappe renders the authorize URL only into its own login page, so there is no address an
application tile in the identity provider can point at. This app adds one:

```
https://erp.example.com/api/method/oidc_extended.callback.start/<provider name>
```

It accepts an optional `redirect_to` parameter for where the user should land once
logged in, restricted to this site. Unknown and disabled providers are refused.

#### Upgrading

- Mappings are to **Role Profiles** and **Module Profiles**, not to individual roles and modules. Versions that mapped individual roles need their mappings recreated with profiles.
- Users are matched by social login userid, then email address, then `username`. Versions that matched by `username` alone found nobody on a site whose users predate the app, and then failed trying to create a user whose email address was taken.
- Id token verification is on after upgrading. A provider whose JWKS endpoint cannot be discovered will refuse logins until the JWKS URL is filled in.
- Existing configurations keep creating users automatically: a patch sets their User Provisioning to "Always Create Users", which is what they did before the setting existed. Configurations created afterwards follow the Social Login Key.

#### Tests

The tests run without a bench, against a stand-in for the parts of Frappe the callback
uses, from the repository root:

```bash
python -m unittest discover -s tests -t .
```

#### License

MIT
