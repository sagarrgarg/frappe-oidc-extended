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

#### Installing on a bench that already has the app

`bench get-app` clones into `apps/` and collides if a copy is already there - a bench
that was used to develop the app, for instance. Check `apps/oidc_extended` first and, if
it is present, skip straight to installing it:

```bash
bench --site <site> install-app oidc_extended
bench --site <site> migrate
```

Being in `apps/` is not the same as being installed: the app also has to be in the
site's installed apps and pip-installed into `env`. `bench install-app` does both.

**Restart the workers afterwards.** A web worker started before the app was
pip-installed cannot import it, and answers every request to the callback with
`ModuleNotFoundError: No module named 'oidc_extended'` until it is restarted -
`bench restart`, or restarting the container in a containerised bench.

#### If the identity provider rejects the redirect URI

A redirect URI carrying the webserver port - `https://erp.example.com:8000/api/method/...`
- is refused by every provider, because it is not the URI registered with them.

The port comes from Frappe, not from this app. `frappe.utils.get_url` appends
`webserver_port` unless the bench configuration sets `restart_supervisor_on_update` or
`restart_systemd_on_update`, so a bench with both `false` advertises the development
port on a production site. Either set one of those flags in
`sites/common_site_config.json`, or pin the URI for the provider in the site's
`site_config.json`:

```json
{
  "keycloak_login": {
    "redirect_uri": "https://erp.example.com/api/method/oidc_extended.callback.custom/keycloak"
  }
}
```

The app logs a warning naming both remedies whenever the URI it is about to present
carries a port, so this shows up in the log rather than as an opaque refusal from the
provider.

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
| Require A Verified Email Address | On by default. Refuses a login the provider marks as having an unverified address. Users are matched to Frappe accounts by email, so an unverified address is a way into whoever owns that address here. Providers that do not send the claim are unaffected. |
| Match Users By Username | Off by default. Adds a last-resort match against a Frappe user whose `username` equals the provider's user id claim, for users provisioned by older versions of this app. The claim is not a Frappe username, so this can match an unrelated account carrying that name. |

A user's first and last name follow the claims on each login, when the provider sends
them. A claim the provider omits leaves the name on record alone.

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
4. An address the provider marks as unverified is refused, unless that requirement is turned off.
5. The Frappe user is resolved - by social login userid first, so an address changed at the identity provider keeps the account; then by email address, lowercased, which is what Frappe names User records by; and, if asked for, by `username`, for users provisioned by earlier versions of this app.
6. `Administrator` and `Guest` can never be logged into this way, and a disabled user is refused.
7. Role profiles and the module profile are assigned from the groups in the token, and the name is brought in step with the claims.
8. If the assignment changed, the user's permission cache is cleared and their other sessions are ended, so a reduced set of roles takes effect immediately rather than at the next session.

All three endpoints are rate limited per IP. The limits are generous on purpose - an
office arrives at one NAT address, and revoking every session at the provider sends one
logout token per user at once - so they bound abuse without policing normal use.

#### Starting a login from the identity provider

Frappe renders the authorize URL only into its own login page, so there is no address an
application tile in the identity provider can point at. This app adds one:

```
https://erp.example.com/api/method/oidc_extended.callback.start/<provider name>
```

It accepts an optional `redirect_to` parameter for where the user should land once
logged in, restricted to this site. Unknown and disabled providers are refused.

#### Ending sessions when the identity provider does

A Frappe session is a cookie backed by Frappe's own session record. Nothing about the
identity provider is consulted after the login completes, and the session lives until it
idles out - `session_expiry` in System Settings, ten days by default. So a user logged
out, deactivated or deleted at the identity provider keeps working here until then.

This app answers OpenID Connect back-channel logout, which closes that gap:

```
https://erp.example.com/api/method/oidc_extended.callback.backchannel_logout/<provider name>
```

Configure that as the provider's Logout URI with the back-channel method. authentik
supports this from version 2025.10; it posts a signed logout token when a session ends -
a user logging out, an administrator deleting a session, an account being deactivated or
deleted - and every Frappe session of that user is ended at once.

The logout token is verified the same way the id token is: signature against the
provider's keys, audience against the client id, issuer against the configured one. It
must carry the back-channel logout event, must not carry a nonce, must be recent, and
its `jti` is remembered so that a token cannot be replayed. If **Verify ID Token
Signature** is off for the provider, back-channel logout is refused rather than trusted -
the signature is the only thing that says the request came from the provider.

Two things to know:

- Every session of the user is ended, not only the one named by the `sid` claim. This app does not record which Frappe session belongs to which session at the provider, and the reason to act on a logout is usually that access has been withdrawn.
- The identity provider must be able to reach the site: this is a server to server request, so a site behind a VPN or an IP allowlist needs a path opened.

Note what this does *not* cover. Removing a user from a group is not a session event, so
no logout token is sent - the change applies at their next login, when role profiles are
re-applied and sessions are cleared if the assignment changed. Immediate handling of an
entitlement change needs either a notification rule at the provider or a scheduled
reconciliation.

#### Removing someone

Three things have to happen when a person leaves, and OpenID Connect only carries one
of them.

| What | How |
| --- | --- |
| Their sessions end | Back-channel logout, immediately |
| They cannot sign in again | The identity provider refuses them |
| Their Frappe account stops being a provisioned account | **Reconciliation** |

Without the third, a departed user keeps an enabled Frappe account with every role it
was given: a seat on a site that bills them, a valid assignee, a member of workflows,
and whatever local credentials that account has - a password, an API key - none of
which the identity provider can revoke. They are fully provisioned and merely cannot
use the front door.

Nothing pushes that fact. A logout token says a session ended, not why; no standard
signal carries "this person left" or "their entitlements shrank". So the app asks the
provider on a schedule, under **Reconciliation** on the configuration:

| Setting | Meaning |
| --- | --- |
| Enable Reconciliation | Off by default. When on, the provider is asked which users still exist, are still enabled, and are in which groups. |
| Frequency | Daily or hourly. The scheduler wakes hourly and skips providers that are not due. |
| When A User Is Gone Or Disabled | `Report Only` (log it), `Remove All Roles` (keep the account, strip entitlements), or `Disable User`. |
| Directory Type / URL | `Keycloak` with the realm URL, or `Authentik` with its base URL. |
| Service Account Client ID / Secret | Keycloak: a client with client authentication and service account roles on, whose service account holds `view-users` from realm-management. |
| API Token | authentik: an API token. authentik users are matched by email, since what it puts in `sub` depends on the provider's subject mode. |

**For a change to land at once rather than at the next run**, Keycloak can call the
webhook endpoint:

```
https://erp.example.com/api/method/oidc_extended.reconciliation.webhook/<provider name>
```

Keycloak has no webhook of its own - it has an event listener SPI, and community
providers built on it (p2-inc/keycloak-events, vymalo/keycloak-webhook and others) send
admin events over HTTP once their JAR is deployed into the server. Point one at that URL
for `USER` and `GROUP_MEMBERSHIP` admin events. On a managed Keycloak such as the one
inside Nubus, check first that a provider JAR survives app updates.

Nothing in the body is trusted beyond an identifier: whatever user id or email address
the payload names is looked up in the directory through the admin API, and what the
directory says is what gets applied. A forged call can at most ask for a user to be
re-checked against the truth. The call must present the **Webhook Secret** as a bearer
token or sign the body with it (HMAC-SHA256, `X-Hub-Signature-256`); without a secret
configured the endpoint is closed. A payload naming a user this site does not have is
answered exactly like one that does, so the endpoint cannot be used to find out who is
here.

Group changes are applied the same way, which is what closes the other half of the gap:
a user removed from a mapped group has their role profiles recomputed and their
sessions ended, without waiting for a login that may never come.

**Run it as a dry run first.** From the console or a client:

```python
frappe.call("oidc_extended.reconciliation.reconcile", provider="keycloak", dry_run=1)
```

It returns what it would do - which users are absent, which are disabled at the
provider, whose roles would change and to what - and writes nothing.

Three things it refuses to do, because a de-provisioning job that misfires is worse
than one that does not run:

- act on an empty directory response, which is a broken API call far more often than an empty directory;
- act when more than half the linked users appear to be missing or disabled, which reads like a partial answer;
- touch `Administrator`, `Guest`, or any user who has never signed in through this provider - the last of these has nothing tying it to a directory entry, so it is not the app's to judge.

#### Upgrading

- Mappings are to **Role Profiles** and **Module Profiles**, not to individual roles and modules. Versions that mapped individual roles need their mappings recreated with profiles.
- Users are matched by social login userid, then email address, then `username`. Versions that matched by `username` alone found nobody on a site whose users predate the app, and then failed trying to create a user whose email address was taken.
- Id token verification is on after upgrading. A provider whose JWKS endpoint cannot be discovered will refuse logins until the JWKS URL is filled in.
- Existing configurations keep creating users automatically: a patch sets their User Provisioning to "Always Create Users", which is what they did before the setting existed. Configurations created afterwards follow the Social Login Key.
- Existing configurations also keep matching users by `username`: a patch turns Match Users By Username on for them, since that leg used to be unconditional. It is off for configurations created afterwards.
- Logins the provider marks as having an unverified email address are refused from this release on. Turn Require A Verified Email Address off if your provider sends the claim but does not maintain it.

#### Tests

The tests run without a bench, against a stand-in for the parts of Frappe the callback
uses, from the repository root:

```bash
python -m unittest discover -s tests -t .
```

#### License

MIT
