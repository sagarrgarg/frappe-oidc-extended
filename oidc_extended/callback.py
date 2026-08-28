# Readings:
# - https://github.com/frappe/frappe/blob/828490e01a3d14e1b0ac3385ea196c72ab2cc950/frappe/integrations/oauth2_logins.py
# - https://github.com/frappe/frappe/blob/828490e01a3d14e1b0ac3385ea196c72ab2cc950/frappe/utils/oauth.py
# - https://github.com/castlecraft/microsoft_integration/blob/main/microsoft_integration/callback.py

import json
import time
from urllib.parse import urlparse

import requests
import jwt

import frappe
import frappe.utils
from frappe import _ # For translations
from frappe.utils import escape_html


# Frappe replaced the base64 state blob with a single-use token in v15.116.0 and
# v16.30.0. Both helpers below arrived with (or before) that change, so their absence
# is how this app detects a Frappe it cannot safely run on - importing them
# unguarded would turn that into an ImportError on every request instead.
try:
    from frappe.utils.oauth import build_oauth_url, consume_oauth_state, get_redirect_uri
except ImportError:
    build_oauth_url = consume_oauth_state = get_redirect_uri = None

from frappe.integrations.doctype.social_login_key.social_login_key import provider_allows_signup
from frappe.sessions import clear_sessions
from frappe.rate_limiter import rate_limit

# This module deliberately does not call frappe.utils.logger.set_log_level(): it sets
# frappe.log_level and clears frappe.loggers for the whole worker process, so importing
# this app would reconfigure logging for every app on the site. Set the level per site.

# The releases that carry frappe.utils.oauth.consume_oauth_state.
MINIMUM_FRAPPE_VERSIONS = "15.116.0 (v15) or 16.30.0 (v16)"

# Values of the "When No Group Matches" setting on OIDC Extended Configuration.
KEEP_EXISTING_ROLES = "Keep Existing Roles"
REMOVE_ALL_ROLES = "Remove All Roles"
DENY_LOGIN = "Deny Login"

# Frappe's built-in accounts, which must never be taken over by a login from an
# identity provider (see frappe.core.doctype.user.user.STANDARD_USERS).
RESERVED_USERS = ("Administrator", "Guest")

# The role without which nobody can administer the site. The last enabled account
# holding it is never disabled, whatever the identity provider says about its groups.
SYSTEM_MANAGER_ROLE = "System Manager"

# Values of the "User Provisioning" setting on OIDC Extended Configuration.
USE_SOCIAL_LOGIN_KEY_SETTING = "Use Social Login Key Setting"
ALWAYS_CREATE_USERS = "Always Create Users"
NEVER_CREATE_USERS = "Never Create Users"

# Asymmetric algorithms only: an id token is verified against the provider's published
# keys, and "none" or an unexpected HMAC would let the caller pick the key.
DEFAULT_SIGNING_ALGORITHMS = ("RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512")

# The discovery document rarely changes and is read on every login.
OPENID_CONFIGURATION_CACHE_TTL = 24 * 60 * 60

# PyJWKClient keeps the fetched keys in memory, so it is worth reusing per worker.
jwk_clients: dict = {}

# Rate limits, per IP per minute. Deliberately generous: they are there to stop an
# unauthenticated caller hammering endpoints that verify signatures, not to police
# normal use. A whole office arrives at one NAT address, so a tight limit on the login
# endpoints would lock everyone out at nine in the morning; and revoking every session
# at the identity provider sends one logout token per user, all at once.
LOGIN_RATE_LIMIT = 120
LOGOUT_RATE_LIMIT = 600
RATE_LIMIT_WINDOW = 60

# OpenID Connect Back-Channel Logout 1.0.
BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# A logout token is delivered server to server and acted on at once, so it has no
# business being old. Tokens outside this window are refused, and their identifiers are
# remembered for as long as one could still be replayed.
LOGOUT_TOKEN_MAX_AGE = 10 * 60
LOGOUT_TOKEN_CLOCK_SKEW = 2 * 60
LOGOUT_TOKEN_REPLAY_TTL = LOGOUT_TOKEN_MAX_AGE + LOGOUT_TOKEN_CLOCK_SKEW

def frappe_is_supported() -> bool:
    """Whether this Frappe carries the OAuth helpers the callback is built on.

    Frappe 15.116.0 and 16.30.0 replaced the base64 `state` blob, which nothing ever
    validated, with a single-use token held in Redis. Everything older sends the old
    format and has no way to validate it, so this app refuses to run there rather than
    reintroducing a `state` that is accepted without being checked.
    """
    return consume_oauth_state is not None


def respond_unsupported_frappe():
    frappe.logger().error(
        f"oidc_extended requires Frappe {MINIMUM_FRAPPE_VERSIONS} or newer; "
        f"this site runs {frappe.__version__}."
    )
    frappe.respond_as_web_page(
        _("Not Supported"),
        _("This site runs Frappe {0}. OIDC Extended requires {1} or newer.").format(
            frappe.__version__, MINIMUM_FRAPPE_VERSIONS
        ),
        http_status_code=501,
        indicator_color="red",
        success=False,
    )


@frappe.whitelist(allow_guest=True)
@rate_limit(limit=LOGIN_RATE_LIMIT, seconds=RATE_LIMIT_WINDOW)
def start(provider: str | None = None, redirect_to: str | None = None):
    """Begins a login with the given provider.

    URL: /api/method/oidc_extended.callback.start/<provider name>

    Frappe has no whitelisted endpoint that starts a social login: the authorize URL
    is only ever rendered into the login page, so a link that should take someone
    straight to the identity provider - an application tile in the provider's own
    dashboard, for instance - has nowhere to point. This is that entry point. It
    builds the same authorize URL the login page would, which means the single-use
    state that `custom` consumes is created here as well.
    """
    from frappe.utils.oauth import get_oauth2_authorize_url
    from frappe.www.login import sanitize_redirect

    if not frappe_is_supported():
        respond_unsupported_frappe()
        return

    if not provider:
        request_path_components = frappe.request.path[1:].split("/")

        if len(request_path_components) == 4 and request_path_components[3]:
            provider = request_path_components[3]

    if not provider or not frappe.db.exists("Social Login Key", provider):
        frappe.respond_as_web_page(
            _("Unknown Provider"),
            _("There is no Social Login Key named {0} on this site.").format(escape_html(str(provider))),
            http_status_code=404,
            indicator_color="red",
            success=False,
        )
        return

    # get_oauth2_providers() lists every Social Login Key, disabled ones included, so
    # this has to be checked here rather than left to the authorize URL to fail on.
    if not frappe.db.get_value("Social Login Key", provider, "enable_social_login"):
        frappe.respond_as_web_page(
            _("Not Allowed"),
            _("Login through {0} is disabled on this site.").format(escape_html(str(provider))),
            http_status_code=403,
            indicator_color="orange",
            success=False,
        )
        return

    frappe.local.response["type"] = "redirect"
    # sanitize_redirect keeps `redirect_to` on this site: it is a parameter of a
    # guest-facing URL that decides where the user lands once they are logged in.
    frappe.local.response["location"] = get_oauth2_authorize_url(provider, sanitize_redirect(redirect_to))


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=LOGOUT_RATE_LIMIT, seconds=RATE_LIMIT_WINDOW)
def backchannel_logout(logout_token: str | None = None):
    """Ends the Frappe sessions of a user the identity provider has logged out.

    URL: /api/method/oidc_extended.callback.backchannel_logout/<provider name>

    Configure that URL as the provider's Logout URI, with the back-channel method. The
    identity provider posts a signed logout token when a session ends there - a user
    logging out, an administrator deleting a session, an account being deactivated or
    deleted - and this ends the matching sessions here. Without it a Frappe session
    outlives everything that happens at the provider, because Frappe's session is a
    cookie backed by its own record and nothing about the provider is consulted again
    once the login is done.

    Every session of the user is ended, not only the one named by the `sid` claim: the
    reason this exists is that access has been withdrawn, and this app does not record
    which Frappe session belongs to which session at the provider.

    Answers 200 when there is nothing to do - an unknown subject is not an error, and
    saying so would tell an unauthenticated caller which subjects exist here.
    """
    try:
        request_path_components = frappe.request.path[1:].split("/")

        if not len(request_path_components) == 4 or not request_path_components[3]:
            raise LogoutTokenError("The logout URL is invalid.")

        provider_name = request_path_components[3]

        # One message for both: which providers exist, and which are half configured, is
        # not something an unauthenticated caller needs to learn.
        if not frappe.db.exists("Social Login Key", provider_name):
            frappe.logger().error(f"A back-channel logout named the unknown provider {provider_name}.")
            raise LogoutTokenError("Unknown provider.")

        if not frappe.db.exists("OIDC Extended Configuration", provider_name):
            frappe.logger().error(f"The provider {provider_name} has no OIDC Extended Configuration.")
            raise LogoutTokenError("Unknown provider.")

        social_login_provider = frappe.get_doc("Social Login Key", provider_name)
        oidc_extended_configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider_name)

        if not signature_verification_enabled(oidc_extended_configuration):
            # The token is the only thing that says this request came from the provider.
            # If signatures are not checked, anyone who can reach this endpoint could end
            # anyone's session, so the feature is refused rather than trusted blindly.
            frappe.logger().error(
                f"Refusing a back-channel logout for {provider_name}: id token signature "
                f"verification is turned off, so a logout token cannot be trusted."
            )
            raise LogoutTokenError("Token verification is disabled for this provider.")

        if not logout_token:
            raise LogoutTokenError("No logout_token was posted.")

        try:
            # A logout token carries iss, aud, iat, jti and a sub and/or sid; it has no
            # exp (Back-Channel Logout 1.0, 2.4), so freshness is checked separately.
            claims = verify_token(
                logout_token,
                social_login_provider,
                oidc_extended_configuration,
                require=("iss", "aud", "iat", "jti"),
                # PyJWT refuses a token issued in the future; allow for a provider whose
                # clock runs a little ahead of this server's.
                leeway=LOGOUT_TOKEN_CLOCK_SKEW,
            )
        except Exception as exception:
            frappe.logger().error(
                f"A logout token from {provider_name} could not be verified: "
                f"{type(exception).__name__}: {exception}"
            )
            raise LogoutTokenError("The logout token could not be verified.")

        validate_logout_claims(claims, provider_name)
    except LogoutTokenError as exception:
        return logout_error(str(exception))

    user_name = frappe.db.get_value(
        "User Social Login", {"provider": provider_name, "userid": claims.get("sub")}, "parent"
    )

    if user_name:
        frappe.logger().info(f"Ending the sessions of {user_name}: {provider_name} logged them out.")
        clear_sessions(user=user_name, force=True)
        frappe.clear_cache(user=user_name)
        frappe.db.commit()
    else:
        frappe.logger().info(
            f"A back-channel logout from {provider_name} named a subject with no user here."
        )

    # Only now: a token whose sessions could not be ended - a database error, say - must
    # stay usable, so that the provider's retry is not refused as a replay.
    remember_logout_token(provider_name, claims.get("jti"))


class LogoutTokenError(Exception):
    """A logout token that will not be acted on."""


def validate_logout_claims(claims: dict, provider_name: str):
    """Checks the claims a logout token must carry, raising on the first that fails."""
    events = claims.get("events")

    if not isinstance(events, dict) or BACKCHANNEL_LOGOUT_EVENT not in events:
        # Without this a token issued for another purpose - an id token, say - would be
        # accepted as a logout instruction (Back-Channel Logout 1.0, 2.6).
        raise LogoutTokenError("The token is not a back-channel logout token.")

    if "nonce" in claims:
        # A logout token must not carry a nonce; one that does is an id token replayed.
        raise LogoutTokenError("A logout token must not contain a nonce.")

    if not claims.get("sub"):
        # This app matches users by the subject; a token carrying only `sid` names a
        # session at the provider that was never recorded here.
        raise LogoutTokenError("The logout token has no sub claim.")

    # `iat` is seconds since the epoch in UTC. time.time() is the same scale;
    # frappe.utils.now_datetime() is the site's timezone and would be read back as the
    # server's, skewing this by the offset between them.
    age = time.time() - float(claims.get("iat"))

    if age > LOGOUT_TOKEN_MAX_AGE or age < -LOGOUT_TOKEN_CLOCK_SKEW:
        raise LogoutTokenError("The logout token is not fresh.")

    if frappe.cache.get_value(logout_token_key(provider_name, claims.get("jti"))):
        frappe.logger().warning(f"A logout token from {provider_name} was replayed.")
        raise LogoutTokenError("This logout token has already been used.")


def logout_token_key(provider_name: str, token_id: str) -> str:
    return f"oidc_extended|logout_token|{provider_name}|{token_id}"


def remember_logout_token(provider_name: str, token_id: str):
    """Records a logout token as used, for as long as one could still be replayed."""
    frappe.cache.set_value(
        logout_token_key(provider_name, token_id), 1, expires_in_sec=LOGOUT_TOKEN_REPLAY_TTL
    )


def logout_error(description: str):
    """The error body of a back-channel logout (Back-Channel Logout 1.0, 2.8).

    Written onto the response rather than returned, so that `error` and
    `error_description` are at the top level of the body instead of nested under the
    `message` key Frappe wraps a return value in.
    """
    frappe.local.response["http_status_code"] = 400
    frappe.local.response["error"] = "invalid_request"
    frappe.local.response["error_description"] = description


@frappe.whitelist(allow_guest=True)
@rate_limit(limit=LOGIN_RATE_LIMIT, seconds=RATE_LIMIT_WINDOW)
def custom(code: str | None = None, state: str | None = None, error: str | None = None, error_description: str | None = None):
    """Callback for processing the request received after a successful authentication in an identity provider (OIDC provider).

    OIDC redirect URL: /api/method/oidc_extended.callback.custom/<provider name>

    This extends the functionality of the current Social Login (OIDC) module. In addition to handling the authentication over OIDC, this:
    - Creates new user if does not exsit.
    - Maps groups from the claim of id token to ERPNext roles.

    `error` and `error_description` are the parameters an identity provider sends
    instead of `code` when it refuses the authorization (RFC 6749 4.1.2.1). They are
    accepted so that a refusal renders a page rather than a traceback about a missing
    argument.
    """

    if not frappe_is_supported():
        respond_unsupported_frappe()
        return

    # `state` is the single-use token Frappe generated when this login flow started
    # (see frappe.utils.oauth.create_oauth_state). Consuming it validates the callback
    # against CSRF/replay and yields the `redirect_to` recorded for that attempt.
    # A valid attempt without a redirect target returns an empty string, an unknown,
    # expired or already-used token returns None - so compare against None explicitly.
    redirect_to = consume_oauth_state(state)

    if redirect_to is None:
        frappe.respond_as_web_page(
            _("Invalid Request"),
            _("Your login attempt is invalid or has expired. Please try again."),
            http_status_code=417,
        )
        return

    if error:
        # The identity provider refused the authorization instead of issuing a code.
        frappe.logger().warning(f"The identity provider returned an error: {error} ({error_description})")
        frappe.respond_as_web_page(
            _("Login Failed"),
            _("The identity provider refused the login: {0}").format(escape_html(str(error_description or error))),
            http_status_code=400,
            indicator_color="red",
            success=False,
            primary_action="/login",
            primary_label="Go to Standard Login",
        )
        return

    if not code:
        frappe.respond_as_web_page(
            _("Invalid Request"),
            _("The identity provider did not return an authorization code."),
            http_status_code=400,
            indicator_color="red",
        )
        return

    request_path_components = frappe.request.path[1:].split("/")

    if not len(request_path_components) == 4 or not request_path_components[3]:
        frappe.respond_as_web_page(_("Invalid request"), _("The redirect URL is invalid."), http_status_code=417)
        return

    # Gets the name of the OIDC custom provider.
    provider_name = request_path_components[3]

    # Gets the document of the default Social Login (OIDC) configuration. The provider
    # name comes from the redirect URL, so it is checked rather than trusted.
    if not frappe.db.exists("Social Login Key", provider_name):
        frappe.logger().error(f"No Social Login Key named {provider_name} exists.")
        frappe.respond_as_web_page(
            _("Unknown Provider"),
            _("There is no Social Login Key named {0} on this site.").format(escape_html(str(provider_name))),
            http_status_code=404,
            indicator_color="red",
            success=False,
        )
        return

    social_login_provider = frappe.get_doc("Social Login Key", provider_name)

    if not social_login_provider.enable_social_login:
        frappe.logger().warning(f"The Social Login Key {provider_name} is disabled.")
        frappe.respond_as_web_page(
            _("Not Allowed"),
            _("Login through {0} is disabled on this site.").format(escape_html(str(provider_name))),
            http_status_code=403,
            indicator_color="orange",
            success=False,
        )
        return

    user_id_claim_name = social_login_provider.user_id_property or "sub"

    # Gets the document of the extended OIDC configuration.
    if not frappe.db.exists("OIDC Extended Configuration", provider_name):
        frappe.logger().error(f"No OIDC Extended Configuration exists for the provider {provider_name}.")
        frappe.respond_as_web_page(
            _("Not Configured"),
            _("The provider {0} has no OIDC Extended Configuration. Create one to map its groups to roles.").format(
                escape_html(str(provider_name))
            ),
            http_status_code=501,
            indicator_color="red",
            success=False,
        )
        return

    oidc_extended_configuration = frappe.get_cached_doc('OIDC Extended Configuration', provider_name)
    given_name_claim_name = oidc_extended_configuration.given_name_claim_name or "given_name"
    family_name_claim_name = oidc_extended_configuration.family_name_claim_name or "family_name"
    email_claim_name = oidc_extended_configuration.email_claim_name or "email"
    groups_claim_name = oidc_extended_configuration.groups_claim_name or "groups"

    # Requests token from token endpoint.
    encoded_id_token = request_id_token(social_login_provider, code)

    if encoded_id_token is None:
        # request_id_token has already answered the request.
        return

    id_token = decode_id_token(encoded_id_token, social_login_provider, oidc_extended_configuration)

    if id_token is None:
        # decode_id_token has already answered the request.
        return

    # Identifies the account at the identity provider. This value is stored as the
    # social login userid of the Frappe user and is what later logins match on, so it
    # has to be the stable, non-reassignable claim ("sub" unless configured otherwise).
    user_id = id_token.get(user_id_claim_name)

    if not user_id:
        frappe.logger().error(f"The id token has no {user_id_claim_name} claim: {sorted(id_token)}")
        frappe.respond_as_web_page(
            _("Missing User ID"),
            _("The identity provider did not return the {0} claim, which identifies the user.").format(
                escape_html(str(user_id_claim_name))
            ),
            http_status_code=400,
            indicator_color="red",
        )
        return

    # Frappe stores and names users by a lowercase email address.
    email = (id_token.get(email_claim_name) or "").strip().lower()

    if not email:
        frappe.respond_as_web_page(
            _("Missing Email"),
            _("The identity provider did not return an email address. An email address is required to log in."),
            http_status_code=400,
            indicator_color="red",
        )
        return

    if not email_is_acceptable(id_token, oidc_extended_configuration):
        frappe.logger().warning(
            f"Refusing the login for {email}: {provider_name} reports the address as unverified."
        )
        frappe.respond_as_web_page(
            _("Email Not Verified"),
            _("The identity provider has not verified your email address."),
            http_status_code=403,
            indicator_color="red",
            success=False,
        )
        return

    first_name = id_token.get(given_name_claim_name)
    last_name = id_token.get(family_name_claim_name)
    # The groups the user have as received in the token.
    groups = normalize_groups(id_token.get(groups_claim_name))
    frappe.logger().debug(f"Groups of user {email}: {groups}")

    frappe.logger().debug(f"Current session user: {frappe.session.user}")

    # Creates the user if does not exsit, otherwise updates the data according to the claims of the token.
    existing_user_name = find_existing_user(
        provider_name,
        user_id,
        email,
        match_by_username=frappe.utils.cint(oidc_extended_configuration.get("match_users_by_username")),
    )
    if existing_user_name:
        frappe.logger().info(f"The login for {email} matched the existing user {existing_user_name}.")

        # Prevents login with the "Administrator" user via OIDC.
        # Reason: If an OIDC provider returns groups that don't map to all
        # necessary admin roles, or if the mapping is not configured properly,
        # the role synchronization logic below would strip critical permissions
        # from this account, potentially locking administrators out of the system.
        # To prevent accidental privilege issues, the Administrator must only
        # authenticate through the local ERPNext login mechanism where roles are
        # managed directly.
        if existing_user_name in RESERVED_USERS:
            frappe.logger().warning(f"Attempted OIDC login with the {existing_user_name} account.")
            frappe.respond_as_web_page(
                _("Not Allowed"),
                _("Login via OIDC is not permitted for the Administrator account. Please use the standard ERPNext login page."),
                http_status_code=403,
                indicator_color="orange",
                success=False,
                primary_action="/login",  # URL for primary action button
                primary_label="Go to Standard Login",  # Label for primary action button
            )
            return

        try:
            # Fetches the existing user.
            user = frappe.get_doc("User", existing_user_name)
        except Exception as e:
            frappe.logger().error(f"Error fetching user: {str(e)}")
            frappe.logger().exception(e)
            raise

        if (user.email or "").lower() != email:
            # User records are named by email and Frappe resets `email` to the record
            # name on save (User.validate), so an address changed at the identity
            # provider cannot be mirrored here without renaming the record.
            frappe.logger().warning(
                f"The identity provider reports {email} for the user {existing_user_name}, "
                f"whose address in Frappe is {user.email}. Keeping the address on record."
            )

        update_user_names(user, first_name, last_name)

        frappe.logger().info(
            f"The existing user {existing_user_name} was fetched: enabled={user.enabled}, "
            f"user type {user.user_type}."
        )
    else:
        if not may_create_user(provider_name, oidc_extended_configuration):
            frappe.logger().warning(
                f"Refusing to create a Frappe user for {email}: user provisioning is not "
                f"allowed for the provider {provider_name}."
            )
            frappe.respond_as_web_page(
                _("Signup is Disabled"),
                _("You do not have an account on this site, and accounts are not created automatically."),
                http_status_code=403,
                indicator_color="red",
                success=False,
            )
            return

        # Creates a new user. `username` is deliberately left to Frappe: it derives one
        # and blanks it on collision (User.validate_username), so it cannot be relied
        # on as an identifier.
        frappe.logger().info(f"Creating a new Frappe user: {email}")

        user = frappe.get_doc(
            {
                "doctype": "User",
                "first_name": first_name or "No first name",
                "last_name": last_name or "No last name",
                "email": email,
                "send_welcome_email": 0,
                "enabled": 1,
                "new_password": frappe.generate_hash(),
                # Frappe replaces a standard user type on save with one derived from the
                # desk access of the user's roles, so this is the value that applies to
                # a user without desk roles - and the one that a custom User Type keeps.
                "user_type": oidc_extended_configuration.get("new_user_type") or "Website User",
            }
        )

        frappe.logger().info(f"New Frappe user {email} created successfully.")

        # Allows making changes on the user (like adding roles) by guest user.
        user.flags.ignore_permissions = True


    # With "Disable Users With No Mapped Group" on the enabled flag is the identity
    # provider's to set, so the decision waits until the groups have been read: someone
    # this app disabled when their group went away is enabled again when it returns.
    if not user.enabled and not disabling_unmapped_users(oidc_extended_configuration):
        frappe.logger().info(f"The user {user.name} is disabled.")
        frappe.respond_as_web_page(_("Not Allowed"), _("User {0} is disabled").format(escape_html(str(user.name))))
        return False

    record_social_login_userid(user, provider_name, user_id)

    # Allows all changes on the user in this code without checking if the operation is permitted to be done by the current user.
    frappe.logger().info(f"Allowing all changes on the user {email} without checking permissions.")
    user.flags.ignore_permissions = True

    if managing_roles(oidc_extended_configuration):
        refused, entitlements_changed = apply_entitlements(
            user, existing_user_name, oidc_extended_configuration, groups, email
        )

        if refused:
            return
    else:
        # Sign-in and offboarding only: the ERP decides who has which roles, and this
        # app is not asked to have an opinion. Note that the roles are not merely left
        # unchanged - they are never read.
        frappe.logger().info(
            f"Not managing the roles of {email}: {provider_name} is configured for sign-in "
            f"only, so whatever roles this site has given them stand."
        )
        entitlements_changed = False

    try:
        user.save()
    except frappe.DuplicateEntryError:
        # Two first logins for the same person at once: the other request inserted the
        # user between the lookup above and this save. Nothing here is lost - the next
        # attempt finds the user that won and carries on - so say so rather than
        # showing a traceback.
        frappe.logger().warning(f"The user {email} was created by another login in flight.")
        frappe.db.rollback()
        frappe.respond_as_web_page(
            _("Please Try Again"),
            _("Your account was being set up by another login. Please try again."),
            http_status_code=409,
            indicator_color="orange",
            success=False,
            primary_action="/login",
            primary_label="Try Again",
        )
        return

    if entitlements_changed:
        frappe.logger().info(
            f"The entitlements of {email} changed. Clearing active sessions to enforce the "
            f"new permissions instantly."
        )
        # The previous frappe.cache().hdel("sessions", ...) and hdel("bhas_role", ...) calls
        # cleared nothing: Frappe keeps sessions in a hash named "session" keyed by sid, not
        # by user, and no cache named "bhas_role" exists. A user whose roles were reduced
        # kept the old ones in every browser tab they already had open.
        frappe.clear_cache(user=user.name)
        # keep_current: the current session is still the guest one that is about to be
        # replaced by post_login below. force: ignore the simultaneous session allowance.
        clear_sessions(user=user.name, keep_current=True, force=True)

    frappe.local.login_manager.user = user.name
    frappe.local.login_manager.post_login()

    frappe.db.commit()

    redirect_post_login(
        desk_user=frappe.local.response.get("message") == "Logged In",
        redirect_to=redirect_to or None
    )

def redirect_uri_for(provider_name: str) -> str:
    """The redirect URI to present at the token endpoint.

    Built with Frappe's own `get_redirect_uri`, which is what produced the value sent
    in the authorization request - the two must be identical or the provider refuses
    the exchange (RFC 6749 4.1.3). It also honours a `redirect_uri` under
    `<provider>_login` in site_config.json, which is the way out when the URL Frappe
    derives is not the one the provider knows.

    That happens more easily than it looks: `frappe.utils.get_url` appends the
    webserver port to the site URL unless the bench sets `restart_supervisor_on_update`
    or `restart_systemd_on_update` (frappe/utils/data.py), so a bench with both off
    produces "https://erp.example.com:8000/..." and every provider rejects it.
    """
    redirect_uri = get_redirect_uri(provider_name)
    parsed = urlparse(redirect_uri)

    if parsed.port and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        frappe.logger().warning(
            f"The redirect URI for {provider_name} carries a port: {redirect_uri}. Identity "
            f"providers match this against the URI registered with them, so unless that one "
            f"carries the port too, the token exchange will be refused. Frappe adds it when "
            f"neither restart_supervisor_on_update nor restart_systemd_on_update is set in "
            f"the bench configuration; setting either, or a redirect_uri under "
            f"{provider_name}_login in site_config.json, removes it."
        )

    return redirect_uri


def request_id_token(social_login_provider, code: str) -> str | None:
    """Exchanges the authorization code for the id token of the token response.

    Returns None, after answering the request, when the token endpoint cannot be
    reached, refuses the exchange or returns no id token. Reading the response
    unconditionally as `token_response["id_token"]` turned every one of those into a
    traceback on a guest-facing page.
    """
    url = build_oauth_url(social_login_provider.base_url, social_login_provider.access_token_url)

    try:
        auth_url_data = json.loads(social_login_provider.auth_url_data or "{}")
    except ValueError:
        frappe.logger().error(
            f"The auth_url_data of {social_login_provider.name} is not valid JSON; "
            f"continuing without the scope it would have carried."
        )
        auth_url_data = {}

    token_request_data = {
        "grant_type": "authorization_code",
        "client_id": social_login_provider.client_id,
        "client_secret": social_login_provider.get_password("client_secret"),
        "scope": auth_url_data.get("scope"),
        "code": code,
        "redirect_uri": redirect_uri_for(social_login_provider.name),
    }

    try:
        response = requests.post(url=url, data=token_request_data, timeout=30)
        token_response = response.json()
    except Exception as exception:
        frappe.logger().error(f"The token endpoint {url} could not be reached: {exception}")
        frappe.respond_as_web_page(
            _("Login Failed"),
            _("The identity provider could not be reached. Please try again."),
            http_status_code=502,
            indicator_color="red",
            success=False,
        )
        return None

    if not isinstance(token_response, dict) or not token_response.get("id_token"):
        # The error fields of a failed exchange are defined in RFC 6749 5.2, and are
        # what tells a misconfigured client id or redirect URI from a network problem.
        error = ""
        if isinstance(token_response, dict):
            error = f"{token_response.get('error')}: {token_response.get('error_description')}"

        frappe.logger().error(f"The token endpoint {url} returned no id token. {error}")
        frappe.respond_as_web_page(
            _("Login Failed"),
            _("The identity provider did not return an id token. Please try again."),
            http_status_code=502,
            indicator_color="red",
            success=False,
        )
        return None

    return token_response["id_token"]


def may_create_user(provider_name: str, configuration) -> bool:
    """Whether a login by someone without a Frappe account may create one.

    This app used to provision users unconditionally, which is defensible when the
    identity provider decides who may reach the callback at all, but it silently
    ignored the Sign-ups field of the Social Login Key and the site's website signup
    setting that Frappe's own social logins honour. It is now a deliberate choice.
    """
    provisioning = configuration.get("user_provisioning") or USE_SOCIAL_LOGIN_KEY_SETTING

    if provisioning == ALWAYS_CREATE_USERS:
        return True

    if provisioning == NEVER_CREATE_USERS:
        return False

    return bool(provider_allows_signup(provider_name))


def get_openid_configuration(social_login_provider, configuration) -> dict:
    """The provider's OpenID discovery document, cached for a day.

    Read from the configured issuer, falling back to the base URL of the Social Login
    Key. Returns an empty dict when the document cannot be read, so that an explicitly
    configured JWKS URL still works without it.
    """
    issuer = (configuration.get("issuer") or social_login_provider.base_url or "").rstrip("/")

    if not issuer:
        return {}

    url = f"{issuer}/.well-known/openid-configuration"
    cache_key = f"oidc_extended|openid_configuration|{url}"
    cached = frappe.cache.get_value(cache_key)

    if cached:
        return cached

    try:
        document = requests.get(url, timeout=10).json()
    except Exception as exception:
        frappe.logger().error(f"Could not read the OpenID configuration from {url}: {exception}")
        return {}

    frappe.cache.set_value(cache_key, document, expires_in_sec=OPENID_CONFIGURATION_CACHE_TTL)
    return document


def get_jwk_client(jwks_url: str):
    """A PyJWKClient for the given JWKS endpoint, reused across logins."""
    if jwks_url not in jwk_clients:
        jwk_clients[jwks_url] = jwt.PyJWKClient(jwks_url, cache_keys=True)

    return jwk_clients[jwks_url]


def get_signing_algorithms(openid_configuration: dict) -> list[str]:
    """The signing algorithms the provider advertises, minus the unsafe ones."""
    advertised = openid_configuration.get("id_token_signing_alg_values_supported") or []
    supported = [alg for alg in advertised if alg in DEFAULT_SIGNING_ALGORITHMS]

    return supported or list(DEFAULT_SIGNING_ALGORITHMS)


def signature_verification_enabled(configuration) -> bool:
    """Whether tokens from this provider are verified. On unless explicitly turned off."""
    verify_signature = configuration.get("verify_id_token_signature")

    if verify_signature is None:
        verify_signature = 1

    return bool(frappe.utils.cint(verify_signature))


def verify_token(encoded_token: str, social_login_provider, configuration, require=("exp",), leeway: int = 0) -> dict:
    """Verifies a token from the identity provider and returns its claims.

    The signature is checked against the keys the provider publishes, the audience
    against the client id of this Social Login Key and, when an issuer is known, the
    "iss" claim against it. Raises if any of that fails - callers decide how to answer,
    since an id token arrives in a browser and a logout token arrives from a server.

    Providers that sign symmetrically (an "HS*" algorithm) are verified against the
    client secret, which is the shared key in that case.
    """
    openid_configuration = get_openid_configuration(social_login_provider, configuration)
    issuer = configuration.get("issuer") or openid_configuration.get("issuer")
    algorithm = jwt.get_unverified_header(encoded_token).get("alg") or ""

    if not issuer:
        frappe.logger().warning(
            f"No issuer is configured for {social_login_provider.name} and none could be read "
            f"from its OpenID configuration, so the iss claim of its tokens is not checked."
        )

    if algorithm.startswith("HS"):
        # OpenID Connect Core 15.1: symmetric signatures use the client secret. The
        # algorithm comes from the token's own header, so it is only honoured when the
        # provider says it signs that way - otherwise a token signed with a leaked
        # client secret would be accepted by a provider that only ever signs
        # asymmetrically.
        advertised = openid_configuration.get("id_token_signing_alg_values_supported")

        if advertised and algorithm not in advertised:
            raise ValueError(
                f"{social_login_provider.name} does not advertise {algorithm}; it signs with "
                f"{advertised}."
            )

        key = social_login_provider.get_password("client_secret")
        algorithms = [algorithm]
    else:
        jwks_url = configuration.get("jwks_url") or openid_configuration.get("jwks_uri")

        if not jwks_url:
            raise ValueError(
                "No JWKS URL is configured for this provider and none could be read from "
                f"its OpenID configuration at {issuer or social_login_provider.base_url}."
            )

        key = get_jwk_client(jwks_url).get_signing_key_from_jwt(encoded_token).key
        algorithms = get_signing_algorithms(openid_configuration)

    claims = jwt.decode(
        encoded_token,
        key=key,
        algorithms=algorithms,
        audience=social_login_provider.client_id,
        issuer=issuer or None,
        leeway=leeway,
        options={"require": list(require)},
    )

    validate_authorized_party(claims, social_login_provider.client_id)

    return claims


def validate_authorized_party(claims: dict, client_id: str):
    """Checks "azp" when the token names more than one audience.

    A token whose "aud" is a list is accepted by the audience check as long as this
    client is somewhere in it, so a token minted for a different client of the same
    provider would otherwise pass. OpenID Connect Core 3.1.3.7 requires "azp" to name
    the party the token was issued to, and to be present when there are several
    audiences.
    """
    audience = claims.get("aud")
    authorized_party = claims.get("azp")

    if isinstance(audience, list | tuple) and len(audience) > 1 and not authorized_party:
        raise jwt.InvalidAudienceError("The token names several audiences but no azp.")

    if authorized_party and authorized_party != client_id:
        raise jwt.InvalidAudienceError(f"The token was issued to {authorized_party}, not to us.")


def validate_audience_without_signature(claims: dict, client_id: str):
    """The audience checks PyJWT skips when the signature is not verified."""
    audience = claims.get("aud")
    audiences = audience if isinstance(audience, list | tuple) else [audience]

    if client_id not in audiences:
        raise jwt.InvalidAudienceError(f"The token is addressed to {audience}, not to us.")

    validate_authorized_party(claims, client_id)


def decode_id_token(encoded_id_token: str, social_login_provider, configuration) -> dict | None:
    """Verifies the id token and returns its claims, or None if it cannot be trusted.

    A token that fails verification is answered with a 401 page and None is returned -
    the claims of an unverified token decide which roles the user gets, so they cannot
    be used.
    """
    if not signature_verification_enabled(configuration):
        frappe.logger().warning(
            "Signature verification of the id token is turned off for the provider "
            f"{social_login_provider.name}. The claims of this token, including the groups "
            "that decide the user's roles, are not authenticated."
        )
        claims = jwt.decode(
            encoded_id_token,
            audience=social_login_provider.client_id,
            options={"verify_signature": False, "verify_aud": False},
        )

        # Turning the signature off turns every other check off with it (PyJWT), so the
        # claims that need no key are checked here: an expired token or one addressed to
        # another client is wrong whether or not its signature was read.
        try:
            expiry = float(claims.get("exp") or 0)

            if not expiry or expiry < time.time():
                raise jwt.ExpiredSignatureError("The token has expired.")

            validate_audience_without_signature(claims, social_login_provider.client_id)
        except Exception as exception:
            frappe.logger().error(f"The id token was rejected: {exception}")
            frappe.respond_as_web_page(
                _("Invalid Token"),
                _("The identity provider returned a token that could not be verified. Please try again."),
                http_status_code=401,
                indicator_color="red",
                success=False,
            )
            return None

        return claims

    try:
        return verify_token(encoded_id_token, social_login_provider, configuration, require=("exp",))
    except Exception as exception:
        frappe.logger().error(
            f"The id token from {social_login_provider.name} could not be verified: "
            f"{type(exception).__name__}: {exception}"
        )
        frappe.respond_as_web_page(
            _("Invalid Token"),
            _("The identity provider returned a token that could not be verified. Please try again."),
            http_status_code=401,
            indicator_color="red",
            success=False,
        )
        return None


def email_is_acceptable(claims: dict, configuration) -> bool:
    """Whether the email address of these claims may be used to find a Frappe user.

    Users are matched by email address, so an address the identity provider has not
    verified is a way into whoever owns that address here. Providers that do not send
    the claim at all are unaffected - only an explicit "not verified" is refused.
    """
    require_verified = configuration.get("require_verified_email")

    if require_verified is None:
        require_verified = 1

    if not frappe.utils.cint(require_verified):
        return True

    verified = claims.get("email_verified")

    if verified is None:
        return True

    if isinstance(verified, str):
        # Some providers send the claim as a string rather than a boolean.
        return verified.strip().lower() in ("true", "1", "yes")

    return bool(verified)


def update_user_names(user, first_name: str | None, last_name: str | None):
    """Keeps the user's name in step with the claims, without inventing one.

    Only claims the provider actually sent are written: falling back to a placeholder
    here would overwrite a name someone maintains in Frappe with "No first name".
    """
    for fieldname, value in (("first_name", first_name), ("last_name", last_name)):
        value = (value or "").strip()

        if value and user.get(fieldname) != value:
            frappe.logger().info(
                f"Updating the {fieldname} of {user.name} from the claims of {value}."
            )
            user.set(fieldname, value)


def record_social_login_userid(user, provider_name: str, user_id: str):
    """Stores the provider's subject on the user, replacing a stale one.

    Frappe's `set_social_login_userid` appends a row unconditionally and
    `get_social_login_userid` returns the first row for the provider, so writing a new
    subject without removing the old one would leave the stale one in charge - and this
    is what later logins are matched on.
    """
    current = user.get_social_login_userid(provider_name)

    if current == user_id:
        return

    if current:
        frappe.logger().warning(
            f"The subject {provider_name} reports for {user.name} changed from {current} "
            f"to {user_id}; replacing the one on record."
        )
        user.set(
            "social_logins",
            [row for row in user.get("social_logins", []) if row.get("provider") != provider_name],
        )

    frappe.logger().debug(f"Recording the {provider_name} subject of {user.name}.")
    user.set_social_login_userid(provider_name, userid=user_id)


def find_existing_user(
    provider_name: str, user_id: str, email: str, match_by_username: bool = False
) -> str | None:
    """The name of the Frappe user this login belongs to, or None if there is none.

    The social login userid is matched first: it is the identity provider's stable
    subject, so a user whose email address changes there keeps their Frappe account.
    The email address is matched next, because Frappe names User records by it - and
    because a site that existed before this app was installed has users the identity
    provider has never seen. Matching on `username` instead, as this app did
    previously, matched nobody on such a site (the subject claim of an identity
    provider is not a Frappe username), and the "create a user" branch that followed
    then failed with a duplicate entry error on the email address.
    """
    if user_id:
        matched = frappe.db.get_value(
            "User Social Login", {"provider": provider_name, "userid": user_id}, "parent"
        )
        if matched:
            return matched

    if email:
        # Regular users are named by their email address.
        if frappe.db.exists("User", email):
            return email

        # Records whose name is not their email address - Administrator and Guest, or
        # a renamed user. `email` carries no unique constraint, so a lookup by name
        # alone would happily create a second account holding the same address.
        matched = frappe.db.exists("User", {"email": email})
        if matched:
            return matched

    if match_by_username:
        # Users provisioned by earlier versions of this app carry the subject in
        # `username`. Off by default: the subject claim is not a Frappe username, so a
        # provider configured to send `preferred_username` could match an unrelated
        # account that happens to carry that name.
        return frappe.db.exists("User", {"username": user_id}) or None

    return None


def normalize_groups(claim_value) -> list[str]:
    """Returns the groups claim as a list of exact group names.

    The claim is a JSON array for most identity providers, but some send a single
    string. Matching a mapping against a raw string with ``in`` would match on
    substrings - a mapping for "sales" would match the group "erp-sales-readonly" -
    so the value is turned into a list and compared exactly. A comma is treated as a
    separator, since group names may contain spaces but not commas.
    """
    if not claim_value:
        return []

    if isinstance(claim_value, str):
        parts = claim_value.split(",") if "," in claim_value else [claim_value]
        return [part.strip() for part in parts if part.strip()]

    if isinstance(claim_value, (list, tuple, set)):
        return [str(group).strip() for group in claim_value if str(group).strip()]

    return [str(claim_value).strip()]


def sort_by_priority(rows: list) -> list:
    """Orders mapping rows by their configured priority, lowest number first.

    Rows sharing a priority keep the order they have in the child table, so the
    result is deterministic even when a user matches several mapped groups.
    """
    return sorted(
        enumerate(rows), key=lambda pair: (int(pair[1].get("priority") or 0), pair[1].get("idx") or pair[0])
    )


def resolve_role_profiles(configuration, groups: list[str]) -> list[str]:
    """Role profiles for the given groups, in descending order of precedence.

    Falls back to the configured fallback role profiles when no group matches.
    Frappe versions that store a single role profile per user assign the first
    entry, so the order matters.

    A row whose role profile is still empty - which is how "Fetch Groups From
    Provider" leaves the rows it imports - is not a match. Counting it as one would
    make a half-filled table shadow the fallback profiles and, with unmapped users
    disabled, lock out the very people whose group was just imported.
    """
    matched = [
        row
        for row in configuration.get("group_role_mappings", [])
        if row.get("group") in groups and row.get("role_profile")
    ]

    if not matched:
        matched = [
            row for row in configuration.get("fallback_role_profiles", []) if row.get("role_profile")
        ]

    profiles = [row.get("role_profile") for _, row in sort_by_priority(matched)]

    # dict.fromkeys keeps the first occurrence of a profile mapped by several groups.
    return list(dict.fromkeys(profile for profile in profiles if profile))


def resolve_module_profile(configuration, groups: list[str]) -> str | None:
    """The module profile for the given groups, or the configured fallback.

    As with the role mappings, a row whose module profile is still empty is not a
    match: an imported group nobody has filled in yet says nothing about this user.
    """
    matched = [
        row
        for row in configuration.get("group_module_mappings", [])
        if row.get("group") in groups and row.get("module_profile")
    ]

    if matched:
        # The User doctype holds a single module profile, so the highest priority wins.
        return sort_by_priority(matched)[0][1].get("module_profile")

    return configuration.get("fallback_module_profile") or None


def resolve_roles(configuration, groups: list[str]) -> list[str]:
    """The roles granted directly by the given groups.

    Roles add up where profiles compete. A role profile is a single Link on Frappe
    v15, so two groups that both map to a profile can only ever produce one of them -
    which leaves nowhere to put "everything an accounts user has, and approval on top".
    Every row whose group the token carries grants its role, so that combination is
    just two rows.

    Rows whose role is still empty are skipped, as they are in the profile mappings:
    an imported group nobody has filled in yet grants nothing.
    """
    granted = [
        row.get("role")
        for row in configuration.get("group_role_grants", [])
        if row.get("group") in groups and row.get("role")
    ]

    return list(dict.fromkeys(granted))


def managed_roles(configuration) -> set[str]:
    """Every role this configuration claims, matched or not.

    This is what makes the grants revocable without them being destructive. A role
    named anywhere in the table is the identity provider's to give and to take away,
    and every other role on the user is somebody's deliberate decision here. Reconcile
    the whole role table instead and the choice is between never revoking anything and
    wiping every grant an administrator made by hand.
    """
    return {
        row.get("role")
        for row in configuration.get("group_role_grants", [])
        if row.get("role") and row.get("group")
    }


def role_profile_would_overwrite_grants(user) -> bool:
    """Whether Frappe will rewrite this user's role table from a role profile on save.

    `User.validate` calls `populate_role_profile_roles`, which empties the role table
    and refills it from the assigned profile whenever one is assigned - on every save,
    not only the first. So a role profile and a directly granted role cannot both be
    held. Frappe enforces that, not this app: a role added by hand in the user form
    disappears the same way.

    Which means the two mappings are alternatives, not layers. Map a group to a role
    profile or to roles; to express "everything an accounts user has, and approval on
    top" on Frappe v15, where only one profile can be assigned, use roles for both.
    """
    return bool(user.get("role_profile_name") or user.get("role_profiles"))


def role_grants_target(user, granted: list[str], managed: set[str]) -> list[str]:
    """The roles the user should end up holding: (current - managed) | granted.

    Their current roles, unchanged, when a role profile is assigned: Frappe rewrites
    the table from that profile on the next save whatever this says, so answering
    anything else would have a caller write the user, achieve nothing, and find the
    same difference on the next run - clearing their sessions every time.
    """
    current = [row.get("role") for row in user.get("roles", []) if row.get("role")]

    if role_profile_would_overwrite_grants(user):
        return current

    kept = [role for role in current if role not in managed]

    return list(dict.fromkeys(kept + list(granted)))


def apply_role_grants(user, granted: list[str], managed: set[str]) -> bool:
    """Reconciles the roles this app manages, leaving every other role alone.

    Returns whether the role table moved. Does nothing when a role profile is
    assigned, since Frappe would undo it during the save that follows.
    """
    if not managed and not granted:
        return False

    if role_profile_would_overwrite_grants(user):
        if granted:
            frappe.logger().warning(
                f"Not granting {granted} to {user.name or user.get('email')}: the role profile "
                f"{user.get('role_profile_name') or user.get('role_profiles')} is assigned, "
                f"and Frappe rewrites the whole role table from it on every save. Map this "
                f"group to a role profile or to roles, not to both."
            )

        return False

    current = [row.get("role") for row in user.get("roles", []) if row.get("role")]
    final = role_grants_target(user, granted, managed)

    if set(final) == set(current):
        return False

    frappe.logger().info(
        f"Roles of {user.name or user.get('email')}: {sorted(current)} -> {sorted(final)}."
    )
    user.set("roles", [])

    for role in final:
        user.append("roles", {"role": role})

    return True


def user_has_multiple_role_profiles() -> bool:
    """True on Frappe versions whose User doctype has the "role_profiles" child table.

    Frappe v15 stores a single role profile in the "role_profile_name" Link field;
    the child table that allows several of them was introduced in v16.
    """
    return bool(frappe.get_meta("User").has_field("role_profiles"))


def roles_of_role_profiles(role_profiles: list[str]) -> set[str]:
    """The roles those Role Profiles grant, for working out what one of them had given."""
    roles = set()

    for name in role_profiles:
        try:
            profile = frappe.get_cached_doc("Role Profile", name)
        except frappe.DoesNotExistError:
            # Deleted since it was assigned. Nothing to attribute to it.
            continue

        roles.update(row.get("role") for row in profile.get("roles", []) if row.get("role"))

    return roles


def apply_role_profiles(user, role_profiles: list[str], grants_govern_roles: bool = False) -> bool:
    """Writes the role profiles in the layout of the running Frappe version.

    Returns whether the assignment changed, so the caller can invalidate sessions
    only when the user's entitlements actually moved.

    `grants_govern_roles` says that this configuration also grants roles directly, in
    which case the role table belongs to the managed set and is not emptied wholesale
    here - see `apply_role_grants`.
    """
    if user_has_multiple_role_profiles():
        previous = [row.get("role_profile") for row in user.get("role_profiles", [])]
        changed = set(previous) != set(role_profiles)

        user.set("role_profiles", [])
        for role_profile in role_profiles:
            user.append("role_profiles", {"role_profile": role_profile})
    else:
        previous = [user.get("role_profile_name")] if user.get("role_profile_name") else []
        # Only one profile can be stored, so the highest priority match wins.
        new = role_profiles[0] if role_profiles else None
        changed = (previous[0] if previous else None) != new
        user.role_profile_name = new

        if len(role_profiles) > 1:
            frappe.logger().info(
                f"This Frappe version stores a single role profile per user; assigning "
                f"{new} to {user.name} and ignoring {role_profiles[1:]}."
            )

    if not role_profiles:
        # Neither layout clears the role table when the profile is emptied: on v15
        # User.populate_role_profile_roles only rewrites the roles while a profile is
        # set. Strip them explicitly so that de-provisioning in the identity provider
        # reaches Frappe.
        current_roles = [row.get("role") for row in user.get("roles", []) if row.get("role")]

        if grants_govern_roles:
            # Only what the profile they just lost had granted. Everything else is
            # either the grants table's, which reconciles it, or somebody's deliberate
            # decision here, which is not this app's to undo.
            stale = roles_of_role_profiles(previous)
            kept = [role for role in current_roles if role not in stale]
        else:
            kept = []

        changed = changed or kept != current_roles
        user.set("roles", [])

        for role in kept:
            user.append("roles", {"role": role})

    return changed


def managing_roles(configuration) -> bool:
    """Whether this provider decides the user's roles at all.

    On unless explicitly turned off, so a site that has not asked for anything else
    behaves exactly as it always has.

    Off is the sign-in and offboarding mode: the identity provider says who may have an
    account and closes it when they leave, and the ERP decides who has which roles.
    Keeping directory groups in step with ERP roles is work, and below a certain size it
    is more work than the mapping saves - at which point the honest configuration is not
    an empty mapping table but no mapping at all. None of the mapping code runs on such
    a site, so nothing in it can reach a role the ERP owns.
    """
    manage = configuration.get("manage_roles")

    if manage is None:
        return True

    return bool(frappe.utils.cint(manage))


def disabling_unmapped_users(configuration) -> bool:
    """Whether a user whose groups grant nothing here has their account disabled.

    Off by default, so a site that has not asked for it behaves exactly as before.

    It composes with "When No Group Matches" rather than replacing it: that setting
    still decides what happens to the roles, this one decides whether the account
    stays usable. Leaving the action on "Keep Existing Roles" and turning this on is
    how a site gates access by group membership without letting the identity provider
    touch anybody's roles.

    Turning it on hands the enabled flag of every user linked to this provider to the
    provider, in both directions: an account disabled by hand here is enabled again at
    the next login if the groups grant something.
    """
    if not managing_roles(configuration):
        # It is a rule about group membership, and this site does not read groups. The
        # callers skip the whole question, but a rule that only holds because of where
        # it is called from is not a rule.
        return False

    return bool(frappe.utils.cint(configuration.get("disable_unmapped_users")))


def has_no_mapped_group(
    role_profiles: list[str], module_profile: str | None, roles: list[str] | None = None
) -> bool:
    """Whether the groups of this login grant anything at all on this site.

    Every mapping table counts, and so do the fallbacks - a site that gates access
    through module mappings alone, or through direct role grants, or that gives
    everyone a fallback profile, has already said what an unrecognised group should
    get.
    """
    return not role_profiles and not module_profile and not roles


def is_last_enabled_system_manager(user) -> bool:
    """Whether disabling this user would leave nobody able to administer the site.

    Administrator is not counted. It cannot log in through this app, and on a site
    where it is a shared or forgotten credential, "Administrator still holds the role"
    is not the same as somebody being able to get in.
    """
    if SYSTEM_MANAGER_ROLE not in {row.get("role") for row in user.get("roles", [])}:
        return False

    holders = frappe.get_all(
        "Has Role",
        filters={"role": SYSTEM_MANAGER_ROLE, "parenttype": "User"},
        pluck="parent",
        limit_page_length=0,
    )
    others = {name for name in holders if name != user.name and name not in RESERVED_USERS}

    if not others:
        return True

    return not frappe.get_all(
        "User",
        filters={"name": ("in", sorted(others)), "enabled": 1},
        pluck="name",
        limit_page_length=0,
    )


def may_disable(user) -> str | None:
    """The reason this user must not be disabled, or None when they may be."""
    if user.name in RESERVED_USERS:
        return f"{user.name} is one of Frappe's built-in accounts"

    if is_last_enabled_system_manager(user):
        return f"{user.name} is the last enabled {SYSTEM_MANAGER_ROLE} on this site"

    return None


def disable_user(user, reason: str) -> bool:
    """Disables a user and ends their sessions, unless a guard forbids it.

    Returns whether the account was disabled. The document is not saved here: a login
    writes the rest of the record in the same save, and a reconciliation strips the
    entitlements first.
    """
    refusal = may_disable(user)

    if refusal:
        frappe.logger().warning(
            f"Not disabling {user.name}: {refusal}. It would have been disabled because "
            f"{reason}."
        )
        return False

    frappe.logger().warning(f"Disabling {user.name}: {reason}.")
    user.enabled = 0
    # An enabled session outlives the flag, so the account would keep working until it
    # idled out - which is most of what disabling it was meant to stop.
    clear_sessions(user=user.name, force=True)
    frappe.clear_cache(user=user.name)

    return True


def enable_user(user, reason: str) -> bool:
    """Enables a user the identity provider vouches for again."""
    if user.enabled:
        return False

    frappe.logger().warning(f"Enabling {user.name} again: {reason}.")
    user.enabled = 1

    return True


def respond_no_mapped_group():
    """The page shown to someone whose groups grant nothing on this site."""
    frappe.respond_as_web_page(
        _("Not Permitted"),
        _("You are not a member of any group that grants access to this site."),
        http_status_code=403,
        indicator_color="red",
        success=False,
    )


def apply_entitlements(user, existing_user_name, configuration, groups, email) -> tuple[bool, bool]:
    """Decides and writes what the groups in the token entitle this user to.

    Returns (refused, changed): whether the login was refused - in which case the
    response has already been written and the caller must stop - and whether the
    user's entitlements moved, which is what decides if their other sessions are ended.

    Nothing calls this when "Manage Roles From The Identity Provider" is off. That is
    the whole of what that switch does, and why it is a switch rather than a set of
    conditions: none of the mapping code runs at all on such a site, so none of it can
    reach a role the ERP owns - not through a mapping somebody left half filled in, and
    not through a mistake in here.
    """
    # Maps the groups of the token to role profiles, most significant first.
    frappe.logger().debug(f"Mapping groups to role profiles for user {email}.")
    role_profiles = resolve_role_profiles(configuration, groups)
    frappe.logger().debug(f"Role profiles resolved for user {email}: {role_profiles}")

    # And to individual roles, which add up rather than competing. Only the roles this
    # configuration names are ever touched, so a role granted here by hand survives.
    granted_roles = resolve_roles(configuration, groups)
    managed = managed_roles(configuration)
    frappe.logger().debug(f"Roles granted to {email} by their groups: {granted_roles}")

    # Delegate module blocking to Frappe's native module profile field. Resolved here,
    # before anything is written, because whether these groups mean anything on this
    # site is a single question - and the answer decides both the entitlements below
    # and whether the account stays usable at all.
    frappe.logger().debug(f"Mapping groups to module profiles for user {email}.")
    module_profile = resolve_module_profile(configuration, groups)

    unmapped_user_action = configuration.unmapped_user_action or KEEP_EXISTING_ROLES
    deny_login = not role_profiles and not granted_roles and unmapped_user_action == DENY_LOGIN

    if disabling_unmapped_users(configuration) and (
        deny_login or has_no_mapped_group(role_profiles, module_profile, granted_roles)
    ):
        # The account itself is refused, not only this session: an enabled Frappe user
        # keeps its API keys, its seat and its local password, none of which the
        # identity provider can revoke. What happens to the roles is still "When No
        # Group Matches" - this only decides whether the account stays usable.
        frappe.logger().warning(
            f"Refusing {email}: the groups {groups} grant no access to this site, and "
            f"unmapped users are disabled here ({unmapped_user_action})."
        )

        if not existing_user_name:
            # There is nothing to disable, and creating an account only to switch it
            # off leaves a record of everyone the provider ever pointed at this site.
            frappe.logger().warning(
                f"No Frappe account is created for {email}: their groups grant nothing here."
            )
            respond_no_mapped_group()
            return True, False

        if not user.enabled:
            frappe.logger().warning(f"The user {user.name} is already disabled.")
            respond_no_mapped_group()
            return True, False

        refusal = may_disable(user)

        if refusal:
            frappe.logger().warning(
                f"Leaving {user.name} exactly as they are: {refusal}. An enabled account "
                f"stripped of the role that makes it useful is the same lockout as a "
                f"disabled one, so neither is done here."
            )
            # Carry on as though the option were off and the action were "Keep Existing
            # Roles", so that the site does not lock itself out through the one door the
            # guard exists to hold open. "Deny Login" still refuses below: that setting
            # was already refusing them before this option existed.
            unmapped_user_action = KEEP_EXISTING_ROLES
        else:
            disable_user(user, f"none of the groups {groups} grants access to this site")

            if unmapped_user_action == REMOVE_ALL_ROLES:
                # Everything, not only the managed set: the managed set exists so that a
                # deliberate local decision about a live user is not stepped on, and
                # this account is being closed.
                apply_role_profiles(user, [])
                user.module_profile = None

            user.save()
            frappe.db.commit()
            respond_no_mapped_group()
            return True, False

    if deny_login:
        frappe.logger().warning(
            f"Denying login for {email}: no group of {groups} is mapped to a role profile "
            f"or a role, and no fallback role profile is configured."
        )
        respond_no_mapped_group()
        return True, False

    if not user.enabled:
        # Only reachable with the option on: without it a disabled user was refused
        # before the groups were read. Their groups grant something again, so the
        # provider has put them back - which is what keeps a group removed by mistake
        # from disabling someone for good.
        enable_user(user, f"the groups {groups} grant access to this site again")

    if role_profiles or unmapped_user_action == REMOVE_ALL_ROLES:
        # "Remove All Roles" with nothing to put back takes every role off the account,
        # which locks the site out as surely as disabling it would if this is the last
        # account that can administer it. The same guard as the disable, for the same
        # reason - and it applies whether or not unmapped users are disabled.
        refusal = None if role_profiles else may_disable(user)

        if refusal:
            frappe.logger().warning(
                f"Not stripping the roles of {user.name}: {refusal}. Keeping the roles "
                f"they have."
            )
            changed = False
        else:
            changed = apply_role_profiles(
                user, role_profiles, grants_govern_roles=bool(managed)
            )
    else:
        # "Keep Existing Roles": the identity provider told us nothing about this
        # user's entitlements, so leave whatever Frappe has on record alone.
        frappe.logger().info(
            f"No role profile matched for {email}; keeping the roles the user already has."
        )
        changed = False

    # On top of whatever the profile decided, and only over the roles this
    # configuration names.
    changed = apply_role_grants(user, granted_roles, managed) or changed

    if module_profile or unmapped_user_action == REMOVE_ALL_ROLES:
        user.module_profile = module_profile or None

    return False, changed


def redirect_post_login(desk_user: bool, redirect_to: str):
    from frappe.www.login import sanitize_redirect

    frappe.local.response["type"] = "redirect"

    # The target was sanitized when the login started, but it has been through Redis
    # since, and a login can also be started by Frappe's own login page. Landing
    # somewhere off this site after authenticating is worth one more check.
    redirect_to = sanitize_redirect(redirect_to)

    if not redirect_to:
        desk_uri = "/app"
        redirect_to = frappe.utils.get_url(desk_uri if desk_user else "/me")

    frappe.local.response["location"] = redirect_to
