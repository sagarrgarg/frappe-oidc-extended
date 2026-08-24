# Readings:
# - https://github.com/frappe/frappe/blob/828490e01a3d14e1b0ac3385ea196c72ab2cc950/frappe/integrations/oauth2_logins.py
# - https://github.com/frappe/frappe/blob/828490e01a3d14e1b0ac3385ea196c72ab2cc950/frappe/utils/oauth.py
# - https://github.com/castlecraft/microsoft_integration/blob/main/microsoft_integration/callback.py

import json
import requests
import jwt

import frappe
import frappe.utils
from frappe import _ # For translations
from frappe.utils.oauth import consume_oauth_state

frappe.utils.logger.set_log_level("INFO")
#frappe.utils.logger.set_log_level("DEBUG")

# Values of the "When No Group Matches" setting on OIDC Extended Configuration.
KEEP_EXISTING_ROLES = "Keep Existing Roles"
REMOVE_ALL_ROLES = "Remove All Roles"
DENY_LOGIN = "Deny Login"

# Frappe's built-in accounts, which must never be taken over by a login from an
# identity provider (see frappe.core.doctype.user.user.STANDARD_USERS).
RESERVED_USERS = ("Administrator", "Guest")

@frappe.whitelist(allow_guest=True)
def custom(code: str, state: str):
    """Callback for processing the request received after a successful authentication in an identity provider (OIDC provider).

    OIDC redirect URL: /api/method/oidc_extended.callback.custom/<provider name>

    This extends the functionality of the current Social Login (OIDC) module. In addition to handling the authentication over OIDC, this:
    - Creates new user if does not exsit.
    - Maps groups from the claim of id token to ERPNext roles.
    """

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

    request_path_components = frappe.request.path[1:].split("/")

    if not len(request_path_components) == 4 or not request_path_components[3]:
        frappe.respond_as_web_page(_("Invalid request"), _("The redirect URL is invalid."), http_status_code=417)
        return

    # Gets the name of the OIDC custom provider.
    provider_name = request_path_components[3]

    # Gets the document of the default Social Login (OIDC) configuration.
    social_login_provider = frappe.get_doc("Social Login Key", frappe.get_conf().get("custom", provider_name))
    user_id_claim_name = social_login_provider.user_id_property or "sub"

    # Gets the document of the extended OIDC configuration.
    oidc_extended_configuration = frappe.get_cached_doc('OIDC Extended Configuration', provider_name)
    given_name_claim_name = oidc_extended_configuration.given_name_claim_name or "given_name"
    family_name_claim_name = oidc_extended_configuration.family_name_claim_name or "family_name"
    email_claim_name = oidc_extended_configuration.email_claim_name or "email"
    groups_claim_name = oidc_extended_configuration.groups_claim_name or "groups"

    token_request_data = {
        "grant_type": "authorization_code",
        "client_id": social_login_provider.client_id,
        "client_secret": social_login_provider.get_password("client_secret"),
        "scope": json.loads(social_login_provider.auth_url_data).get("scope"),
        "code": code,
        "redirect_uri": frappe.utils.get_url(social_login_provider.redirect_url), # Combines ERPNext URL with redirect URL.
    }

    # Requests token from token endpoint.
    token_response = requests.post(
        url=social_login_provider.base_url + social_login_provider.access_token_url,
        data=token_request_data,
    ).json()

    id_token = jwt.decode(token_response["id_token"], audience="erpnext", options={"verify_signature": False})

    # Identifies the account at the identity provider. This value is stored as the
    # social login userid of the Frappe user and is what later logins match on, so it
    # has to be the stable, non-reassignable claim ("sub" unless configured otherwise).
    user_id = id_token.get(user_id_claim_name)

    if not user_id:
        frappe.logger().error(f"The id token has no {user_id_claim_name} claim: {sorted(id_token)}")
        frappe.respond_as_web_page(
            _("Missing User ID"),
            _("The identity provider did not return the {0} claim, which identifies the user.").format(
                user_id_claim_name
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

    first_name = id_token.get(given_name_claim_name, "No first name")
    last_name = id_token.get(family_name_claim_name, "No last name")
    # The groups the user have as received in the token.
    groups = normalize_groups(id_token.get(groups_claim_name))
    frappe.logger().debug(f"Groups of user {email}: {groups}")

    frappe.logger().debug(f"Current session user: {frappe.session.user}")

    # Creates the user if does not exsit, otherwise updates the data according to the claims of the token.
    existing_user_name = find_existing_user(provider_name, user_id, email)
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
        if existing_user_name in RESERVED_USERS or str(user_id).lower() in ("administrator", "guest"):
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

        frappe.logger().info(f"The existing user {existing_user_name} fetched successfully.")
        frappe.logger().debug(f"The existing user data: {user.as_dict()}")
    else:
        # Creates a new user. `username` is deliberately left to Frappe: it derives one
        # and blanks it on collision (User.validate_username), so it cannot be relied
        # on as an identifier.
        frappe.logger().info(f"Creating a new Frappe user: {email}")

        user = frappe.get_doc(
            {
                "doctype": "User",
                "first_name": first_name,
                "last_name": last_name,
                "email": email,
                "send_welcome_email": 0,
                "enabled": 1,
                "new_password": frappe.generate_hash(),
                "user_type": "System User"
            }
        )

        frappe.logger().info(f"New Frappe user {email} created successfully.")

        # Allows making changes on the user (like adding roles) by guest user.
        user.flags.ignore_permissions = True


    if not user.enabled:
        frappe.logger().info(f"The user {user.name} is disabled.")
        frappe.respond_as_web_page(_("Not Allowed"), _("User {0} is disabled").format(user.name))
        return False

    if not user.get_social_login_userid(provider_name):
        frappe.logger().debug(f"set_social_login_userid for provider {provider_name} and user {user.name} called.")
        user.set_social_login_userid(provider_name, userid=user_id)

    # Allows all changes on the user in this code without checking if the operation is permitted to be done by the current user.
    frappe.logger().info(f"Allowing all changes on the user {email} without checking permissions.")
    user.flags.ignore_permissions = True

    # Maps the groups of the token to role profiles, most significant first.
    frappe.logger().debug(f"Mapping groups to role profiles for user {email}.")
    role_profiles = resolve_role_profiles(oidc_extended_configuration, groups)
    frappe.logger().debug(f"Role profiles resolved for user {email}: {role_profiles}")

    unmapped_user_action = oidc_extended_configuration.unmapped_user_action or KEEP_EXISTING_ROLES

    if not role_profiles and unmapped_user_action == DENY_LOGIN:
        frappe.logger().warning(
            f"Denying login for {email}: no group of {groups} is mapped to a role profile "
            f"and no fallback role profile is configured."
        )
        frappe.respond_as_web_page(
            _("Not Permitted"),
            _("You are not a member of any group that grants access to this site."),
            http_status_code=403,
            indicator_color="red",
            success=False,
        )
        return

    if role_profiles or unmapped_user_action == REMOVE_ALL_ROLES:
        role_profiles_changed = apply_role_profiles(user, role_profiles)
    else:
        # "Keep Existing Roles": the identity provider told us nothing about this
        # user's entitlements, so leave whatever Frappe has on record alone.
        frappe.logger().info(
            f"No role profile matched for {email}; keeping the roles the user already has."
        )
        role_profiles_changed = False

    # Delegate module blocking to Frappe's native module profile field.
    frappe.logger().debug(f"Mapping groups to module profiles for user {email}.")
    module_profile = resolve_module_profile(oidc_extended_configuration, groups)

    if module_profile or unmapped_user_action == REMOVE_ALL_ROLES:
        user.module_profile = module_profile or None

    user.save()

    if role_profiles_changed:
        frappe.logger().info(f"Role profiles changed for {email}. Clearing active sessions to enforce new permissions instantly.")
        frappe.cache().hdel("sessions", user.name)
        frappe.cache().hdel("bhas_role", user.name)

    frappe.local.login_manager.user = user.name
    frappe.local.login_manager.post_login()

    frappe.db.commit()

    redirect_post_login(
        desk_user=frappe.local.response.get("message") == "Logged In",
        redirect_to=redirect_to or None
    )

def find_existing_user(provider_name: str, user_id: str, email: str) -> str | None:
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

    # Users provisioned by earlier versions of this app carry the subject in `username`.
    return frappe.db.exists("User", {"username": user_id}) or None


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
    """
    matched = [
        row for row in configuration.get("group_role_mappings", []) if row.get("group") in groups
    ]

    if not matched:
        matched = list(configuration.get("fallback_role_profiles", []))

    profiles = [row.get("role_profile") for _, row in sort_by_priority(matched)]

    # dict.fromkeys keeps the first occurrence of a profile mapped by several groups.
    return list(dict.fromkeys(profile for profile in profiles if profile))


def resolve_module_profile(configuration, groups: list[str]) -> str | None:
    """The module profile for the given groups, or the configured fallback."""
    matched = [
        row for row in configuration.get("group_module_mappings", []) if row.get("group") in groups
    ]

    if matched:
        # The User doctype holds a single module profile, so the highest priority wins.
        return sort_by_priority(matched)[0][1].get("module_profile")

    return configuration.get("fallback_module_profile") or None


def user_has_multiple_role_profiles() -> bool:
    """True on Frappe versions whose User doctype has the "role_profiles" child table.

    Frappe v15 stores a single role profile in the "role_profile_name" Link field;
    the child table that allows several of them was introduced in v16.
    """
    return bool(frappe.get_meta("User").has_field("role_profiles"))


def apply_role_profiles(user, role_profiles: list[str]) -> bool:
    """Writes the role profiles in the layout of the running Frappe version.

    Returns whether the assignment changed, so the caller can invalidate sessions
    only when the user's entitlements actually moved.
    """
    if user_has_multiple_role_profiles():
        current = {row.get("role_profile") for row in user.get("role_profiles", [])}
        changed = current != set(role_profiles)

        user.set("role_profiles", [])
        for role_profile in role_profiles:
            user.append("role_profiles", {"role_profile": role_profile})
    else:
        current = user.get("role_profile_name")
        # Only one profile can be stored, so the highest priority match wins.
        new = role_profiles[0] if role_profiles else None
        changed = current != new
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
        changed = changed or bool(user.get("roles"))
        user.set("roles", [])

    return changed


def redirect_post_login(desk_user: bool, redirect_to: str):
    frappe.local.response["type"] = "redirect"

    if not redirect_to:
        desk_uri = "/app"
        redirect_to = frappe.utils.get_url(desk_uri if desk_user else "/me")

    frappe.local.response["location"] = redirect_to
