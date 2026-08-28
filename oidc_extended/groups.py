"""Filling the mapping tables from the vocabulary the identity provider already has.

The group names in the mappings are typed by hand today, against a list that lives in
another system. A typo is silent - the row simply never matches - and it stays silent
until somebody logs in and finds they have no roles. With unmapped users disabled it
stops being silent and starts being a lockout.

So this asks the provider what it actually calls things, through the same admin API
the reconciliation already uses, and adds the names that are missing. It only ever
adds: an existing row is never rewritten or removed, and a row whose profile is still
empty is ignored at login (see `resolve_role_profiles`), so a half-filled table
changes nothing until somebody finishes it.
"""

import frappe
from frappe import _

from oidc_extended.directory import ClientNotFoundError, get_directory

# The two tables a group name can appear in. The profile column of each is what an
# administrator fills in afterwards; until they do, the row is ignored at login.
MAPPING_TABLES = ("group_role_mappings", "group_module_mappings")

# What each directory type needs before it can be asked anything.
REQUIRED_CREDENTIALS = {
	"Keycloak": (
		("directory_client_id", "Service Account Client ID"),
		("directory_client_secret", "Service Account Client Secret"),
	),
	"Authentik": (("directory_api_token", "API Token"),),
}


@frappe.whitelist(methods=["POST"])
def fetch_groups(provider: str) -> dict:
	"""Adds the provider's groups to both mapping tables, with the profiles left blank.

	Returns what it did rather than only writing it, so the button can say how many
	names were new and how many were already mapped - "nothing happened" and "nothing
	needed to happen" look identical otherwise.
	"""
	frappe.only_for("System Manager")

	configuration = frappe.get_doc("OIDC Extended Configuration", provider)
	check_credentials(configuration)

	# The client id the Social Login Key presents is the client whose roles are this
	# site's vocabulary; nothing else identifies which client of the realm we are.
	client_id = frappe.db.get_value("Social Login Key", configuration.provider, "client_id")

	try:
		names, source = get_directory(configuration).get_group_names(client_id)
	except ClientNotFoundError:
		frappe.throw(
			_("The identity provider has no client with the id {0}, which is the Client ID of the Social Login Key {1}.").format(
				frappe.bold(client_id), configuration.provider
			)
		)

	# Keep the provider's order, drop anything it repeats.
	names = list(dict.fromkeys(name.strip() for name in names if name and name.strip()))

	if not names:
		frappe.throw(
			_("{0} returned no groups. Nothing was added.").format(configuration.get("directory_type"))
		)

	result = {"provider": provider, "source": source, "groups": names}

	for table in MAPPING_TABLES:
		mapped = {(row.get("group") or "").strip() for row in configuration.get(table, [])}
		missing = [name for name in names if name not in mapped]

		for name in missing:
			configuration.append(table, {"group": name})

		result[f"{table}_added"] = len(missing)
		result[f"{table}_present"] = len(names) - len(missing)

	if any(result[f"{table}_added"] for table in MAPPING_TABLES):
		configuration.save()

	frappe.logger().info(
		f"Fetched {len(names)} group names for {provider} from {source}: "
		f"{result['group_role_mappings_added']} added to the role mappings, "
		f"{result['group_module_mappings_added']} to the module mappings."
	)

	return result


def check_credentials(configuration):
	"""Refuses early, and by name, rather than through an HTTP error from the provider."""
	directory_type = configuration.get("directory_type")

	if not directory_type:
		frappe.throw(
			_("Set a Directory Type under Reconciliation first: the groups are read through the same API the reconciliation uses.")
		)

	for fieldname, label in REQUIRED_CREDENTIALS.get(directory_type, ()):
		if not configuration.get(fieldname):
			frappe.throw(
				_("{0} is needed to read the groups of a {1} directory.").format(
					frappe.bold(_(label)), directory_type
				)
			)
