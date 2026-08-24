import frappe

ALWAYS_CREATE_USERS = "Always Create Users"


def execute():
	"""Keeps automatic user creation on for configurations that predate the setting.

	Until this release the callback created a Frappe user for every login that reached
	it. The new "User Provisioning" setting defaults to following the Sign-ups field of
	the Social Login Key, which would silently stop provisioning users on a site that
	relies on it, so configurations that already exist are pinned to the behaviour they
	had. Configurations created from now on get the default.
	"""
	if not frappe.db.has_column("OIDC Extended Configuration", "user_provisioning"):
		return

	for name in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		frappe.db.set_value(
			"OIDC Extended Configuration", name, "user_provisioning", ALWAYS_CREATE_USERS,
			update_modified=False,
		)
