import frappe


def execute():
	"""Keeps role management on for configurations that predate the setting.

	"Manage Roles From The Identity Provider" is what this app has always done, and its
	default is on - but a default only applies to documents created after it exists.
	A configuration that predates it would otherwise be read as the site having asked
	for the sign-in and offboarding mode, and would quietly stop assigning the roles it
	has been assigning all along.
	"""
	if not frappe.db.has_column("OIDC Extended Configuration", "manage_roles"):
		return

	for name in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		frappe.db.set_value(
			"OIDC Extended Configuration", name, "manage_roles", 1, update_modified=False
		)
