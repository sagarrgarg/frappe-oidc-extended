import frappe


def execute():
	"""Keeps group-driven roles on for configurations that predate the switch.

	"Use Groups From The Identity Provider" is what this app has always done, and its
	default is on - but a default only applies to documents created after it exists. A
	configuration that predates it would otherwise be read as the site having asked for
	the sign-in and offboarding mode, and would quietly stop assigning the roles it has
	been assigning all along.

	The switch was called `manage_roles` for one release on an unreleased branch. Where
	that column is still there, its value is carried over rather than overwritten, so a
	site that tried the branch and turned the switch off does not have it turned back on
	underneath them.
	"""
	if not frappe.db.has_column("OIDC Extended Configuration", "use_groups"):
		return

	previous = frappe.db.has_column("OIDC Extended Configuration", "manage_roles")

	for name in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		value = 1

		if previous:
			value = frappe.utils.cint(
				frappe.db.get_value("OIDC Extended Configuration", name, "manage_roles")
			)

		frappe.db.set_value(
			"OIDC Extended Configuration", name, "use_groups", value, update_modified=False
		)
