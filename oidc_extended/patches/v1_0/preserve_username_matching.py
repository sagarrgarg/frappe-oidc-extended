import frappe


def execute():
	"""Keeps the username fallback on for configurations that predate the setting.

	Until this release a login that matched no social login userid and no email address
	was matched against `username`, where earlier versions of this app stored the
	identity provider's user id claim. That leg is now off by default, because the claim
	is not a Frappe username and can match an unrelated account, but a site already
	relying on it would stop matching those users on upgrade.
	"""
	if not frappe.db.has_column("OIDC Extended Configuration", "match_users_by_username"):
		return

	for name in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		frappe.db.set_value(
			"OIDC Extended Configuration", name, "match_users_by_username", 1, update_modified=False
		)
