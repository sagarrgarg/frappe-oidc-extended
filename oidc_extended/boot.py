"""What the desk needs to know about this app before it renders anything.

The User form warns that an identity provider owns somebody's roles, and locks the
fields it writes. Whether that is true depends on the provider's configuration, which
the form has no business reading - it is a System Manager document, and the User form is
open to more people than that. So the answer is settled here, once per session, and the
form is told only what it needs: which providers decide roles.
"""

import frappe


def boot_session(bootinfo):
	bootinfo.oidc_extended = {"providers_managing_roles": providers_managing_roles()}


def providers_managing_roles() -> list[str]:
	"""The providers whose configuration says the groups in the token decide the roles.

	`frappe.get_all` does not check permissions, which is what makes this answerable for
	a user who cannot read the configuration - and all it discloses is a provider name
	they can already see on their own social login row.

	Which is the "Use Groups From The Identity Provider" switch: reading the groups is
	what leads to writing the roles. A configuration that predates it has no value
	stored, and this app has always read groups, so an unset field counts as on - the
	same reading `using_groups` takes on the server.
	"""
	return [
		row["name"]
		for row in frappe.get_all(
			"OIDC Extended Configuration", fields=["name", "use_groups"], limit_page_length=0
		)
		if row.get("use_groups") is None or frappe.utils.cint(row.get("use_groups"))
	]
