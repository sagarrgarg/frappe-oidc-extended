# Copyright (c) 2023, Mohammed Noureldin and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document

class OIDCExtendedConfiguration(Document):
	def validate(self):
		self.validate_duplicate_module_groups()
		self.warn_about_groups_mapped_to_both_a_profile_and_roles()
		self.warn_about_fallbacks_that_disarm_the_disable_option()

	def validate_duplicate_module_groups(self):
		if not self.group_module_mappings:
			return

		seen_groups = set()
		for row in self.group_module_mappings:
			if row.group in seen_groups:
				frappe.throw(
					frappe._("Row {0}: The group '{1}' is already mapped. Module profiles only support a single mapping per group.").format(row.idx, row.group)
				)
			seen_groups.add(row.group)

	def warn_about_groups_mapped_to_both_a_profile_and_roles(self):
		"""A group cannot do both, because Frappe will not let it.

		`User.validate` empties the role table and refills it from the assigned role
		profile on every save, so a role granted to a user who also has a profile is
		gone by the time the save returns. The two tables are alternatives.
		"""
		profiles = {row.group for row in (self.group_role_mappings or []) if row.role_profile}
		grants = {row.group for row in (self.group_role_grants or []) if row.role}
		both = sorted(profiles & grants)

		if not both:
			return

		frappe.msgprint(
			frappe._("The group(s) {0} are mapped to a role profile and to roles. Frappe rewrites a user's whole role table from their role profile on every save, so the profile wins and the roles are never granted. Map each group to one or the other.").format(
				frappe.bold(", ".join(both))
			),
			title=frappe._("A Group Cannot Grant Both"),
			indicator="orange",
		)

	def warn_about_fallbacks_that_disarm_the_disable_option(self):
		"""A fallback profile counts as a mapped group, so nobody is ever unmapped.

		The two settings are individually reasonable and together silently cancel out:
		everyone who matches no group gets the fallback, which means the disable never
		fires and the site believes it is gating access when it is not.
		"""
		if not frappe.utils.cint(self.get("disable_unmapped_users")):
			return

		fallbacks = [row.role_profile for row in (self.fallback_role_profiles or []) if row.role_profile]

		if not fallbacks and not self.fallback_module_profile:
			return

		frappe.msgprint(
			frappe._("A fallback profile is configured, so every user matches something and \"Disable Users With No Mapped Group\" will never disable anybody. Clear the fallbacks to gate access on group membership."),
			title=frappe._("The Fallback Profiles Disarm This"),
			indicator="orange",
		)
