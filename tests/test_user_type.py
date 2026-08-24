"""Point 6: the user type of newly created users must not be hardcoded."""

from tests.base import CallbackTestCase


class TestNewUserType(CallbackTestCase):
	def test_a_user_without_desk_roles_is_a_website_user(self):
		self.run_callback()

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("user_type"), "Website User")

	def test_a_configured_custom_user_type_is_kept(self):
		self.frappe.flags.standard_user_types = {"System User", "Website User"}
		self.config.new_user_type = "Portal Member"
		self.run_callback()

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("user_type"), "Portal Member")

	def test_frappe_still_promotes_a_user_holding_a_desk_role(self):
		"""The role profiles you map decide the seat, not the field this app writes."""
		self.frappe.flags.desk_roles = {"Sales User"}
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("user_type"), "System User")

	def test_an_unmapped_user_does_not_become_a_system_user(self):
		self.frappe.flags.desk_roles = {"Sales User"}
		self.run_callback(claims=self.id_token_claims(groups=["unmapped"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("user_type"), "Website User")
		self.assertEqual(self.roles_of(user), [])
