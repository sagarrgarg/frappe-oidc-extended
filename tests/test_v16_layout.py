"""The v16 User layout: several role profiles in a Table MultiSelect."""

from tests.base import CallbackTestCase


class TestV16RoleProfiles(CallbackTestCase):
	def setUp(self):
		super().setUp()
		self.use_frappe_v16_user()

	def test_every_matched_profile_is_written_in_priority_order(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile", priority=20)
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile", priority=10)
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(
			self.role_profiles_of(user), ["Accounts Profile", "Sales Profile"]
		)
		self.assertEqual(
			self.roles_of(user), ["Accounts User", "Sales User", "Sales Manager"]
		)

	def test_the_deprecated_link_field_is_left_to_frappe(self):
		"""v16 keeps `role_profile_name` in sync from the child table itself."""
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")

	def test_de_provisioning_empties_the_child_table_and_the_roles(self):
		"""v16's populate_role_profile_roles returns early on an empty table, so the
		roles have to be stripped here or a de-provisioned user keeps them."""
		user = self.add_existing_user(
			role_profiles=[{"role_profile": "Sales Profile"}], roles=[{"role": "Sales User"}]
		)
		self.config.unmapped_user_action = "Remove All Roles"
		self.run_callback(claims=self.id_token_claims(groups=["unmapped"]))

		self.assertEqual(self.role_profiles_of(user), [])
		self.assertEqual(self.roles_of(user), [])
		self.assertIsNone(user.get("role_profile_name"))

	def test_keeping_existing_roles_leaves_the_child_table_alone(self):
		user = self.add_existing_user(
			role_profiles=[{"role_profile": "Sales Profile"}, {"role_profile": "Accounts Profile"}]
		)
		self.run_callback(claims=self.id_token_claims(groups=["unmapped"]))

		self.assertEqual(
			self.role_profiles_of(user), ["Sales Profile", "Accounts Profile"]
		)

	def test_a_removed_group_removes_only_that_profile(self):
		user = self.add_existing_user(
			role_profiles=[{"role_profile": "Sales Profile"}, {"role_profile": "Accounts Profile"}]
		)
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(self.role_profiles_of(user), ["Sales Profile"])
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])
		self.assertEqual(
			self.frappe.sessions.cleared,
			[{"user": "jane@example.com", "keep_current": True, "force": True}],
		)
