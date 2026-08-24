"""Point 2: role profiles must be written the way the running Frappe version stores them."""

from tests.base import CallbackTestCase


class TestRoleProfileAssignment(CallbackTestCase):
	def test_v15_writes_the_single_role_profile_link_field(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertEqual(user.get("role_profiles"), None)
		# Frappe repopulates the role table from the profile on save.
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])

	def test_v16_writes_every_matched_profile_into_the_child_table(self):
		self.use_frappe_v16_user()
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.role_profiles_of(user), ["Sales Profile", "Accounts Profile"])
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager", "Accounts User"])

	def test_v15_multiple_matches_resolve_by_priority_not_by_row_order(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile", priority=20)
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile", priority=10)
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Accounts Profile")

	def test_v15_equal_priorities_fall_back_to_table_order(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts", "erp-sales"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")

	def test_fallback_profiles_apply_when_no_group_matches(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.set_fallback_role_profiles("Employee Profile")
		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Employee Profile")

	def test_duplicate_profiles_from_several_groups_are_collapsed(self):
		self.use_frappe_v16_user()
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.map_group_to_role_profile("erp-sales-eu", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-sales-eu"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.role_profiles_of(user), ["Sales Profile"])


class TestUnmappedUsers(CallbackTestCase):
	def test_default_keeps_the_role_profile_the_user_already_has(self):
		user = self.add_existing_user(role_profile_name="Sales Profile")
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["not-mapped"]))

		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		# Frappe re-derives the role table from the retained profile on save.
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])
		self.assertLoggedIn("jane@example.com")

	def test_default_keeps_roles_granted_outside_a_role_profile(self):
		user = self.add_existing_user(roles=[{"role": "Accounts User"}, {"role": "Projects User"}])
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["not-mapped"]))

		self.assertEqual(self.roles_of(user), ["Accounts User", "Projects User"])
		self.assertLoggedIn("jane@example.com")

	def test_remove_all_roles_deprovisions_the_user(self):
		user = self.add_existing_user(
			role_profile_name="Sales Profile", roles=[{"role": "Sales User"}]
		)
		self.config.unmapped_user_action = "Remove All Roles"
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["not-mapped"]))

		self.assertIsNone(user.get("role_profile_name"))
		self.assertEqual(self.roles_of(user), [])
		self.assertLoggedIn("jane@example.com")

	def test_remove_all_roles_also_clears_the_module_profile(self):
		user = self.add_existing_user(module_profile="Restricted Modules")
		self.config.unmapped_user_action = "Remove All Roles"
		self.run_callback(claims=self.id_token_claims(groups=[]))

		self.assertIsNone(user.get("module_profile"))

	def test_deny_login_refuses_the_login_and_saves_nothing(self):
		user = self.add_existing_user(
			role_profile_name="Sales Profile", roles=[{"role": "Sales User"}]
		)
		self.config.unmapped_user_action = "Deny Login"
		self.run_callback(claims=self.id_token_claims(groups=["not-mapped"]))

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()
		self.assertEqual(user.save_count, 0)
		self.assertEqual(self.roles_of(user), ["Sales User"])


class TestGroupMatching(CallbackTestCase):
	def test_group_names_match_exactly_not_by_substring(self):
		self.map_group_to_role_profile("sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales-readonly"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertIsNone(user.get("role_profile_name"))

	def test_a_comma_separated_string_claim_is_split(self):
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile")
		self.run_callback(claims=self.id_token_claims(groups="erp-sales, erp-accounts"))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Accounts Profile")

	def test_a_single_string_claim_may_contain_spaces(self):
		self.map_group_to_role_profile("Sales Team", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups="Sales Team"))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")

	def test_a_missing_groups_claim_is_not_an_error(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		claims = self.id_token_claims()
		claims.pop("groups")
		self.run_callback(claims=claims)

		self.assertLoggedIn("jane@example.com")


class TestModuleProfileAssignment(CallbackTestCase):
	def test_module_profile_matches_by_priority(self):
		self.config.append("group_module_mappings", {"group": "erp-sales", "module_profile": "Sales Modules", "priority": 20})
		self.config.append("group_module_mappings", {"group": "erp-accounts", "module_profile": "Accounts Modules", "priority": 10})
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("module_profile"), "Accounts Modules")

	def test_fallback_module_profile_applies_when_nothing_matches(self):
		self.config.fallback_module_profile = "Restricted Modules"
		self.run_callback(claims=self.id_token_claims(groups=["unmapped"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("module_profile"), "Restricted Modules")


class TestApplyRoleProfilesReturnValue(CallbackTestCase):
	"""The return value gates session invalidation, so it must be accurate."""

	def test_reports_change_when_the_profile_moves(self):
		user = self.add_existing_user(role_profile_name="Sales Profile")
		self.assertTrue(self.callback.apply_role_profiles(user, ["Accounts Profile"]))

	def test_reports_no_change_when_the_profile_is_the_same(self):
		user = self.add_existing_user(role_profile_name="Sales Profile")
		self.assertFalse(self.callback.apply_role_profiles(user, ["Sales Profile"]))

	def test_reports_no_change_on_v16_when_only_the_order_differs(self):
		self.use_frappe_v16_user()
		user = self.add_existing_user(
			role_profiles=[{"role_profile": "Sales Profile"}, {"role_profile": "Accounts Profile"}]
		)
		self.assertFalse(
			self.callback.apply_role_profiles(user, ["Accounts Profile", "Sales Profile"])
		)

	def test_reports_change_when_roles_are_stripped(self):
		user = self.add_existing_user(roles=[{"role": "Sales User"}])
		self.assertTrue(self.callback.apply_role_profiles(user, []))
		self.assertEqual(self.roles_of(user), [])
