"""Granting roles directly, and taking back only what was granted.

A role profile is a single Link on Frappe v15, so two groups that both map to a
profile can only ever produce one of them - which leaves nowhere to put "everything an
accounts user has, and approval on top". Roles granted per group add up instead.

The rule that makes that safe is the managed set: every role named anywhere in the
grants table is the identity provider's to give and to take away, and every other role
on the user is somebody's deliberate decision here. Reconcile the whole role table
instead and the choice is between never revoking anything and wiping every grant an
administrator made by hand.
"""

from tests.base import CallbackTestCase


class RoleGrantTestCase(CallbackTestCase):
	def grant(self, group, role):
		self.config.append("group_role_grants", {"group": group, "role": role})


class TestGrantingRoles(RoleGrantTestCase):
	def test_a_matched_group_grants_its_role(self):
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), ["Accounts User"])

	def test_several_groups_add_up_instead_of_competing(self):
		self.grant("erp-accounts", "Accounts User")
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts", "erp-approvers"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), ["Accounts User", "Accounts Manager"])

	def test_a_role_granted_by_two_groups_is_added_once(self):
		self.grant("erp-accounts", "Accounts User")
		self.grant("erp-accounts-eu", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts", "erp-accounts-eu"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), ["Accounts User"])

	def test_a_row_with_no_role_grants_nothing(self):
		"""As "Fetch Groups From Provider" leaves the rows it imports."""
		self.grant("erp-imported", None)

		self.run_callback(claims=self.id_token_claims(groups=["erp-imported"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), [])

	def test_groups_match_by_exact_string(self):
		self.grant("accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts-readonly"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), [])


class TestTheManagedSet(RoleGrantTestCase):
	def test_leaving_the_group_takes_the_role_back(self):
		user = self.add_existing_user(roles=[{"role": "Accounts Manager"}])
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertEqual(self.roles_of(user), [])

	def test_a_role_granted_by_hand_survives(self):
		"""Nothing names it in the table, so it is not the provider's to take away."""
		user = self.add_existing_user(roles=[{"role": "Projects User"}])
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		self.assertEqual(self.roles_of(user), ["Projects User", "Accounts User"])

	def test_a_role_granted_by_hand_survives_losing_every_group(self):
		user = self.add_existing_user(roles=[{"role": "Projects User"}])
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertEqual(self.roles_of(user), ["Projects User"])

	def test_a_managed_role_held_for_another_reason_is_still_taken(self):
		"""The table claims the role, so holding it is the provider's statement to make."""
		user = self.add_existing_user(roles=[{"role": "Accounts User"}])
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertEqual(self.roles_of(user), [])

	def test_an_empty_table_touches_nothing(self):
		user = self.add_existing_user(roles=[{"role": "Projects User"}])

		self.run_callback(claims=self.id_token_claims(groups=["anything"]))

		self.assertEqual(self.roles_of(user), ["Projects User"])


class TestAlongsideRoleProfiles(RoleGrantTestCase):
	"""The two mappings are alternatives, because Frappe makes them alternatives.

	`User.validate` empties the role table and refills it from the assigned role
	profile on every save, so a granted role cannot survive alongside one. A role added
	by hand in the user form disappears the same way; this is not something the app
	could arrange differently.
	"""

	def test_a_role_profile_wins_and_the_grant_is_reported_not_silently_dropped(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales", "erp-approvers"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertIn(
			"Not granting ['Accounts Manager'] to jane@example.com",
			"\n".join(m for level, m in self.frappe.logger_calls if level == "warning"),
		)

	def test_losing_the_profile_strips_what_it_granted_and_nothing_else(self):
		"""The hole a managed set would otherwise leave on a site that uses both."""
		user = self.add_existing_user(
			role_profile_name="Sales Profile",
			roles=[{"role": "Sales User"}, {"role": "Sales Manager"}, {"role": "Projects User"}],
		)
		self.config.unmapped_user_action = "Remove All Roles"
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["erp-approvers"]))

		self.assertIsNone(user.get("role_profile_name"))
		self.assertEqual(self.roles_of(user), ["Projects User", "Accounts Manager"])

	def test_a_profile_kept_from_an_earlier_login_also_wins(self):
		"""The wipe follows the assigned profile, not the one this login resolved."""
		user = self.add_existing_user(role_profile_name="Sales Profile")
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["erp-approvers"]))

		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])

	def test_the_grant_is_taken_back_while_the_profile_stays(self):
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])

	def test_a_grant_alone_leaves_the_profile_field_empty(self):
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertIsNone(user.get("role_profile_name"))

	def test_no_profile_means_no_second_save(self):
		user = self.add_existing_user()
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		self.assertEqual(user.save_count, 1)

	def test_remove_all_roles_strips_the_grants_too(self):
		user = self.add_existing_user(roles=[{"role": "Accounts User"}])
		self.config.unmapped_user_action = "Remove All Roles"
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertEqual(self.roles_of(user), [])

	def test_sessions_are_cleared_when_only_a_grant_moved(self):
		"""A reduced set of roles has to reach the tabs the user already has open."""
		self.add_existing_user(roles=[{"role": "Accounts Manager"}])
		self.grant("erp-approvers", "Accounts Manager")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertIn(
			{"user": "jane@example.com", "keep_current": True, "force": True},
			self.frappe.sessions.cleared,
		)


class TestGrantsCountAsAMappedGroup(RoleGrantTestCase):
	def test_a_granted_role_keeps_the_account_enabled(self):
		self.config.disable_unmapped_users = 1
		user = self.add_existing_user()
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertLoggedIn("jane@example.com")

	def test_no_granted_role_and_nothing_else_disables(self):
		self.config.disable_unmapped_users = 1
		user = self.add_existing_user()
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["something-else"]))

		self.assertEqual(user.get("enabled"), 0)

	def test_a_granted_role_is_not_denied_login(self):
		self.config.unmapped_user_action = "Deny Login"
		self.grant("erp-accounts", "Accounts User")

		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		self.assertLoggedIn("jane@example.com")
