"""Disabling the account, not only the session, of a user whose groups grant nothing.

"Deny Login" refuses the session and leaves the account enabled behind it: its API
keys still authenticate, it still holds its roles, it still counts as a seat, and its
local password is still whatever it is. None of that is the identity provider's to
revoke. This option closes the account instead, and composes with "When No Group
Matches" rather than replacing it - so a site can gate access by group membership
while the app never touches anybody's roles.
"""

from tests.base import CallbackTestCase


class DisableUnmappedTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		self.config.disable_unmapped_users = 1
		self.map_group_to_role_profile("erp-sales", "Sales Profile")

	def unmapped_login(self, **kwargs):
		return self.run_callback(claims=self.id_token_claims(groups=["not-mapped"], **kwargs))

	def warnings(self):
		return [message for level, message in self.frappe.logger_calls if level == "warning"]


class TestTheMatrix(DisableUnmappedTestCase):
	"""Each cell of the table: the option decides the account, the action the roles."""

	def test_keep_existing_roles_disables_without_touching_the_roles(self):
		user = self.add_existing_user(
			role_profile_name="Sales Profile", roles=[{"role": "Sales User"}]
		)
		self.config.unmapped_user_action = "Keep Existing Roles"

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 0)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		# Frappe re-derives the role table from the retained profile on save.
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])
		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_remove_all_roles_strips_and_disables(self):
		user = self.add_existing_user(
			role_profile_name="Sales Profile",
			roles=[{"role": "Sales User"}],
			module_profile="Restricted Modules",
		)
		self.config.unmapped_user_action = "Remove All Roles"

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 0)
		self.assertIsNone(user.get("role_profile_name"))
		self.assertEqual(self.roles_of(user), [])
		self.assertIsNone(user.get("module_profile"))
		self.assertNotLoggedIn()

	def test_deny_login_disables_as_well_as_refusing(self):
		user = self.add_existing_user(role_profile_name="Sales Profile")
		self.config.unmapped_user_action = "Deny Login"

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 0)
		# The action still governs the roles, and "Deny Login" says nothing about them.
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_off_by_default_leaves_todays_behaviour_alone(self):
		self.config.disable_unmapped_users = 0
		user = self.add_existing_user(role_profile_name="Sales Profile")

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertLoggedIn("jane@example.com")


class TestWhatCountsAsMapped(DisableUnmappedTestCase):
	def test_a_matched_group_leaves_the_account_alone(self):
		user = self.add_existing_user()

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertLoggedIn("jane@example.com")

	def test_a_module_mapping_alone_is_enough(self):
		"""A site may gate access through module mappings and no role mappings at all."""
		user = self.add_existing_user()
		self.config.append(
			"group_module_mappings", {"group": "erp-viewers", "module_profile": "Restricted Modules"}
		)

		self.run_callback(claims=self.id_token_claims(groups=["erp-viewers"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("module_profile"), "Restricted Modules")
		self.assertLoggedIn("jane@example.com")

	def test_a_fallback_role_profile_is_enough(self):
		user = self.add_existing_user()
		self.set_fallback_role_profiles("Employee Profile")

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)
		self.assertLoggedIn("jane@example.com")

	def test_a_fallback_module_profile_is_enough(self):
		user = self.add_existing_user()
		self.config.fallback_module_profile = "Restricted Modules"

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)
		self.assertLoggedIn("jane@example.com")

	def test_groups_match_by_exact_string(self):
		user = self.add_existing_user()

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales-readonly"]))

		self.assertEqual(user.get("enabled"), 0)

	def test_an_imported_row_with_no_profile_is_not_a_match(self):
		"""Otherwise a half-filled table shadows the fallback and locks people out."""
		user = self.add_existing_user()
		self.set_fallback_role_profiles("Employee Profile")
		self.config.append("group_role_mappings", {"group": "erp-imported", "role_profile": None})
		self.config.append("group_module_mappings", {"group": "erp-imported", "module_profile": None})

		self.run_callback(claims=self.id_token_claims(groups=["erp-imported"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Employee Profile")
		self.assertLoggedIn("jane@example.com")

	def test_an_imported_row_with_no_profile_and_no_fallback_disables(self):
		user = self.add_existing_user()
		self.config.append("group_role_mappings", {"group": "erp-imported", "role_profile": None})

		self.run_callback(claims=self.id_token_claims(groups=["erp-imported"]))

		self.assertEqual(user.get("enabled"), 0)


class TestComingBack(DisableUnmappedTestCase):
	def test_a_disabled_user_whose_group_returns_is_enabled_again(self):
		"""Without this, a membership removed by mistake disables someone for good."""
		user = self.add_existing_user(enabled=0)

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertLoggedIn("jane@example.com")

	def test_a_disabled_user_is_still_refused_with_the_option_off(self):
		self.config.disable_unmapped_users = 0
		user = self.add_existing_user(enabled=0)

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(user.get("enabled"), 0)
		self.assertNotLoggedIn()
		self.assertWebPage(title_contains="Not Allowed")

	def test_an_already_disabled_user_with_no_group_is_refused_without_a_write(self):
		user = self.add_existing_user(enabled=0)

		self.unmapped_login()

		self.assertEqual(user.save_count, 0)
		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()


class TestSessionsAndLogging(DisableUnmappedTestCase):
	def test_the_sessions_of_a_disabled_user_are_ended(self):
		"""A live session outlives the flag, which is most of what disabling was for."""
		self.add_existing_user()

		self.unmapped_login()

		self.assertIn(
			{"user": "jane@example.com", "keep_current": False, "force": True},
			self.frappe.sessions.cleared,
		)
		self.assertIn({"user": "jane@example.com"}, self.frappe.cleared_caches)

	def test_the_decision_is_logged_with_the_address_and_the_groups(self):
		self.add_existing_user()

		self.unmapped_login()

		logged = "\n".join(self.warnings())
		self.assertIn("jane@example.com", logged)
		self.assertIn("not-mapped", logged)
		self.assertIn("Disabling jane@example.com", logged)


class TestNewUsers(DisableUnmappedTestCase):
	def test_no_account_is_created_for_someone_whose_groups_grant_nothing(self):
		self.unmapped_login()

		self.assertEqual(self.frappe.user_store.users, {})
		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_an_account_is_still_created_for_someone_who_is_mapped(self):
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(self.frappe.user_store.users["jane@example.com"].get("enabled"), 1)
		self.assertLoggedIn("jane@example.com")


class TestGuards(DisableUnmappedTestCase):
	"""Two accounts are never closed, however the identity provider answers."""

	def test_the_last_enabled_system_manager_is_kept(self):
		user = self.add_existing_user(roles=[{"role": "System Manager"}])

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)
		self.assertIn(
			"Not disabling jane@example.com: jane@example.com is the last enabled System Manager on this site",
			"\n".join(self.warnings()),
		)

	def test_the_login_carries_on_when_the_guard_fires(self):
		"""Refusing them as well would lock the site out through the same door."""
		self.add_existing_user(roles=[{"role": "System Manager"}])

		self.unmapped_login()

		self.assertLoggedIn("jane@example.com")

	def test_deny_login_still_refuses_when_the_guard_fires(self):
		"""The guard protects the account, not a setting that was already refusing them."""
		user = self.add_existing_user(roles=[{"role": "System Manager"}])
		self.config.unmapped_user_action = "Deny Login"

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)
		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_one_of_several_system_managers_is_disabled(self):
		user = self.add_existing_user(roles=[{"role": "System Manager"}])
		self.frappe.user_store.add(
			email="other@example.com", enabled=1, roles=[{"role": "System Manager"}]
		)

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 0)

	def test_a_disabled_second_system_manager_does_not_count(self):
		user = self.add_existing_user(roles=[{"role": "System Manager"}])
		self.frappe.user_store.add(
			email="other@example.com", enabled=0, roles=[{"role": "System Manager"}]
		)

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)

	def test_administrator_holding_the_role_does_not_count(self):
		"""It cannot log in through this app, so it is not a way back into the site."""
		user = self.add_existing_user(roles=[{"role": "System Manager"}])
		admin = self.frappe.user_store.add(
			email="admin@example.com", enabled=1, roles=[{"role": "System Manager"}]
		)
		admin._data["name"] = "Administrator"
		self.frappe.user_store.users["Administrator"] = admin
		del self.frappe.user_store.users["admin@example.com"]

		self.unmapped_login()

		self.assertEqual(user.get("enabled"), 1)

	def test_the_built_in_accounts_are_never_disabled(self):
		for name in ("Administrator", "Guest"):
			user = self.frappe.user_store.add(email=f"{name}@example.com", enabled=1)
			user._data["name"] = name

			self.assertFalse(self.callback.disable_user(user, "a reason"))
			self.assertEqual(user.get("enabled"), 1)
