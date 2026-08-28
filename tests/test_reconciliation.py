"""Reconciliation: what happens to a Frappe user after someone leaves the directory.

Their sessions end and they cannot sign in, but the Frappe user stays enabled with
every role it was given - a seat, an assignee, and whatever local credentials it has.
Nothing in OpenID Connect reports that, so the directory is asked directly.
"""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class ReconciliationTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import reconciliation

		self.reconciliation = reconciliation
		self.config.enable_reconciliation = 1
		self.config.directory_type = "Keycloak"
		self.config.directory_url = "https://idp.example.com/realms/erp"
		self.config.absent_user_action = "Disable User"
		self.map_group_to_role_profile("/erp/sales", "Sales Profile")
		self.map_group_to_role_profile("/erp/accounts", "Accounts Profile")

	def add_linked_user(self, email, subject, **fields):
		fields.setdefault("enabled", 1)
		user = self.frappe.user_store.add(email=email, **fields)
		user.set_social_login_userid(PROVIDER, userid=subject)
		return user

	def run_reconciliation(self, directory_users, dry_run=False):
		with mock.patch.object(
			self.reconciliation, "get_directory", return_value=mock.Mock(get_users=lambda: directory_users)
		):
			return self.reconciliation.run_reconciliation(PROVIDER, dry_run=dry_run)

	def directory_user(self, email, subject, groups=("/erp/sales",), enabled=True):
		return {"subject": subject, "email": email, "enabled": enabled, "groups": list(groups)}


class TestDeprovisioning(ReconciliationTestCase):
	def test_a_user_gone_from_the_directory_is_disabled_and_stripped(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual([entry["user"] for entry in report["absent"]], ["jane@example.com"])
		self.assertEqual(user.get("enabled"), 0)
		self.assertIsNone(user.get("role_profile_name"))
		self.assertEqual(self.roles_of(user), [])

	def test_a_user_disabled_at_the_provider_is_disabled_here(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1", enabled=False),
				self.directory_user("john@example.com", "sub-2"),
			]
		)

		self.assertEqual([e["user"] for e in report["disabled_at_provider"]], ["jane@example.com"])
		self.assertEqual(user.get("enabled"), 0)

	def test_their_sessions_are_ended_too(self):
		self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")
		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertIn(
			{"user": "jane@example.com", "keep_current": False, "force": True},
			self.frappe.sessions.cleared,
		)

	def test_report_only_changes_nothing(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")
		self.config.absent_user_action = "Report Only"

		report = self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(len(report["absent"]), 1)
		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")

	def test_remove_all_roles_keeps_the_account(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")
		self.config.absent_user_action = "Remove All Roles"

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(user.get("enabled"), 1)
		self.assertIsNone(user.get("role_profile_name"))


class TestGroupChanges(ReconciliationTestCase):
	def test_a_group_removal_reaches_frappe_without_a_login(self):
		"""The gap this closes: group membership is not a session event, so nothing is
		sent when it changes, and the user may never log in again."""
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/accounts"])]
		)

		self.assertEqual(user.get("role_profile_name"), "Accounts Profile")
		self.assertEqual([c["user"] for c in report["roles_changed"]], ["jane@example.com"])

	def test_losing_every_mapped_group_strips_the_roles(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")

		self.run_reconciliation([self.directory_user("jane@example.com", "sub-1", groups=[])])

		self.assertIsNone(user.get("role_profile_name"))
		self.assertEqual(self.roles_of(user), [])

	def test_an_unchanged_user_is_left_alone(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(report["unchanged"], ["jane@example.com"])
		self.assertEqual(self.frappe.sessions.cleared, [])
		self.assertEqual(user.save_count, 0)


class TestSafetyRails(ReconciliationTestCase):
	def test_an_empty_directory_is_refused(self):
		"""A directory that answers with nothing is broken far more often than empty."""
		self.add_linked_user("jane@example.com", "sub-1")

		with self.assertRaises(Exception):
			self.run_reconciliation([])

	def test_a_run_that_would_deprovision_most_users_is_refused(self):
		for index in range(4):
			self.add_linked_user(f"user{index}@example.com", f"sub-{index}")

		with self.assertRaises(Exception):
			self.run_reconciliation([self.directory_user("user0@example.com", "sub-0")])

		self.assertEqual(self.frappe.user_store.users["user1@example.com"].get("enabled"), 1)

	def test_reserved_accounts_are_never_touched(self):
		admin = self.frappe.user_store.add(email="admin@example.com", enabled=1)
		admin._data["name"] = "Administrator"
		self.frappe.user_store.users["Administrator"] = admin
		del self.frappe.user_store.users["admin@example.com"]
		admin.set_social_login_userid(PROVIDER, userid="sub-admin")
		self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(
			[entry["user"] for entry in report["skipped"]], ["Administrator"]
		)
		self.assertEqual(admin.get("enabled"), 1)

	def test_a_dry_run_writes_nothing(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[self.directory_user("john@example.com", "sub-2")], dry_run=True
		)

		self.assertTrue(report["dry_run"])
		self.assertEqual(len(report["absent"]), 1)
		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")

	def test_users_who_never_signed_in_through_the_provider_are_untouched(self):
		"""Nothing ties them to a directory entry, so they are not ours to act on."""
		local = self.frappe.user_store.add(email="local@example.com", enabled=1)
		self.add_linked_user("jane@example.com", "sub-1")

		self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(local.get("enabled"), 1)


class TestDisablingUnmappedUsers(ReconciliationTestCase):
	"""The same verdict the login reaches, for the users who never log in again."""

	def setUp(self):
		super().setUp()
		self.config.disable_unmapped_users = 1
		self.config.absent_user_action = "Report Only"

	def test_a_user_whose_groups_map_to_nothing_is_disabled(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1", groups=["/other/thing"]),
				self.directory_user("john@example.com", "sub-2"),
			]
		)

		self.assertEqual([entry["user"] for entry in report["unmapped"]], ["jane@example.com"])
		self.assertEqual(user.get("enabled"), 0)
		self.assertIsNone(user.get("role_profile_name"))
		self.assertIn(
			{"user": "jane@example.com", "keep_current": False, "force": True},
			self.frappe.sessions.cleared,
		)

	def test_it_changes_nothing_with_the_option_off(self):
		self.config.disable_unmapped_users = 0
		user = self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/other/thing"])]
		)

		self.assertEqual(report["unmapped"], [])
		self.assertEqual(user.get("enabled"), 1)

	def test_a_user_the_directory_vouches_for_again_is_enabled(self):
		user = self.add_linked_user("jane@example.com", "sub-1", enabled=0)

		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertEqual([c["user"] for c in report["roles_changed"]], ["jane@example.com"])

	def test_re_enabling_happens_even_when_the_roles_already_match(self):
		"""Nothing else revisits a user who cannot log in, so this run has to notice."""
		user = self.add_linked_user(
			"jane@example.com", "sub-1", enabled=0, role_profile_name="Sales Profile"
		)

		self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(user.get("enabled"), 1)

	def test_a_module_mapping_alone_keeps_a_user_enabled(self):
		self.config.append(
			"group_module_mappings", {"group": "/erp/viewers", "module_profile": "Restricted Modules"}
		)
		user = self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/viewers"])]
		)

		self.assertEqual(report["unmapped"], [])
		self.assertEqual(user.get("enabled"), 1)

	def test_a_dry_run_writes_nothing(self):
		user = self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1", groups=["/other/thing"]),
				self.directory_user("john@example.com", "sub-2"),
			],
			dry_run=True,
		)

		self.assertEqual(len(report["unmapped"]), 1)
		self.assertEqual(user.get("enabled"), 1)

	def test_a_run_that_would_disable_most_users_is_refused(self):
		"""A groups query that comes back thin reads exactly like a mass departure."""
		for index in range(4):
			self.add_linked_user(f"user{index}@example.com", f"sub-{index}")

		with self.assertRaises(Exception):
			self.run_reconciliation(
				[self.directory_user(f"user{index}@example.com", f"sub-{index}", groups=[]) for index in range(4)]
			)

		self.assertEqual(self.frappe.user_store.users["user1@example.com"].get("enabled"), 1)

	def test_the_last_enabled_system_manager_is_kept(self):
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "System Manager"}]
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1", groups=["/other/thing"]),
				self.directory_user("john@example.com", "sub-2"),
			]
		)

		self.assertEqual(user.get("enabled"), 1)
		# The entitlements still go: only the account itself is protected.
		self.assertEqual(self.roles_of(user), [])


class TestDisablingUnmappedUsersOverTheWebhook(ReconciliationTestCase):
	def setUp(self):
		super().setUp()
		self.config.disable_unmapped_users = 1
		self.config.absent_user_action = "Report Only"

	def reconcile_user(self, entry, subject="sub-1"):
		with mock.patch.object(
			self.reconciliation,
			"get_directory",
			return_value=mock.Mock(get_user=lambda **kwargs: entry),
		):
			return self.reconciliation.reconcile_user(PROVIDER, subject=subject)

	def test_a_group_removal_disables_the_account_at_once(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")

		result = self.reconcile_user(
			self.directory_user("jane@example.com", "sub-1", groups=["/other/thing"])
		)

		self.assertEqual(result["action"], "Disable User")
		self.assertEqual(user.get("enabled"), 0)

	def test_a_group_returning_enables_the_account_at_once(self):
		user = self.add_linked_user("jane@example.com", "sub-1", enabled=0)

		self.reconcile_user(self.directory_user("jane@example.com", "sub-1"))

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")


class TestRoleGrants(ReconciliationTestCase):
	"""Directly granted roles are reconciled too, and only the managed ones."""

	def grant(self, group, role):
		self.config.append("group_role_grants", {"group": group, "role": role})

	def test_a_group_removal_takes_the_granted_role_back(self):
		self.grant("/erp/approvers", "Accounts Manager")
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "Accounts Manager"}]
		)

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/sales"])]
		)

		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])
		self.assertEqual(report["roles_changed"][0]["roles_from"], ["Accounts Manager"])

	def test_a_role_granted_by_hand_survives_a_run(self):
		self.grant("/erp/approvers", "Accounts Manager")
		user = self.add_linked_user("jane@example.com", "sub-1", roles=[{"role": "Projects User"}])

		self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/approvers"])]
		)

		self.assertEqual(self.roles_of(user), ["Projects User", "Accounts Manager"])

	def test_a_user_whose_grants_already_match_is_left_alone(self):
		self.grant("/erp/approvers", "Accounts Manager")
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "Accounts Manager"}]
		)

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/approvers"])]
		)

		self.assertEqual(report["unchanged"], ["jane@example.com"])
		self.assertEqual(user.save_count, 0)

	def test_a_granted_role_counts_as_a_mapped_group(self):
		self.config.disable_unmapped_users = 1
		self.grant("/erp/approvers", "Accounts Manager")
		user = self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["/erp/approvers"])]
		)

		self.assertEqual(report["unmapped"], [])
		self.assertEqual(user.get("enabled"), 1)
