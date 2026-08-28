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
			self.reconciliation,
			"get_directory",
			return_value=mock.Mock(get_users=lambda **kwargs: directory_users),
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
		# And the role, not only the flag: an enabled System Manager stripped of the
		# System Manager role leaves the site exactly as unadministrable.
		self.assertEqual(self.roles_of(user), ["System Manager"])


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


class TestRepeatedRuns(ReconciliationTestCase):
	"""A user already dealt with is not dealt with again, every hour, forever."""

	def setUp(self):
		super().setUp()
		self.config.disable_unmapped_users = 1
		self.config.absent_user_action = "Disable User"

	def test_a_disabled_unmapped_user_is_not_rewritten_on_the_next_run(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")
		directory = [
			self.directory_user("jane@example.com", "sub-1", groups=["/nowhere"]),
			self.directory_user("john@example.com", "sub-2"),
		]

		self.run_reconciliation(directory)
		saves = user.save_count
		self.frappe.sessions.cleared.clear()

		report = self.run_reconciliation(directory)

		self.assertEqual(report["unmapped"], [])
		self.assertEqual([e["user"] for e in report["settled"]], ["jane@example.com"])
		self.assertEqual(user.save_count, saves)
		self.assertEqual(self.frappe.sessions.cleared, [])

	def test_a_departed_user_is_not_rewritten_on_the_next_run(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		self.add_linked_user("john@example.com", "sub-2")
		directory = [self.directory_user("john@example.com", "sub-2")]

		self.run_reconciliation(directory)
		saves = user.save_count

		report = self.run_reconciliation(directory)

		self.assertEqual(report["absent"], [])
		self.assertEqual([e["user"] for e in report["settled"]], ["jane@example.com"])
		self.assertEqual(user.save_count, saves)

	def test_report_only_keeps_reporting_because_that_is_all_it_does(self):
		self.config.absent_user_action = "Report Only"
		self.config.disable_unmapped_users = 0
		self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")
		directory = [self.directory_user("john@example.com", "sub-2")]

		self.run_reconciliation(directory)
		report = self.run_reconciliation(directory)

		self.assertEqual([e["user"] for e in report["absent"]], ["jane@example.com"])

	def test_settled_users_stop_counting_towards_the_mass_change_guard(self):
		"""Otherwise a site whose leavers accumulate past half stops reconciling at all."""
		for index in range(6):
			self.add_linked_user(f"gone{index}@example.com", f"gone-{index}", enabled=0)
		for index in range(4):
			self.add_linked_user(
				f"here{index}@example.com", f"here-{index}", role_profile_name="Accounts Profile"
			)

		report = self.run_reconciliation(
			[self.directory_user(f"here{index}@example.com", f"here-{index}") for index in range(4)]
		)

		self.assertEqual(len(report["settled"]), 6)
		self.assertEqual(len(report["roles_changed"]), 4)
		self.assertEqual(
			self.frappe.user_store.users["here0@example.com"].get("role_profile_name"),
			"Sales Profile",
		)


class TestRepeatedWebhookCalls(ReconciliationTestCase):
	"""An event listener can be chatty; a settled user is not rewritten each time."""

	def reconcile_user(self, entry):
		with mock.patch.object(
			self.reconciliation,
			"get_directory",
			return_value=mock.Mock(get_user=lambda **kwargs: entry),
		):
			return self.reconciliation.reconcile_user(PROVIDER, subject="sub-1")

	def test_a_departed_user_is_deprovisioned_once(self):
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")

		self.assertEqual(self.reconcile_user(None)["action"], "Disable User")
		saves = user.save_count

		self.assertEqual(self.reconcile_user(None)["action"], "unchanged")
		self.assertEqual(user.save_count, saves)

	def test_an_unmapped_user_is_disabled_once(self):
		self.config.disable_unmapped_users = 1
		user = self.add_linked_user("jane@example.com", "sub-1", role_profile_name="Sales Profile")
		entry = self.directory_user("jane@example.com", "sub-1", groups=["/nowhere"])

		self.assertEqual(self.reconcile_user(entry)["action"], "Disable User")
		saves = user.save_count

		self.assertEqual(self.reconcile_user(entry)["action"], "unchanged")
		self.assertEqual(user.save_count, saves)


class TestNoChurn(ReconciliationTestCase):
	"""A run that cannot change anything must not keep trying."""

	def test_a_profile_and_a_matching_grant_settle_instead_of_looping(self):
		"""Frappe rewrites the role table from the profile, so the grant never lands.
		Reporting it as a change every run rewrote the user and ended their sessions
		hourly, forever, without ever applying anything."""
		self.config.append(
			"group_role_grants", {"group": "/erp/approvers", "role": "Accounts Manager"}
		)
		user = self.add_linked_user(
			"jane@example.com",
			"sub-1",
			role_profile_name="Sales Profile",
			roles=[{"role": "Sales User"}, {"role": "Sales Manager"}],
		)
		directory = [
			self.directory_user("jane@example.com", "sub-1", groups=["/erp/sales", "/erp/approvers"])
		]

		for _ in range(3):
			report = self.run_reconciliation(directory)

		self.assertEqual(report["unchanged"], ["jane@example.com"])
		self.assertEqual(user.save_count, 0)
		self.assertEqual(self.frappe.sessions.cleared, [])


class TestTheSiteKeepsAnAdministrator(ReconciliationTestCase):
	def test_two_system_managers_losing_their_groups_at_once_leaves_one(self):
		"""Both are enabled when the report is built, so the guard has to hold at the
		moment each is written, not at the moment the report was drawn up."""
		self.config.disable_unmapped_users = 1
		self.config.absent_user_action = "Report Only"
		self.add_linked_user("a@example.com", "sub-a", roles=[{"role": "System Manager"}])
		self.add_linked_user("b@example.com", "sub-b", roles=[{"role": "System Manager"}])
		for index in range(6):
			self.add_linked_user(f"u{index}@example.com", f"sub-u{index}")

		directory = [
			self.directory_user("a@example.com", "sub-a", groups=["/nowhere"]),
			self.directory_user("b@example.com", "sub-b", groups=["/nowhere"]),
		] + [self.directory_user(f"u{index}@example.com", f"sub-u{index}") for index in range(6)]

		self.run_reconciliation(directory)

		administrable = [
			name
			for name, user in self.frappe.user_store.users.items()
			if user.get("enabled")
			and any(row.get("role") == "System Manager" for row in user.get("roles", []))
		]
		self.assertEqual(administrable, ["b@example.com"])

	def test_a_departed_system_manager_who_is_the_last_one_is_left_alone(self):
		self.config.absent_user_action = "Disable User"
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "System Manager"}]
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(self.roles_of(user), ["System Manager"])

	def test_remove_all_roles_does_not_strip_the_last_one_either(self):
		self.config.absent_user_action = "Remove All Roles"
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "System Manager"}]
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(self.roles_of(user), ["System Manager"])


class TestReconcilingEveryEnabledUser(ReconciliationTestCase):
	"""By default only users who have signed in through the provider are considered - a
	social login row is the one thing tying a Frappe user to a directory entry. That is
	too narrow for a site whose reason for running this is offboarding: an account made
	here by hand belongs to a real person, and when they leave nothing closes it."""

	def add_local_user(self, email, **fields):
		fields.setdefault("enabled", 1)
		fields.setdefault("user_type", "System User")
		return self.frappe.user_store.add(email=email, **fields)

	def test_by_default_a_user_who_has_never_signed_in_is_untouched(self):
		local = self.add_local_user("local@example.com")
		self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(local.get("enabled"), 1)
		self.assertNotIn("local@example.com", [entry["user"] for entry in report["absent"]])

	def test_with_the_option_on_they_are_matched_by_email_and_disabled(self):
		self.config.reconcile_all_users = 1
		local = self.add_local_user("local@example.com")
		self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1"),
				self.directory_user("john@example.com", "sub-2"),
			]
		)

		self.assertEqual([entry["user"] for entry in report["absent"]], ["local@example.com"])
		self.assertEqual(local.get("enabled"), 0)

	def test_a_local_user_the_directory_does_have_is_reconciled_normally(self):
		self.config.reconcile_all_users = 1
		local = self.add_local_user("local@example.com")

		self.run_reconciliation(
			[self.directory_user("local@example.com", "sub-local", groups=["/erp/accounts"])]
		)

		self.assertEqual(local.get("enabled"), 1)
		self.assertEqual(local.get("role_profile_name"), "Accounts Profile")

	def test_an_exempt_user_is_never_acted_on(self):
		"""A service account cannot be told apart from somebody who has left."""
		self.config.reconcile_all_users = 1
		self.config.append(
			"reconciliation_exempt_users",
			{"user": "integration@example.com", "reason": "the warehouse scanner"},
		)
		service = self.add_local_user("integration@example.com")
		self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation(
			[
				self.directory_user("jane@example.com", "sub-1"),
				self.directory_user("john@example.com", "sub-2"),
			]
		)

		self.assertEqual(service.get("enabled"), 1)
		self.assertEqual(report["absent"], [])

	def test_portal_accounts_are_never_swept_in(self):
		"""Customers, suppliers and applicants are enabled users who will never be in a
		staff directory. Sweeping them in reads every one of them as somebody who has
		left, and there can be thousands - the exemption list is no answer to that."""
		self.config.reconcile_all_users = 1
		customer = self.frappe.user_store.add(
			email="customer@shop.example", enabled=1, user_type="Website User"
		)
		self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(report["absent"], [])
		self.assertEqual(customer.get("enabled"), 1)

	def test_someone_who_has_signed_in_is_covered_whatever_their_user_type(self):
		"""Including the accounts this app creates, which default to Website User."""
		self.config.reconcile_all_users = 1
		user = self.add_linked_user("jane@example.com", "sub-1", user_type="Website User")
		for index in range(3):
			self.add_linked_user(f"staff{index}@example.com", f"staff-{index}")

		self.run_reconciliation(
			[self.directory_user(f"staff{index}@example.com", f"staff-{index}") for index in range(3)]
		)

		self.assertEqual(user.get("enabled"), 0)

	def test_a_disabled_local_user_is_not_swept_in(self):
		"""The widened sweep is about the people currently working here."""
		self.config.reconcile_all_users = 1
		gone = self.add_local_user("gone@example.com", enabled=0)
		self.add_linked_user("jane@example.com", "sub-1")

		report = self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertNotIn(
			"gone@example.com",
			[entry["user"] for entry in report["absent"] + report["settled"]],
		)
		self.assertEqual(gone.get("enabled"), 0)

	def test_a_disabled_linked_user_is_still_swept_in_so_they_can_return(self):
		self.config.reconcile_all_users = 1
		self.config.disable_unmapped_users = 1
		user = self.add_linked_user("jane@example.com", "sub-1", enabled=0)

		self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(user.get("enabled"), 1)

	def test_the_mass_change_guard_still_applies_to_the_wider_set(self):
		self.config.reconcile_all_users = 1
		for index in range(4):
			self.add_local_user(f"local{index}@example.com")
		self.add_linked_user("jane@example.com", "sub-1")

		with self.assertRaises(Exception):
			self.run_reconciliation([self.directory_user("jane@example.com", "sub-1")])

		self.assertEqual(self.frappe.user_store.users["local0@example.com"].get("enabled"), 1)
