"""Sign-in and offboarding only: the identity provider opens and closes the account,
the ERP decides what the account may do.

Mapping directory groups to ERP roles is work to keep in step, and below a certain size
it is more work than the mapping saves. The honest configuration for such a site is not
an empty mapping table - which still runs the mapping code, and still has an opinion
when somebody half-fills it in - but no mapping at all.
"""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class SignInOnlyTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		self.config.use_groups = 0
		# Configured, and none of it may be read.
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.config.append("group_role_grants", {"group": "erp-sales", "role": "Accounts User"})
		self.config.append(
			"group_module_mappings", {"group": "erp-sales", "module_profile": "Sales Modules"}
		)
		self.set_fallback_role_profiles("Employee Profile")


class TestLoginLeavesTheRolesAlone(SignInOnlyTestCase):
	def test_an_existing_user_keeps_exactly_the_roles_the_erp_gave_them(self):
		# Roles assigned by hand and no role profile, which is what a site running this
		# mode looks like.
		user = self.add_existing_user(
			roles=[{"role": "Accounts User"}, {"role": "Projects User"}],
			module_profile="Restricted Modules",
		)
		before = {
			"roles": self.roles_of(user),
			"role_profile_name": user.get("role_profile_name"),
			"module_profile": user.get("module_profile"),
		}

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(self.roles_of(user), before["roles"])
		self.assertEqual(user.get("role_profile_name"), before["role_profile_name"])
		self.assertEqual(user.get("module_profile"), before["module_profile"])
		self.assertLoggedIn("jane@example.com")

	def test_a_group_that_maps_to_nothing_changes_nothing_either(self):
		user = self.add_existing_user(roles=[{"role": "Projects User"}])

		self.run_callback(claims=self.id_token_claims(groups=["not-mapped-anywhere"]))

		self.assertEqual(self.roles_of(user), ["Projects User"])
		self.assertLoggedIn("jane@example.com")

	def test_none_of_the_mapping_code_runs_at_all(self):
		"""Not "computed and discarded" - a bug in any of it cannot reach this site."""
		self.add_existing_user(roles=[{"role": "Projects User"}])

		with mock.patch.object(
			self.callback, "apply_entitlements", side_effect=AssertionError("was called")
		):
			self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertLoggedIn("jane@example.com")

	def test_the_access_gating_settings_are_not_consulted(self):
		self.config.unmapped_user_action = "Deny Login"
		self.config.disable_unmapped_users = 1
		user = self.add_existing_user(roles=[{"role": "Projects User"}])

		self.run_callback(claims=self.id_token_claims(groups=["not-mapped-anywhere"]))

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(self.roles_of(user), ["Projects User"])
		self.assertLoggedIn("jane@example.com")

	def test_a_new_user_is_still_created_and_signed_in(self):
		self.run_callback(claims=self.id_token_claims(groups=["whatever"]))

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(self.roles_of(user), [])
		self.assertLoggedIn("jane@example.com")

	def test_a_disabled_user_is_still_refused(self):
		"""Nothing re-enables anybody here: the enabled flag is not the provider's to
		set on a site that only asked it to close accounts."""
		user = self.add_existing_user(enabled=0)

		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(user.get("enabled"), 0)
		self.assertNotLoggedIn()
		self.assertWebPage(title_contains="Not Allowed")


class TestOffboarding(SignInOnlyTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import reconciliation

		self.reconciliation = reconciliation
		self.config.enable_reconciliation = 1
		self.config.directory_type = "Keycloak"
		self.config.directory_url = "https://idp.example.com/realms/erp"
		self.config.absent_user_action = "Disable User"

	def add_linked_user(self, email, subject, **fields):
		fields.setdefault("enabled", 1)
		user = self.frappe.user_store.add(email=email, **fields)
		user.set_social_login_userid(PROVIDER, userid=subject)
		return user

	def directory_user(self, email, subject, groups=("erp-sales",), enabled=True):
		return {"subject": subject, "email": email, "enabled": enabled, "groups": list(groups)}

	def run_reconciliation(self, directory_users, dry_run=False):
		with mock.patch.object(
			self.reconciliation,
			"get_directory",
			return_value=mock.Mock(get_users=lambda **kwargs: directory_users),
		):
			return self.reconciliation.run_reconciliation(PROVIDER, dry_run=dry_run)

	def test_a_user_absent_from_the_directory_is_disabled(self):
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "Accounts Manager"}]
		)
		self.add_linked_user("john@example.com", "sub-2")

		report = self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual([entry["user"] for entry in report["absent"]], ["jane@example.com"])
		self.assertEqual(user.get("enabled"), 0)

	def test_their_roles_are_left_exactly_as_the_erp_set_them(self):
		user = self.add_linked_user(
			"jane@example.com",
			"sub-1",
			roles=[{"role": "Accounts Manager"}, {"role": "Projects User"}],
			module_profile="Restricted Modules",
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(self.roles_of(user), ["Accounts Manager", "Projects User"])
		self.assertEqual(user.get("module_profile"), "Restricted Modules")

	def test_a_role_profile_is_still_re_derived_when_the_account_is_closed(self):
		"""Frappe, not this app: `User.validate` refills the role table from the assigned
		role profile on every save, so the save that disables somebody re-derives their
		roles from it. Roles held alongside a profile are not a state Frappe keeps in the
		first place - which is the reason to assign roles rather than profiles on a site
		that manages them by hand."""
		user = self.add_linked_user(
			"jane@example.com", "sub-1", role_profile_name="Sales Profile", roles=[]
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(user.get("enabled"), 0)
		self.assertEqual(user.get("role_profile_name"), "Sales Profile")
		self.assertEqual(self.roles_of(user), ["Sales User", "Sales Manager"])

	def test_their_sessions_are_ended(self):
		self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertIn(
			{"user": "jane@example.com", "keep_current": False, "force": True},
			self.frappe.sessions.cleared,
		)

	def test_the_last_system_manager_is_still_spared(self):
		user = self.add_linked_user(
			"jane@example.com", "sub-1", roles=[{"role": "System Manager"}]
		)
		self.add_linked_user("john@example.com", "sub-2")

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(user.get("enabled"), 1)
		self.assertEqual(self.roles_of(user), ["System Manager"])

	def test_a_user_the_directory_still_has_is_left_alone_entirely(self):
		user = self.add_linked_user("jane@example.com", "sub-1", roles=[{"role": "Projects User"}])

		report = self.run_reconciliation(
			[self.directory_user("jane@example.com", "sub-1", groups=["erp-sales"])]
		)

		self.assertEqual(report["unchanged"], ["jane@example.com"])
		self.assertEqual(self.roles_of(user), ["Projects User"])
		self.assertEqual(user.save_count, 0)

	def test_a_disabled_user_is_not_disabled_again_next_run(self):
		self.add_linked_user("jane@example.com", "sub-1", enabled=0)
		self.add_linked_user("john@example.com", "sub-2")
		directory = [self.directory_user("john@example.com", "sub-2")]

		report = self.run_reconciliation(directory)

		self.assertEqual(report["absent"], [])
		self.assertEqual([e["user"] for e in report["settled"]], ["jane@example.com"])

	def test_report_only_still_only_reports(self):
		user = self.add_linked_user("jane@example.com", "sub-1")
		self.add_linked_user("john@example.com", "sub-2")
		self.config.absent_user_action = "Report Only"

		self.run_reconciliation([self.directory_user("john@example.com", "sub-2")])

		self.assertEqual(user.get("enabled"), 1)


class TestTheSwitchIsOneField(SignInOnlyTestCase):
	"""One field decides whether the groups are used, and everything that depends on
	them is hidden with it. Deliberately exact: a group-driven field added later without
	being gated should fail here rather than sit on a form that says it does nothing."""

	def configuration(self):
		import json
		from pathlib import Path

		path = (
			Path(__file__).resolve().parents[1]
			/ "oidc_extended/oidc_extended/doctype/oidc_extended_configuration"
			/ "oidc_extended_configuration.json"
		)
		return json.loads(path.read_text())

	def test_the_switch_is_on_by_default_and_comes_first(self):
		doc = self.configuration()
		switch = [f for f in doc["fields"] if f["fieldname"] == "use_groups"]

		self.assertEqual(len(switch), 1)
		self.assertEqual(switch[0]["default"], "1")
		self.assertEqual(switch[0]["fieldtype"], "Check")
		# Before anything it governs, rather than inside a section it hides.
		self.assertEqual(doc["field_order"][:2], ["provider", "use_groups"])

	def test_everything_group_driven_hangs_off_it(self):
		doc = self.configuration()
		gated = {
			field["fieldname"]
			for field in doc["fields"]
			if field.get("depends_on") == "eval:doc.use_groups"
		}

		self.assertEqual(
			gated,
			{
				"groups_claim_name",
				"roles_section",
				"fallback_role_profiles",
				"group_role_mappings",
				"group_role_grants",
				"unmapped_user_action",
				"disable_unmapped_users",
				"modules_section",
			},
		)
