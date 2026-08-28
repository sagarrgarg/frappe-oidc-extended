"""What the User form is told about who owns a user's roles.

The form warns that an identity provider will replace an edit at the next login, and
locks the fields this app writes. That is true where the app maps groups to roles and
false where it is used to sign people in and close their accounts - and locking the
fields there would stop exactly the work that mode exists for. The form cannot read the
configuration to find out, since it is a System Manager document and the User form is
open to more people, so the answer is settled at session start.
"""

import types

from tests.base import PROVIDER, CallbackTestCase


class TestProvidersManagingRoles(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import boot

		self.boot = boot

	def add_provider(self, name, **fields):
		from tests import frappe_stub

		doc = frappe_stub.FakeDoc({"doctype": "OIDC Extended Configuration", "name": name, **fields})
		self.frappe.docs[("OIDC Extended Configuration", name)] = doc
		return doc

	def test_a_provider_that_manages_roles_is_listed(self):
		self.config.use_groups = 1

		self.assertEqual(self.boot.providers_managing_roles(), [PROVIDER])

	def test_a_provider_that_does_not_is_left_out(self):
		self.config.use_groups = 0

		self.assertEqual(self.boot.providers_managing_roles(), [])

	def test_a_configuration_predating_the_setting_counts_as_managing(self):
		"""This app has always managed roles, so an unset field is not a decision."""
		self.config._data.pop("use_groups", None)

		self.assertEqual(self.boot.providers_managing_roles(), [PROVIDER])

	def test_each_provider_is_answered_for_separately(self):
		self.config.use_groups = 0
		self.add_provider("keycloak", use_groups=1)

		self.assertEqual(self.boot.providers_managing_roles(), ["keycloak"])

	def test_the_answer_is_put_where_the_desk_looks_for_it(self):
		self.config.use_groups = 1
		bootinfo = types.SimpleNamespace()

		self.boot.boot_session(bootinfo)

		self.assertEqual(bootinfo.oidc_extended["providers_managing_roles"], [PROVIDER])

	def test_it_is_answerable_without_permission_on_the_configuration(self):
		"""frappe.get_all does not check permissions, which is the point: the form is
		open to people who cannot read a System Manager document."""
		import inspect

		source = inspect.getsource(self.boot.providers_managing_roles)
		self.assertIn("frappe.get_all", source)
		self.assertNotIn("get_list", source)
