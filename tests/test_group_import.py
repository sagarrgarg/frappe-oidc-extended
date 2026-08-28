"""Reading the group vocabulary from the provider instead of typing it in.

The group names in the mappings are strings that live in another system. A typo is
silent - the row just never matches - and it stays silent until someone logs in with
no roles. With unmapped users disabled it stops being silent and becomes a lockout.
"""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class GroupImportTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import directory, groups

		self.groups = groups
		self.directory = directory
		self.config.directory_type = "Keycloak"
		self.config.directory_url = "https://idp.example.com/realms/erp"
		self.config.directory_client_id = "erp-reconciler"
		self.config.directory_client_secret = "a-secret"

	def fetch(self, names, source="the roles of the erp-ggil client"):
		with mock.patch.object(
			self.groups,
			"get_directory",
			return_value=mock.Mock(get_group_names=lambda client_id=None: (names, source)),
		):
			return self.groups.fetch_groups(PROVIDER)

	def rows(self, table):
		return [(row.get("group"), row.get("role_profile") or row.get("module_profile"))
				for row in self.config.get(table, [])]


class TestFetchingGroups(GroupImportTestCase):
	def test_it_fills_both_tables_with_the_profiles_left_blank(self):
		result = self.fetch(["ERP-Access", "ERP-Accounts"])

		self.assertEqual(
			self.rows("group_role_mappings"), [("ERP-Access", None), ("ERP-Accounts", None)]
		)
		self.assertEqual(
			self.rows("group_module_mappings"), [("ERP-Access", None), ("ERP-Accounts", None)]
		)
		self.assertEqual(result["group_role_mappings_added"], 2)
		self.assertEqual(result["group_role_mappings_present"], 0)
		self.assertEqual(result["source"], "the roles of the erp-ggil client")

	def test_it_never_touches_a_row_that_is_already_there(self):
		self.map_group_to_role_profile("ERP-Access", "Sales Profile", priority=7)

		result = self.fetch(["ERP-Access", "ERP-Accounts"])

		self.assertEqual(
			self.rows("group_role_mappings"), [("ERP-Access", "Sales Profile"), ("ERP-Accounts", None)]
		)
		self.assertEqual(self.config.group_role_mappings[0].get("priority"), 7)
		self.assertEqual(result["group_role_mappings_added"], 1)
		self.assertEqual(result["group_role_mappings_present"], 1)

	def test_running_it_again_adds_only_what_is_new(self):
		self.fetch(["ERP-Access"])
		result = self.fetch(["ERP-Access", "ERP-Accounts"])

		self.assertEqual(self.rows("group_role_mappings"), [("ERP-Access", None), ("ERP-Accounts", None)])
		self.assertEqual(result["group_role_mappings_added"], 1)

	def test_nothing_new_means_nothing_is_saved(self):
		self.fetch(["ERP-Access"])
		saves = self.config.save_count

		self.fetch(["ERP-Access"])

		self.assertEqual(self.config.save_count, saves)

	def test_a_name_the_provider_repeats_is_added_once(self):
		self.fetch(["ERP-Access", "ERP-Access", " ERP-Access "])

		self.assertEqual(self.rows("group_role_mappings"), [("ERP-Access", None)])

	def test_an_empty_answer_is_reported_rather_than_written(self):
		with self.assertRaises(Exception):
			self.fetch([])

		self.assertEqual(self.rows("group_role_mappings"), [])

	def test_a_missing_client_id_is_named_in_the_message(self):
		with mock.patch.object(
			self.groups,
			"get_directory",
			return_value=mock.Mock(
				get_group_names=mock.Mock(side_effect=self.directory.ClientNotFoundError("erp-ggil"))
			),
		):
			with self.assertRaises(Exception) as raised:
				self.groups.fetch_groups(PROVIDER)

		self.assertIn("erpnext-client-id", str(raised.exception))

	def test_missing_credentials_are_refused_before_the_provider_is_called(self):
		self.config.directory_client_secret = None

		with self.assertRaises(Exception) as raised:
			self.groups.fetch_groups(PROVIDER)

		self.assertIn("Service Account Client Secret", str(raised.exception))

	def test_a_directory_type_is_required(self):
		self.config.directory_type = None

		with self.assertRaises(Exception) as raised:
			self.groups.fetch_groups(PROVIDER)

		self.assertIn("Directory Type", str(raised.exception))

	def test_the_client_id_of_the_social_login_key_is_what_is_asked_about(self):
		asked = []

		with mock.patch.object(
			self.groups,
			"get_directory",
			return_value=mock.Mock(
				get_group_names=lambda client_id=None: (asked.append(client_id), (["ERP-Access"], "roles"))[1]
			),
		):
			self.groups.fetch_groups(PROVIDER)

		self.assertEqual(asked, ["erpnext-client-id"])


class TestKeycloakGroupNames(GroupImportTestCase):
	def responses(self, *payloads):
		remaining = list(payloads)

		def get(url, **kwargs):
			result = mock.Mock()
			result.json.return_value = remaining.pop(0) if remaining else []
			result.raise_for_status.return_value = None
			self.requested.append((url, kwargs.get("params")))
			return result

		self.requested = []
		return get

	def keycloak(self, *payloads):
		token = mock.Mock()
		token.json.return_value = {"access_token": "an-access-token"}
		token.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "post", return_value=token):
			with mock.patch.object(self.directory.requests, "get", side_effect=self.responses(*payloads)):
				return self.directory.get_directory(self.config).get_group_names("erp-ggil")

	def test_it_prefers_the_roles_of_the_client(self):
		"""Client roles are scoped to one client; realm groups are visible to them all."""
		names, source = self.keycloak(
			[{"id": "internal-uuid", "clientId": "erp-ggil"}],
			[{"name": "ERP-Access"}, {"name": "ERP-Accounts"}],
		)

		self.assertEqual(names, ["ERP-Access", "ERP-Accounts"])
		self.assertIn("erp-ggil", source)
		self.assertEqual(
			self.requested[0],
			("https://idp.example.com/admin/realms/erp/clients", {"clientId": "erp-ggil"}),
		)
		self.assertEqual(
			self.requested[1][0],
			"https://idp.example.com/admin/realms/erp/clients/internal-uuid/roles",
		)

	def test_it_falls_back_to_the_realm_groups_when_the_client_has_none(self):
		names, source = self.keycloak(
			[{"id": "internal-uuid", "clientId": "erp-ggil"}],
			[],
			[
				{
					"name": "erp",
					"path": "/erp",
					"subGroups": [{"name": "sales", "path": "/erp/sales", "subGroups": []}],
				}
			],
		)

		self.assertEqual(names, ["/erp", "/erp/sales"])
		self.assertEqual(source, "the groups of the realm")

	def test_an_unknown_client_is_an_error_rather_than_an_empty_list(self):
		with self.assertRaises(self.directory.ClientNotFoundError):
			self.keycloak([])


class TestAuthentikGroupNames(GroupImportTestCase):
	def test_it_reads_the_group_names(self):
		self.config.directory_type = "Authentik"
		self.config.directory_url = "https://idp.example.com"
		self.config.directory_api_token = "a-token"

		result = mock.Mock()
		result.json.return_value = {
			"results": [{"name": "erp-sales"}, {"name": "erp-accounts"}],
			"pagination": {"next": 0},
		}
		result.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "get", return_value=result):
			names, source = self.directory.get_directory(self.config).get_group_names("erp-ggil")

		self.assertEqual(names, ["erp-sales", "erp-accounts"])
		self.assertEqual(source, "the groups of the directory")
