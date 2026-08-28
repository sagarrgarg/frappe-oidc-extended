"""The directory clients, against the API shapes the providers document."""

from unittest import mock

from tests.base import CallbackTestCase


class DirectoryTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import directory

		self.directory = directory

	def responses(self, *payloads):
		"""A requests.get that answers each call with the next payload."""
		remaining = list(payloads)

		def get(url, **kwargs):
			result = mock.Mock()
			result.json.return_value = remaining.pop(0) if remaining else []
			result.raise_for_status.return_value = None
			self.requested.append((url, kwargs.get("params")))
			return result

		self.requested = []
		return get


class TestKeycloakDirectory(DirectoryTestCase):
	def setUp(self):
		super().setUp()
		self.config.directory_type = "Keycloak"
		self.config.directory_url = "https://idp.example.com/realms/erp"
		self.config.directory_client_id = "erp-reconciler"
		self.config.directory_client_secret = "a-secret"

	def test_it_reads_users_and_their_group_paths(self):
		users = [{"id": "sub-1", "email": "Jane@Example.com", "enabled": True}]
		groups = [{"id": "g1", "name": "sales", "path": "/erp/sales"}]

		token = mock.Mock()
		token.json.return_value = {"access_token": "an-access-token"}
		token.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "post", return_value=token) as post:
			with mock.patch.object(self.directory.requests, "get", side_effect=self.responses(users, groups)):
				result = self.directory.get_directory(self.config).get_users()

		self.assertEqual(
			result,
			[{"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/sales"]}],
		)
		self.assertEqual(post.call_args.kwargs["data"]["grant_type"], "client_credentials")

	def test_it_queries_the_admin_api_of_the_realm(self):
		token = mock.Mock()
		token.json.return_value = {"access_token": "an-access-token"}
		token.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "post", return_value=token):
			with mock.patch.object(self.directory.requests, "get", side_effect=self.responses([])):
				self.directory.get_directory(self.config).get_users()

		self.assertEqual(self.requested[0][0], "https://idp.example.com/admin/realms/erp/users")

	def test_a_user_without_an_email_address_is_still_read(self):
		users = [{"id": "sub-1", "enabled": False}]
		token = mock.Mock()
		token.json.return_value = {"access_token": "t"}
		token.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "post", return_value=token):
			with mock.patch.object(self.directory.requests, "get", side_effect=self.responses(users, [])):
				result = self.directory.get_directory(self.config).get_users()

		self.assertEqual(result[0]["email"], "")
		self.assertFalse(result[0]["enabled"])


class TestAuthentikDirectory(DirectoryTestCase):
	def setUp(self):
		super().setUp()
		self.config.directory_type = "Authentik"
		self.config.directory_url = "https://auth.example.com"
		self.config.directory_api_token = "a-token"

	def test_it_reads_users_and_group_names(self):
		page = {
			"results": [
				{
					"pk": 7,
					"email": "Jane@Example.com",
					"is_active": True,
					"groups_obj": [{"name": "erp-sales"}],
				}
			],
			"pagination": {"next": 0},
		}

		with mock.patch.object(self.directory.requests, "get", side_effect=self.responses(page)):
			result = self.directory.get_directory(self.config).get_users()

		self.assertEqual(
			result,
			[{"subject": None, "email": "jane@example.com", "enabled": True, "groups": ["erp-sales"]}],
		)

	def test_it_follows_pagination(self):
		first = {"results": [{"email": "a@example.com", "is_active": True}], "pagination": {"next": 2}}
		second = {"results": [{"email": "b@example.com", "is_active": True}], "pagination": {"next": 0}}

		with mock.patch.object(self.directory.requests, "get", side_effect=self.responses(first, second)):
			result = self.directory.get_directory(self.config).get_users()

		self.assertEqual([entry["email"] for entry in result], ["a@example.com", "b@example.com"])


class TestDirectorySelection(DirectoryTestCase):
	def test_an_unconfigured_directory_type_is_refused(self):
		self.config.directory_type = None

		with self.assertRaises(Exception):
			self.directory.get_directory(self.config)

	def test_a_missing_directory_url_is_refused(self):
		self.config.directory_type = "Keycloak"
		self.config.directory_url = None

		with self.assertRaises(Exception):
			self.directory.get_directory(self.config)


class TestSkippingTheGroupFetch(TestKeycloakDirectory):
	"""Keycloak does not return group membership with the user list, so asking for it
	costs one request per user. A site that does not manage roles never reads them, and
	that difference is what makes a fifteen-minute sweep possible on a real realm."""

	def keycloak(self, *payloads, with_groups=True):
		token = mock.Mock()
		token.json.return_value = {"access_token": "an-access-token"}
		token.raise_for_status.return_value = None

		with mock.patch.object(self.directory.requests, "post", return_value=token):
			with mock.patch.object(
				self.directory.requests, "get", side_effect=self.responses(*payloads)
			):
				return self.directory.get_directory(self.config).get_users(with_groups=with_groups)

	def test_the_groups_are_read_by_default(self):
		users = [{"id": "sub-1", "email": "jane@example.com", "enabled": True}]
		groups = [{"id": "g1", "name": "sales", "path": "/erp/sales"}]

		result = self.keycloak(users, groups)

		self.assertEqual(result[0]["groups"], ["/erp/sales"])
		self.assertEqual(len(self.requested), 2)

	def test_one_request_serves_the_whole_page_when_they_are_not(self):
		users = [
			{"id": "sub-1", "email": "jane@example.com", "enabled": True},
			{"id": "sub-2", "email": "john@example.com", "enabled": False},
		]

		result = self.keycloak(users, with_groups=False)

		self.assertEqual([user["enabled"] for user in result], [True, False])
		self.assertEqual([user["groups"] for user in result], [[], []])
		self.assertEqual(len(self.requested), 1)
