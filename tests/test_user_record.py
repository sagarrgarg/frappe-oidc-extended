"""What a login writes onto the Frappe user besides roles."""

from unittest import mock

from tests.base import CallbackTestCase
from tests.frappe_stub import DuplicateEntryError


class TestUserNames(CallbackTestCase):
	def test_the_name_of_an_existing_user_follows_the_claims(self):
		user = self.frappe.user_store.add(
			email="jane@example.com", enabled=1, first_name="Jane", last_name="Doe"
		)
		self.run_callback(claims=self.id_token_claims(family_name="Doe-Smith"))

		self.assertEqual(user.get("last_name"), "Doe-Smith")

	def test_a_missing_claim_does_not_overwrite_a_name(self):
		"""The creation defaults must not leak onto users who already have a name."""
		user = self.frappe.user_store.add(
			email="jane@example.com", enabled=1, first_name="Jane", last_name="Doe"
		)
		claims = self.id_token_claims()
		claims.pop("given_name")
		claims.pop("family_name")
		self.run_callback(claims=claims)

		self.assertEqual(user.get("first_name"), "Jane")
		self.assertEqual(user.get("last_name"), "Doe")

	def test_a_blank_claim_does_not_overwrite_a_name(self):
		user = self.frappe.user_store.add(
			email="jane@example.com", enabled=1, first_name="Jane", last_name="Doe"
		)
		self.run_callback(claims=self.id_token_claims(given_name="   "))

		self.assertEqual(user.get("first_name"), "Jane")

	def test_a_new_user_without_name_claims_still_gets_placeholders(self):
		claims = self.id_token_claims()
		claims.pop("given_name")
		claims.pop("family_name")
		self.run_callback(claims=claims)

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("first_name"), "No first name")
		self.assertEqual(user.get("last_name"), "No last name")


class TestConcurrentFirstLogin(CallbackTestCase):
	def test_a_user_created_by_another_login_in_flight_is_reported(self):
		"""Two first logins at once: the loser used to end in a duplicate entry
		traceback on a guest-facing page."""
		self.frappe.user_store.add(email="jane@example.com", enabled=1)

		with mock.patch.object(self.callback, "find_existing_user", return_value=None):
			try:
				self.run_callback()
			except DuplicateEntryError:  # pragma: no cover - the bug this test guards
				self.fail("the duplicate entry reached the caller")

		self.assertWebPage(http_status_code=409)
		self.assertNotLoggedIn()


class TestSocialLoginKeyRobustness(CallbackTestCase):
	def test_malformed_auth_url_data_does_not_break_the_login(self):
		self.social_login_key.auth_url_data = "{not json"
		self.run_callback()

		self.assertLoggedIn("jane@example.com")
		self.assertIsNone(self.token_post.call_args.kwargs["data"]["scope"])
