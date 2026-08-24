"""Point 3: an OIDC login must find the Frappe user it belongs to."""

from tests.base import PROVIDER, CallbackTestCase
from tests.frappe_stub import DuplicateEntryError


class TestExistingUserMatching(CallbackTestCase):
	def test_a_user_that_predates_this_app_is_matched_by_email(self):
		"""The regression that breaks every login on an existing site.

		Users of a site that existed before this app was installed have a `username`
		Frappe derived from their name, never the subject claim of the identity
		provider - so the old lookup missed them and the create that followed hit a
		duplicate entry error on the email address, which is the User record's name.
		"""
		user = self.frappe.user_store.add(
			email="jane@example.com", username="jane", first_name="Jane", enabled=1
		)
		self.run_callback()

		self.assertLoggedIn("jane@example.com")
		self.assertEqual(len(self.frappe.user_store.users), 1)
		self.assertEqual(user.get("username"), "jane")

	def test_the_subject_is_recorded_as_the_social_login_userid(self):
		user = self.frappe.user_store.add(email="jane@example.com", username="jane", enabled=1)
		self.run_callback()

		claims = self.id_token_claims()
		self.assertEqual(user.get_social_login_userid(PROVIDER), claims["sub"])

	def test_a_later_login_is_matched_by_the_subject_even_if_the_email_changed(self):
		claims = self.id_token_claims()
		user = self.frappe.user_store.add(email="jane@example.com", enabled=1)
		user.set_social_login_userid(PROVIDER, userid=claims["sub"])

		self.run_callback(claims=self.id_token_claims(email="jane.doe@example.com"))

		self.assertLoggedIn("jane@example.com")
		self.assertEqual(len(self.frappe.user_store.users), 1)

	def test_a_user_provisioned_by_an_older_version_is_matched_when_asked_for(self):
		"""The username leg only: the addresses deliberately differ."""
		claims = self.id_token_claims()
		self.frappe.user_store.add(
			email="j.doe@example.com", username=claims["sub"], enabled=1
		)
		self.config.match_users_by_username = 1
		self.run_callback()

		self.assertLoggedIn("j.doe@example.com")
		self.assertEqual(len(self.frappe.user_store.users), 1)

	def test_the_username_leg_is_off_by_default(self):
		"""The user id claim is not a Frappe username; matching one to the other can
		hand an unrelated account to whoever the provider calls by that name."""
		claims = self.id_token_claims()
		self.frappe.user_store.add(
			email="j.doe@example.com", username=claims["sub"], enabled=1
		)
		self.run_callback()

		self.assertLoggedIn("jane@example.com")
		self.assertEqual(len(self.frappe.user_store.users), 2)

	def test_the_email_claim_is_matched_case_insensitively(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=1)
		self.run_callback(claims=self.id_token_claims(email="Jane@Example.COM"))

		self.assertLoggedIn("jane@example.com")
		self.assertEqual(len(self.frappe.user_store.users), 1)

	def test_a_disabled_user_may_not_log_in(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=0)
		self.run_callback()

		self.assertWebPage(title_contains="not allowed")
		self.assertNotLoggedIn()


class TestUserCreation(CallbackTestCase):
	def test_an_unknown_user_is_created_and_named_by_email(self):
		self.run_callback()

		self.assertIn("jane@example.com", self.frappe.user_store.users)
		user = self.frappe.user_store.users["jane@example.com"]
		self.assertEqual(user.get("first_name"), "Jane")
		self.assertEqual(user.get("last_name"), "Doe")
		self.assertLoggedIn("jane@example.com")

	def test_the_username_field_is_left_to_frappe(self):
		"""Frappe derives a username and blanks it on collision, so it is not ours to set."""
		self.run_callback()

		user = self.frappe.user_store.users["jane@example.com"]
		self.assertIsNone(user.get("username"))

	def test_creating_a_user_whose_email_is_taken_never_happens(self):
		self.frappe.user_store.add(email="jane@example.com", username="someone-else", enabled=1)
		try:
			self.run_callback()
		except DuplicateEntryError:  # pragma: no cover - the bug this test guards
			self.fail("the callback tried to create a user that already exists")

		self.assertLoggedIn("jane@example.com")


class TestReservedAccounts(CallbackTestCase):
	def test_the_administrator_account_cannot_be_taken_over_by_email(self):
		admin = self.frappe.user_store.add(email="admin@example.com", enabled=1)
		admin._data["name"] = "Administrator"
		self.frappe.user_store.users["Administrator"] = admin
		del self.frappe.user_store.users["admin@example.com"]

		self.run_callback(claims=self.id_token_claims(email="admin@example.com"))

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_a_subject_claiming_to_be_administrator_is_refused(self):
		self.frappe.user_store.add(email="jane@example.com", username="administrator", enabled=1)
		self.run_callback(claims=self.id_token_claims(sub="administrator"))

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()


class TestRequiredClaims(CallbackTestCase):
	def test_a_token_without_the_subject_claim_is_refused(self):
		claims = self.id_token_claims()
		claims.pop("sub")
		self.run_callback(claims=claims)

		self.assertWebPage(http_status_code=400)
		self.assertNotLoggedIn()

	def test_a_token_without_an_email_claim_is_refused(self):
		claims = self.id_token_claims()
		claims.pop("email")
		self.run_callback(claims=claims)

		self.assertWebPage(http_status_code=400)
		self.assertNotLoggedIn()

	def test_a_blank_email_claim_is_refused(self):
		self.run_callback(claims=self.id_token_claims(email="   "))

		self.assertWebPage(http_status_code=400)
		self.assertNotLoggedIn()


class TestVerifiedEmail(CallbackTestCase):
	"""Users are matched by email, so an unverified one is a way into someone's account."""

	def test_a_login_with_an_unverified_email_is_refused(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=1)
		self.run_callback(claims=self.id_token_claims(email_verified=False))

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_the_claim_is_also_understood_as_a_string(self):
		self.run_callback(claims=self.id_token_claims(email_verified="false"))

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_a_verified_email_logs_in(self):
		self.run_callback(claims=self.id_token_claims(email_verified=True))

		self.assertLoggedIn("jane@example.com")

	def test_a_provider_that_does_not_send_the_claim_is_unaffected(self):
		self.run_callback()

		self.assertLoggedIn("jane@example.com")

	def test_the_requirement_can_be_turned_off(self):
		self.config.require_verified_email = 0
		self.run_callback(claims=self.id_token_claims(email_verified=False))

		self.assertLoggedIn("jane@example.com")

	def test_no_user_is_created_for_an_unverified_email(self):
		self.run_callback(claims=self.id_token_claims(email_verified=False))

		self.assertEqual(self.frappe.user_store.users, {})


class TestSubjectOnRecord(CallbackTestCase):
	def test_a_changed_subject_replaces_the_one_on_record(self):
		"""Frappe appends social login rows and reads the first, so a stale subject
		would stay in charge of every later login and of back-channel logout."""
		user = self.frappe.user_store.add(email="jane@example.com", enabled=1)
		user.set_social_login_userid(PROVIDER, userid="the-old-subject")

		self.run_callback()

		rows = [row for row in user.get("social_logins", []) if row.get("provider") == PROVIDER]
		self.assertEqual(len(rows), 1, "a second row would shadow the new subject")
		self.assertEqual(rows[0].get("userid"), self.id_token_claims()["sub"])

	def test_an_unchanged_subject_is_left_alone(self):
		user = self.frappe.user_store.add(email="jane@example.com", enabled=1)
		user.set_social_login_userid(PROVIDER, userid=self.id_token_claims()["sub"])

		self.run_callback()

		rows = [row for row in user.get("social_logins", []) if row.get("provider") == PROVIDER]
		self.assertEqual(len(rows), 1)
