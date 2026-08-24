"""Point 5: creating a Frappe user for an unknown login must be a deliberate choice."""

from tests.base import CallbackTestCase


class TestUserProvisioning(CallbackTestCase):
	def test_the_social_login_key_setting_is_followed_by_default(self):
		self.social_login_key.sign_ups = "Allow"
		self.run_callback()

		self.assertLoggedIn("jane@example.com")

	def test_a_provider_that_disallows_signup_does_not_get_a_user(self):
		self.social_login_key.sign_ups = "Deny"
		self.run_callback()

		self.assertWebPage(http_status_code=403, title_contains="signup")
		self.assertNotLoggedIn()
		self.assertEqual(self.frappe.user_store.users, {})

	def test_an_unset_social_login_key_falls_back_to_the_site_signup_setting(self):
		self.social_login_key.sign_ups = None
		self.frappe.flags.signup_disabled = True
		self.run_callback()

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_always_create_users_overrides_the_social_login_key(self):
		self.social_login_key.sign_ups = "Deny"
		self.config.user_provisioning = "Always Create Users"
		self.run_callback()

		self.assertLoggedIn("jane@example.com")

	def test_never_create_users_overrides_the_social_login_key(self):
		self.social_login_key.sign_ups = "Allow"
		self.config.user_provisioning = "Never Create Users"
		self.run_callback()

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_existing_users_log_in_even_when_provisioning_is_off(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=1)
		self.config.user_provisioning = "Never Create Users"
		self.run_callback()

		self.assertLoggedIn("jane@example.com")
