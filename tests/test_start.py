"""Point 9: an entry point that begins a login, which Frappe itself does not expose."""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class TestStart(CallbackTestCase):
	def start(self, **kwargs):
		self.frappe.request.path = f"/api/method/oidc_extended.callback.start/{PROVIDER}"
		self.frappe.request.url = f"https://erp.example.com/api/method/oidc_extended.callback.start/{PROVIDER}"
		return self.callback.start(**kwargs)

	def test_it_redirects_to_the_authorize_url_of_the_provider_in_the_path(self):
		self.start()

		self.assertEqual(self.frappe.local.response["type"], "redirect")
		self.assertIn(f"provider={PROVIDER}", self.frappe.local.response["location"])

	def test_the_provider_may_also_be_passed_as_a_parameter(self):
		self.frappe.request.path = "/api/method/oidc_extended.callback.start"
		self.callback.start(provider=PROVIDER)

		self.assertIn(f"provider={PROVIDER}", self.frappe.local.response["location"])

	def test_an_unknown_provider_is_refused(self):
		self.frappe.request.path = "/api/method/oidc_extended.callback.start/nope"
		self.callback.start()

		self.assertWebPage(http_status_code=404)
		self.assertNotIn("location", self.frappe.local.response)

	def test_a_disabled_provider_is_refused(self):
		"""Frappe lists disabled Social Login Keys among its OAuth providers."""
		self.social_login_key.enable_social_login = 0
		self.start()

		self.assertWebPage(http_status_code=403)
		self.assertNotIn("location", self.frappe.local.response)

	def test_the_state_carries_the_requested_redirect(self):
		self.start(redirect_to="/app/sales-order")

		self.assertIn("/app/sales-order", list(self.frappe.cache.store.values()))

	def test_a_redirect_to_another_site_is_neutralised(self):
		self.start(redirect_to="https://evil.example.com/steal")

		self.assertNotIn(
			"https://evil.example.com/steal", list(self.frappe.cache.store.values())
		)

	def test_a_login_started_here_completes_at_the_callback(self):
		"""The state created by start is the one custom consumes."""
		self.start(redirect_to="/app/sales-order")
		location = self.frappe.local.response["location"]
		state = location.split("state=")[1]

		self.frappe.local.response = {}
		self.run_callback(state=state)

		self.assertLoggedIn("jane@example.com")
		self.assertEqual(self.frappe.local.response["location"], "/app/sales-order")
