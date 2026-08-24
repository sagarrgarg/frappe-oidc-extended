"""The app refuses to run on a Frappe whose OAuth state cannot be validated."""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class TestUnsupportedFrappe(CallbackTestCase):
	"""Frappe 15.116.0 and 16.30.0 introduced the single-use OAuth state.

	Everything older - including v16.0 to v16.29 - sends the base64 blob that nothing
	could validate, so the callback says so instead of failing on an import.
	"""

	def test_the_callback_reports_an_unsupported_frappe(self):
		self.frappe.__version__ = "16.29.0"
		with mock.patch.object(self.callback, "consume_oauth_state", None):
			self.callback.custom(code="auth-code", state="0" * 32)

		page = self.assertWebPage(http_status_code=501)
		self.assertIn("16.30.0", page["html"])
		self.assertNotLoggedIn()

	def test_the_start_endpoint_reports_an_unsupported_frappe(self):
		self.frappe.request.path = f"/api/method/oidc_extended.callback.start/{PROVIDER}"
		with mock.patch.object(self.callback, "consume_oauth_state", None):
			self.callback.start()

		self.assertWebPage(http_status_code=501)
		self.assertNotIn("location", self.frappe.local.response)

	def test_a_supported_frappe_is_not_reported(self):
		self.run_callback()

		self.assertEqual(self.frappe.web_pages, [])
		self.assertLoggedIn("jane@example.com")
