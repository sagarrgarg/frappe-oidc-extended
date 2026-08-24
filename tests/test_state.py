"""Point 1: the `state` parameter must be validated through Frappe's single-use token."""

import base64
import json

from tests.base import PROVIDER, CallbackTestCase


class TestOAuthState(CallbackTestCase):
	def test_valid_state_completes_login(self):
		self.run_callback(state=self.make_state())
		self.assertLoggedIn("jane@example.com")

	def test_state_carries_redirect_to(self):
		self.run_callback(state=self.make_state(redirect_to="/app/sales-order"))
		self.assertEqual(self.frappe.local.response["location"], "/app/sales-order")

	def test_valid_state_without_redirect_to_falls_back_to_desk(self):
		self.run_callback(state=self.make_state())
		self.assertEqual(self.frappe.local.response["location"], "https://erp.example.com/app")

	def test_unknown_state_is_rejected(self):
		self.run_callback(state="0" * 32)
		self.assertWebPage(http_status_code=417)
		self.assertNotLoggedIn()
		self.token_post.assert_not_called()

	def test_state_is_single_use(self):
		state = self.make_state()
		self.run_callback(state=state)
		self.assertLoggedIn("jane@example.com")

		self.setUp()  # fresh request, same (already consumed) state
		self.run_callback(state=state)
		self.assertWebPage(http_status_code=417)
		self.assertNotLoggedIn()

	def test_legacy_v14_base64_state_is_rejected_not_crashed(self):
		legacy = base64.b64encode(
			json.dumps({"site": "erp.example.com", "token": "abc", "redirect_to": "/app"}).encode()
		).decode()
		self.run_callback(state=legacy)
		self.assertWebPage(http_status_code=417)
		self.assertNotLoggedIn()

	def test_empty_state_is_rejected(self):
		self.run_callback(state="")
		self.assertWebPage(http_status_code=417)
		self.assertNotLoggedIn()
