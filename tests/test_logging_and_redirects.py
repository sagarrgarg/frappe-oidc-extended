"""Side effects of importing the app, what it writes to the log, and where it sends people."""

from tests.base import CallbackTestCase


class TestLoggingSideEffects(CallbackTestCase):
	def test_importing_the_app_does_not_reconfigure_logging(self):
		"""set_log_level sets frappe.log_level and clears frappe.loggers for the whole
		worker, so an app import would reconfigure logging for every app on the site."""
		self.assertEqual(self.frappe.log_level_calls, [])

	def test_the_user_record_is_not_written_to_the_log(self):
		self.frappe.user_store.add(
			email="jane@example.com", enabled=1, api_key="secret-api-key", phone="555-0100"
		)
		self.run_callback()

		logged = " ".join(message for _, message in self.frappe.logger_calls)
		self.assertNotIn("secret-api-key", logged)
		self.assertNotIn("555-0100", logged)


class TestPostLoginRedirect(CallbackTestCase):
	def test_a_redirect_off_this_site_is_not_followed(self):
		"""Defence in depth: the target is sanitized when the login starts, but it has
		been through Redis since, and Frappe's own login page can start one too."""
		state = self.make_state(redirect_to="https://evil.example.com/steal")
		self.run_callback(state=state)

		self.assertLoggedIn("jane@example.com")
		self.assertNotIn("evil.example.com", self.frappe.local.response["location"])

	def test_a_redirect_on_this_site_is_followed(self):
		self.run_callback(state=self.make_state(redirect_to="/app/sales-order"))

		self.assertEqual(self.frappe.local.response["location"], "/app/sales-order")
