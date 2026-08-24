"""The redirect URI presented at the token endpoint.

It must be identical to the one sent in the authorization request, or the provider
refuses the exchange (RFC 6749 4.1.3), and identical to the one registered with the
provider. Frappe derives it, and its derivation depends on bench configuration.
"""

from tests.base import PROVIDER, CallbackTestCase


class TestRedirectUri(CallbackTestCase):
	def test_it_is_built_the_way_frappe_builds_the_authorization_one(self):
		self.run_callback()

		self.assertEqual(
			self.token_post.call_args.kwargs["data"]["redirect_uri"],
			f"https://erp.example.com/api/method/oidc_extended.callback.custom/{PROVIDER}",
		)

	def test_site_config_can_pin_it_exactly(self):
		"""The way out when the URL Frappe derives is not the one the provider knows."""
		pinned = f"https://erp.example.com/api/method/oidc_extended.callback.custom/{PROVIDER}"
		self.frappe.conf[f"{PROVIDER}_login"] = {"redirect_uri": pinned}
		self.run_callback()

		self.assertEqual(self.token_post.call_args.kwargs["data"]["redirect_uri"], pinned)

	def test_a_port_in_the_redirect_uri_is_reported(self):
		"""frappe.utils.get_url appends the webserver port unless the bench sets
		restart_supervisor_on_update or restart_systemd_on_update, and every provider
		then rejects the exchange."""
		self.frappe.conf[f"{PROVIDER}_login"] = {
			"redirect_uri": f"https://erp.example.com:8000/api/method/oidc_extended.callback.custom/{PROVIDER}"
		}
		self.run_callback()

		warnings = [msg for level, msg in self.frappe.logger_calls if level == "warning"]
		self.assertTrue(
			[msg for msg in warnings if "carries a port" in msg],
			f"expected a warning about the port, got {warnings}",
		)

	def test_a_local_development_url_is_not_reported(self):
		self.frappe.conf[f"{PROVIDER}_login"] = {
			"redirect_uri": "http://localhost:8000/api/method/oidc_extended.callback.custom/authentik"
		}
		self.run_callback()

		self.assertFalse(
			[msg for level, msg in self.frappe.logger_calls if level == "warning" and "carries a port" in msg]
		)
