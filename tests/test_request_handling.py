"""Point 8: a guest-facing callback must answer every failure with a page, not a traceback."""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class TestProviderResolution(CallbackTestCase):
	def test_an_unknown_provider_in_the_redirect_url_is_refused(self):
		self.run_callback(path="/api/method/oidc_extended.callback.custom/not-a-provider")

		self.assertWebPage(http_status_code=404)
		self.assertNotLoggedIn()

	def test_a_site_config_key_named_custom_no_longer_redirects_every_provider(self):
		"""`frappe.get_conf().get("custom", provider_name)` resolved every provider to
		whatever a site happened to keep under the "custom" key."""
		self.frappe.conf["custom"] = "some-other-provider"
		self.run_callback()

		self.assertLoggedIn("jane@example.com")

	def test_a_disabled_social_login_key_is_refused(self):
		self.social_login_key.enable_social_login = 0
		self.run_callback()

		self.assertWebPage(http_status_code=403)
		self.assertNotLoggedIn()

	def test_a_provider_without_an_extended_configuration_is_reported(self):
		del self.frappe.docs[("OIDC Extended Configuration", PROVIDER)]
		self.run_callback()

		self.assertWebPage(http_status_code=501, title_contains="not configured")
		self.assertNotLoggedIn()

	def test_a_malformed_redirect_url_is_refused(self):
		self.run_callback(path="/api/method/oidc_extended.callback.custom")

		self.assertWebPage(http_status_code=417)
		self.assertNotLoggedIn()


class TestProviderErrors(CallbackTestCase):
	def test_an_authorization_error_renders_a_page(self):
		state = self.make_state()
		self.callback.custom(state=state, error="access_denied", error_description="User cancelled")

		page = self.assertWebPage(http_status_code=400)
		self.assertIn("User cancelled", page["html"])
		self.assertNotLoggedIn()

	def test_a_callback_without_a_code_renders_a_page(self):
		state = self.make_state()
		self.callback.custom(state=state)

		self.assertWebPage(http_status_code=400)
		self.assertNotLoggedIn()

	def test_an_error_with_a_stale_state_is_still_refused_as_stale(self):
		self.callback.custom(state="0" * 32, error="access_denied")

		self.assertWebPage(http_status_code=417)


class TestTokenEndpointFailures(CallbackTestCase):
	def test_an_unreachable_token_endpoint_renders_a_page(self):
		state = self.make_state()
		with mock.patch.object(self.callback.requests, "post", side_effect=OSError("connection refused")):
			self.callback.custom(code="auth-code", state=state)

		self.assertWebPage(http_status_code=502)
		self.assertNotLoggedIn()

	def test_a_token_response_without_an_id_token_renders_a_page(self):
		self.run_callback(token_response={"error": "invalid_client", "error_description": "bad secret"})

		self.assertWebPage(http_status_code=502)
		self.assertNotLoggedIn()
		self.assertTrue(
			[msg for level, msg in self.frappe.logger_calls if level == "error" and "invalid_client" in msg],
			"the provider's error should be logged so it can be diagnosed",
		)

	def test_an_unparseable_token_response_renders_a_page(self):
		post = mock.Mock()
		post.return_value.json.side_effect = ValueError("not json")
		state = self.make_state()
		with mock.patch.object(self.callback.requests, "post", post):
			self.callback.custom(code="auth-code", state=state)

		self.assertWebPage(http_status_code=502)
		self.assertNotLoggedIn()

	def test_the_token_endpoint_url_is_built_from_the_social_login_key(self):
		self.run_callback()

		self.assertEqual(
			self.token_post.call_args.kwargs["url"],
			"https://idp.example.com/application/o/token/",
		)

	def test_an_absolute_token_url_is_used_as_it_is(self):
		self.social_login_key.access_token_url = "https://tokens.example.com/oauth/token"
		self.run_callback()

		self.assertEqual(
			self.token_post.call_args.kwargs["url"], "https://tokens.example.com/oauth/token"
		)

	def test_a_social_login_key_without_auth_url_data_still_works(self):
		self.social_login_key.auth_url_data = None
		self.run_callback()

		self.assertLoggedIn("jane@example.com")
		self.assertIsNone(self.token_post.call_args.kwargs["data"]["scope"])
