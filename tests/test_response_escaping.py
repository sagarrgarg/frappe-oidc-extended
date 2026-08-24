"""Values echoed back into a web page must be escaped.

`frappe.respond_as_web_page` renders its message as raw HTML: frappe/www/message.py
assigns `frappe.local.message` to the template context untouched, and Frappe's Jinja
environment is built without autoescape. Anything of the caller's that reaches it is
therefore markup, and these endpoints are reachable by guests.
"""

from tests.base import PROVIDER, CallbackTestCase

PAYLOAD = "<script>alert(document.domain)</script>"

# A payload carried in the URL path cannot contain a slash: the callback requires the
# path to have exactly four components. It does not need one.
PATH_PAYLOAD = "<img src=x onerror=alert(1)>"


class TestResponseEscaping(CallbackTestCase):
	def assertNoMarkup(self, page, payload=PAYLOAD):
		opening_tag = payload[: payload.index(" ")] if " " in payload else payload.split(">")[0] + ">"
		self.assertNotIn(opening_tag, page["html"])
		self.assertIn("&lt;", page["html"])
		self.assertNotIn("<", page["html"].replace("&lt;", ""))

	def test_an_unknown_provider_name_is_escaped_at_the_start_endpoint(self):
		"""Reachable with no state and no session: a plain link is enough."""
		self.frappe.request.path = "/api/method/oidc_extended.callback.start"
		self.callback.start(provider=PAYLOAD)

		self.assertNoMarkup(self.assertWebPage(http_status_code=404))

	def test_an_unknown_provider_name_in_the_path_is_escaped(self):
		self.frappe.request.path = f"/api/method/oidc_extended.callback.start/{PATH_PAYLOAD}"
		self.callback.start()

		self.assertNoMarkup(self.assertWebPage(http_status_code=404), PATH_PAYLOAD)

	def test_an_unknown_provider_at_the_callback_is_escaped(self):
		self.run_callback(path=f"/api/method/oidc_extended.callback.custom/{PATH_PAYLOAD}")

		self.assertNoMarkup(self.assertWebPage(http_status_code=404), PATH_PAYLOAD)

	def test_the_error_description_of_the_provider_is_escaped(self):
		state = self.make_state()
		self.callback.custom(state=state, error="access_denied", error_description=PAYLOAD)

		self.assertNoMarkup(self.assertWebPage(http_status_code=400))

	def test_the_error_code_of_the_provider_is_escaped(self):
		state = self.make_state()
		self.callback.custom(state=state, error=PAYLOAD)

		self.assertNoMarkup(self.assertWebPage(http_status_code=400))

	def test_a_disabled_provider_name_is_escaped(self):
		self.social_login_key.enable_social_login = 0
		self.social_login_key._data["name"] = PATH_PAYLOAD
		self.frappe.docs[("Social Login Key", PATH_PAYLOAD)] = self.social_login_key
		self.frappe.request.path = f"/api/method/oidc_extended.callback.start/{PATH_PAYLOAD}"
		self.callback.start()

		self.assertNoMarkup(self.assertWebPage(http_status_code=403), PATH_PAYLOAD)

	def test_a_missing_claim_name_is_escaped(self):
		self.config.email_claim_name = PAYLOAD
		self.social_login_key.user_id_property = PAYLOAD
		self.run_callback()

		self.assertNoMarkup(self.assertWebPage(http_status_code=400))
