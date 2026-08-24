"""The webhook receiver: act on one user the moment the provider says something changed.

Keycloak has no webhook of its own - an event listener provider deployed into it sends
admin events in whatever shape its author chose - so nothing in the body is trusted
beyond an identifier. The user is looked up in the directory and what that says is what
is applied.
"""

import hashlib
import hmac
import json
from unittest import mock

from tests.base import PROVIDER, CallbackTestCase

SECRET = "a-shared-webhook-secret"


class WebhookTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import reconciliation

		self.reconciliation = reconciliation
		self.config.enable_reconciliation = 1
		self.config.directory_type = "Keycloak"
		self.config.directory_url = "https://idp.example.com/realms/erp"
		self.config.webhook_secret = SECRET
		self.config.absent_user_action = "Disable User"
		self.map_group_to_role_profile("/erp/sales", "Sales Profile")
		self.map_group_to_role_profile("/erp/accounts", "Accounts Profile")

		self.user = self.frappe.user_store.add(
			email="jane@example.com", enabled=1, role_profile_name="Sales Profile"
		)
		self.user.set_social_login_userid(PROVIDER, userid="sub-1")

	def post(self, payload, headers=None, directory_user=..., path=None):
		body = json.dumps(payload).encode()
		self.frappe.request.path = path or f"/api/method/oidc_extended.reconciliation.webhook/{PROVIDER}"
		self.frappe.request.get_data = lambda: body
		self.frappe.request_headers = headers if headers is not None else {"Authorization": f"Bearer {SECRET}"}

		entry = directory_user if directory_user is not ... else {
			"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/sales"]
		}

		with mock.patch.object(
			self.reconciliation, "get_directory", return_value=mock.Mock(get_user=lambda **kw: entry)
		):
			return self.reconciliation.webhook()

	def signature_header(self, payload):
		body = json.dumps(payload).encode()
		return {"X-Hub-Signature-256": "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()}


class TestWebhookAuthentication(WebhookTestCase):
	def test_a_bearer_secret_is_accepted(self):
		self.post({"userId": "sub-1"}, directory_user={
			"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/accounts"]
		})

		self.assertEqual(self.user.get("role_profile_name"), "Accounts Profile")

	def test_a_signed_body_is_accepted(self):
		payload = {"userId": "sub-1"}
		self.post(payload, headers=self.signature_header(payload), directory_user={
			"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/accounts"]
		})

		self.assertEqual(self.user.get("role_profile_name"), "Accounts Profile")

	def test_a_wrong_secret_is_refused(self):
		self.post({"userId": "sub-1"}, headers={"Authorization": "Bearer not-the-secret"})

		self.assertEqual(self.frappe.local.response.get("http_status_code"), 401)
		self.assertEqual(self.user.get("role_profile_name"), "Sales Profile")

	def test_a_tampered_body_is_refused(self):
		signed = self.signature_header({"userId": "sub-1"})
		self.post({"userId": "sub-2"}, headers=signed)

		self.assertEqual(self.frappe.local.response.get("http_status_code"), 401)

	def test_the_endpoint_is_closed_without_a_configured_secret(self):
		self.config.webhook_secret = None
		self.post({"userId": "sub-1"}, headers={})

		self.assertEqual(self.frappe.local.response.get("http_status_code"), 401)

	def test_it_is_post_only_and_open_to_guests(self):
		self.assertEqual(self.reconciliation.webhook.allowed_methods, ["POST"])
		self.assertTrue(self.reconciliation.webhook.allow_guest)


class TestWebhookPayloads(WebhookTestCase):
	def test_a_keycloak_admin_event_resource_path_is_understood(self):
		"""Group membership events name the user in a path, not a field."""
		self.post(
			{
				"realmId": "erp",
				"operationType": "DELETE",
				"resourceType": "GROUP_MEMBERSHIP",
				"resourcePath": "users/sub-1/groups/8ac1b4f2-0000-4000-8000-000000000001",
			},
			directory_user={
				"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": []
			},
		)

		self.assertIsNone(self.user.get("role_profile_name"))
		self.assertEqual(self.roles_of(self.user), [])

	def test_an_email_only_payload_is_understood(self):
		self.post(
			{"type": "USER", "details": {"email": "jane@example.com"}},
			directory_user={
				"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/accounts"]
			},
		)

		self.assertEqual(self.user.get("role_profile_name"), "Accounts Profile")

	def test_a_payload_naming_nobody_is_ignored(self):
		self.post({"type": "REALM_ROLE_MAPPING", "realmId": "erp"})

		self.assertNotEqual(self.frappe.local.response.get("http_status_code"), 500)
		self.assertEqual(self.user.get("role_profile_name"), "Sales Profile")

	def test_an_unparseable_body_is_ignored(self):
		self.frappe.request.path = f"/api/method/oidc_extended.reconciliation.webhook/{PROVIDER}"
		self.frappe.request.get_data = lambda: b"not json"
		self.frappe.request_headers = {"Authorization": f"Bearer {SECRET}"}
		self.reconciliation.webhook()

		self.assertNotEqual(self.frappe.local.response.get("http_status_code"), 500)


class TestWebhookActions(WebhookTestCase):
	def test_a_user_deleted_at_the_provider_is_deprovisioned(self):
		self.post({"userId": "sub-1"}, directory_user=None)

		self.assertEqual(self.user.get("enabled"), 0)
		self.assertIsNone(self.user.get("role_profile_name"))

	def test_a_user_disabled_at_the_provider_is_deprovisioned(self):
		self.post({"userId": "sub-1"}, directory_user={
			"subject": "sub-1", "email": "jane@example.com", "enabled": False, "groups": ["/erp/sales"]
		})

		self.assertEqual(self.user.get("enabled"), 0)

	def test_a_group_change_ends_their_sessions(self):
		self.post({"userId": "sub-1"}, directory_user={
			"subject": "sub-1", "email": "jane@example.com", "enabled": True, "groups": ["/erp/accounts"]
		})

		self.assertIn(
			{"user": "jane@example.com", "keep_current": False, "force": True},
			self.frappe.sessions.cleared,
		)

	def test_an_unchanged_user_is_left_alone(self):
		self.post({"userId": "sub-1"})

		self.assertEqual(self.user.save_count, 0)
		self.assertEqual(self.frappe.sessions.cleared, [])

	def test_a_user_this_site_does_not_have_is_not_an_error(self):
		"""And is answered the same way as a known one, so the endpoint tells nobody
		which subjects exist here."""
		self.post({"userId": "sub-somebody-else"}, directory_user=None)

		self.assertIsNone(self.frappe.local.response.get("http_status_code"))
		self.assertEqual(self.user.get("enabled"), 1)

	def test_a_user_who_never_signed_in_here_is_not_touched(self):
		local = self.frappe.user_store.add(email="local@example.com", enabled=1)
		self.post({"email": "local@example.com"}, directory_user=None)

		self.assertEqual(local.get("enabled"), 1)

	def test_an_unknown_provider_is_refused(self):
		self.post({"userId": "sub-1"}, path="/api/method/oidc_extended.reconciliation.webhook/nope")

		self.assertEqual(self.frappe.local.response.get("http_status_code"), 400)
