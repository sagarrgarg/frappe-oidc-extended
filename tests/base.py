"""Shared fixtures for the callback tests."""

import sys
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
	sys.path.insert(0, str(REPO_ROOT))

from tests import frappe_stub  # noqa: E402

PROVIDER = "authentik"
SIGNING_KID = "test-signing-key"


def _rsa_key():
	from cryptography.hazmat.primitives.asymmetric import rsa

	return rsa.generate_private_key(public_exponent=65537, key_size=2048)


# Generated once: the provider's signing key, and a key it never published.
SIGNING_KEY = _rsa_key()
ATTACKER_KEY = _rsa_key()

DISCOVERY_DOCUMENT = {
	"issuer": "https://idp.example.com/application/o/erpnext/",
	"jwks_uri": "https://idp.example.com/application/o/erpnext/jwks/",
	"id_token_signing_alg_values_supported": ["RS256", "ES256"],
}


class FakeJWKClient:
	"""Stands in for PyJWKClient so the JWKS fetch stays out of the test.

	Signature verification itself is done by the real PyJWT with a real key.
	"""

	def __init__(self, key):
		self.key = key

	def get_signing_key_from_jwt(self, token):
		import types

		return types.SimpleNamespace(key=self.key)


class CallbackTestCase(unittest.TestCase):
	"""Installs a fresh fake Frappe and a configured provider before every test."""

	def setUp(self):
		self.frappe = frappe_stub.install()

		# Re-import the app against the fresh stub.
		for name in [n for n in sys.modules if n == "oidc_extended" or n.startswith("oidc_extended.")]:
			del sys.modules[name]
		from oidc_extended import callback

		self.callback = callback

		self.social_login_key = frappe_stub.FakeDoc(
			{
				"doctype": "Social Login Key",
				"name": PROVIDER,
				"provider_name": PROVIDER,
				"enable_social_login": 1,
				"client_id": "erpnext-client-id",
				"client_secret": "erpnext-client-secret-0123456789abcdef",
				"base_url": "https://idp.example.com",
				"authorize_url": "/application/o/authorize/",
				"access_token_url": "/application/o/token/",
				"redirect_url": f"/api/method/oidc_extended.callback.custom/{PROVIDER}",
				"auth_url_data": '{"scope": "openid email profile"}',
				"user_id_property": "sub",
				"sign_ups": "Allow",
			}
		)
		self.frappe.docs[("Social Login Key", PROVIDER)] = self.social_login_key

		self.config = frappe_stub.FakeDoc(
			{
				"doctype": "OIDC Extended Configuration",
				"name": PROVIDER,
				"provider": PROVIDER,
				"given_name_claim_name": "given_name",
				"family_name_claim_name": "family_name",
				"email_claim_name": "email",
				"groups_claim_name": "groups",
				"group_role_mappings": [],
				"fallback_role_profiles": [],
				"group_module_mappings": [],
				"fallback_module_profile": None,
				"verify_id_token_signature": 1,
				"jwks_url": None,
				"issuer": None,
			}
		)
		self.frappe.docs[("OIDC Extended Configuration", PROVIDER)] = self.config

		self.frappe.flags.role_profile_roles = {
			"Sales Profile": ["Sales User", "Sales Manager"],
			"Accounts Profile": ["Accounts User"],
			"Employee Profile": ["Employee"],
		}

	# -- helpers -------------------------------------------------------------------
	def use_frappe_v16_user(self):
		"""Switch the fake User doctype to the v16 layout (role_profiles child table)."""
		self.frappe.user_fields.add("role_profiles")
		self.frappe.user_fields.discard("role_profile_name")

	def add_existing_user(self, **fields):
		"""An already-provisioned Frappe user, matching the default token claims."""
		claims = self.id_token_claims()
		defaults = {
			"email": claims["email"],
			"username": claims["sub"],
			"first_name": "Jane",
			"last_name": "Doe",
			"enabled": 1,
			"user_type": "System User",
		}
		defaults.update(fields)
		return self.frappe.user_store.add(**defaults)

	def roles_of(self, user):
		return [row.get("role") for row in user.get("roles", [])]

	def role_profiles_of(self, user):
		if "role_profiles" in self.frappe.user_fields:
			return [row.get("role_profile") for row in user.get("role_profiles", [])]
		return [user.get("role_profile_name")] if user.get("role_profile_name") else []

	def map_group_to_role_profile(self, group, role_profile, **extra):
		self.config.append("group_role_mappings", {"group": group, "role_profile": role_profile, **extra})

	def set_fallback_role_profiles(self, *role_profiles):
		for role_profile in role_profiles:
			self.config.append("fallback_role_profiles", {"role_profile": role_profile})

	def make_state(self, redirect_to=None):
		from frappe.utils.oauth import create_oauth_state

		return create_oauth_state(redirect_to)

	def id_token_claims(self, **overrides):
		import time

		now = int(time.time())
		claims = {
			"sub": "b1f0c2d4-0000-4000-8000-000000000001",
			"email": "jane@example.com",
			"given_name": "Jane",
			"family_name": "Doe",
			"groups": ["erp-sales"],
			"aud": self.social_login_key.client_id,
			"iss": DISCOVERY_DOCUMENT["issuer"],
			"iat": now,
			"exp": now + 300,
		}
		claims.update(overrides)
		return claims

	def encode_id_token(self, claims=None, key=None, algorithm="RS256", headers=None):
		"""Signs a token the way the identity provider would."""
		import jwt

		return jwt.encode(
			claims or self.id_token_claims(),
			key=key if key is not None else SIGNING_KEY,
			algorithm=algorithm,
			headers={"kid": SIGNING_KID, **(headers or {})},
		)

	def run_callback(
		self,
		code="auth-code",
		state=None,
		claims=None,
		token_response=None,
		path=None,
		id_token=None,
		published_key=None,
		discovery=None,
	):
		"""Invoke the callback with the token endpoint and the JWKS fetch mocked out."""
		self.frappe.request.path = path or f"/api/method/oidc_extended.callback.custom/{PROVIDER}"
		if state is None:
			state = self.make_state()

		response = token_response
		if response is None:
			response = {"id_token": id_token or self.encode_id_token(claims or self.id_token_claims())}

		post = mock.Mock()
		post.return_value.json.return_value = response
		post.return_value.status_code = 200
		post.return_value.ok = True

		# The provider publishes SIGNING_KEY unless a test says otherwise.
		self.jwks_urls = []
		key = SIGNING_KEY.public_key() if published_key is None else published_key

		def jwk_client(jwks_url):
			self.jwks_urls.append(jwks_url)
			return FakeJWKClient(key)

		self.discovery_urls = []
		document = DISCOVERY_DOCUMENT if discovery is None else discovery

		def get(url, **kwargs):
			self.discovery_urls.append(url)
			result = mock.Mock()
			result.json.return_value = document
			return result

		with mock.patch.object(self.callback.requests, "post", post), mock.patch.object(
			self.callback.requests, "get", side_effect=get
		), mock.patch.object(self.callback, "get_jwk_client", side_effect=jwk_client):
			result = self.callback.custom(code=code, state=state)

		self.token_post = post
		return result

	# -- assertions ----------------------------------------------------------------
	def assertWebPage(self, http_status_code=None, title_contains=None):
		self.assertTrue(self.frappe.web_pages, "expected respond_as_web_page to be called")
		page = self.frappe.web_pages[-1]
		if http_status_code is not None:
			self.assertEqual(page.get("http_status_code"), http_status_code, page)
		if title_contains is not None:
			self.assertIn(title_contains.lower(), str(page.get("title")).lower(), page)
		return page

	def assertLoggedIn(self, user):
		self.assertEqual(self.frappe.local.login_manager.user, user)
		self.assertEqual(self.frappe.local.response.get("type"), "redirect")

	def assertNotLoggedIn(self):
		self.assertIsNone(self.frappe.local.login_manager.user)
