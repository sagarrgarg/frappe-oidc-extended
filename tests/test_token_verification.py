"""Point 4: the id token must be verified, not merely decoded."""

import jwt

from tests.base import ATTACKER_KEY, DISCOVERY_DOCUMENT, SIGNING_KEY, CallbackTestCase


class TestSignatureVerification(CallbackTestCase):
	def test_a_correctly_signed_token_is_accepted(self):
		self.run_callback()
		self.assertLoggedIn("jane@example.com")

	def test_a_token_signed_by_another_key_is_refused(self):
		"""The claims of an unverified token decide the user's roles."""
		forged = self.encode_id_token(
			self.id_token_claims(groups=["erp-administrators"]), key=ATTACKER_KEY
		)
		self.run_callback(id_token=forged)

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()
		self.assertEqual(self.frappe.user_store.users, {})

	def test_an_unsigned_token_is_refused(self):
		unsigned = jwt.encode(self.id_token_claims(), key=None, algorithm="none")
		self.run_callback(id_token=unsigned)

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_an_hmac_token_forged_with_the_public_key_is_refused(self):
		"""The algorithm confusion attack: sign with the published public key as secret."""
		from cryptography.hazmat.primitives import serialization

		public_pem = (
			SIGNING_KEY.public_key()
			.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo,
			)
			.decode()
		)
		# PyJWT refuses to sign with a public key, so the token is assembled by hand,
		# which is what an attacker would do anyway.
		forged = self.sign_hs256_by_hand(self.id_token_claims(), secret=public_pem)
		self.run_callback(id_token=forged)

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_a_symmetrically_signed_token_is_verified_against_the_client_secret(self):
		signed = jwt.encode(
			self.id_token_claims(), key=self.social_login_key.client_secret, algorithm="HS256"
		)
		self.run_callback(id_token=signed)

		self.assertLoggedIn("jane@example.com")

	def test_verification_can_be_turned_off_deliberately(self):
		self.config.verify_id_token_signature = 0
		forged = self.encode_id_token(self.id_token_claims(), key=ATTACKER_KEY)
		self.run_callback(id_token=forged)

		self.assertLoggedIn("jane@example.com")
		self.assertTrue(
			[msg for level, msg in self.frappe.logger_calls if level == "warning" and "not authenticated" in msg],
			"turning verification off should be logged as a warning",
		)


	def sign_hs256_by_hand(self, claims, secret):
		import base64
		import hashlib
		import hmac
		import json

		def segment(data):
			return base64.urlsafe_b64encode(data).rstrip(b"=")

		header = segment(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
		payload = segment(json.dumps(claims).encode())
		signing_input = header + b"." + payload
		signature = segment(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())

		return (signing_input + b"." + signature).decode()


class TestAudienceAndIssuer(CallbackTestCase):
	def test_the_audience_is_the_client_id_of_the_social_login_key(self):
		self.run_callback(claims=self.id_token_claims(aud="erpnext-client-id"))
		self.assertLoggedIn("jane@example.com")

	def test_a_token_for_another_audience_is_refused(self):
		self.run_callback(claims=self.id_token_claims(aud="some-other-client"))

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_the_previously_hardcoded_audience_is_no_longer_accepted(self):
		self.run_callback(claims=self.id_token_claims(aud="erpnext"))

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_a_token_from_another_issuer_is_refused(self):
		self.config.issuer = DISCOVERY_DOCUMENT["issuer"]
		self.run_callback(claims=self.id_token_claims(iss="https://evil.example.com/"))

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_the_issuer_from_the_discovery_document_is_enforced(self):
		self.run_callback(claims=self.id_token_claims(iss="https://evil.example.com/"))

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()


class TestTokenLifetime(CallbackTestCase):
	def test_an_expired_token_is_refused(self):
		import time

		now = int(time.time())
		self.run_callback(claims=self.id_token_claims(iat=now - 3600, exp=now - 60))

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()

	def test_a_token_without_an_expiry_is_refused(self):
		claims = self.id_token_claims()
		claims.pop("exp")
		self.run_callback(claims=claims)

		self.assertWebPage(http_status_code=401)
		self.assertNotLoggedIn()


class TestKeyDiscovery(CallbackTestCase):
	def test_the_configured_jwks_url_is_used(self):
		self.config.jwks_url = "https://auth.example.com/application/o/erpnext/jwks/"
		self.run_callback()

		self.assertEqual(self.jwks_urls, ["https://auth.example.com/application/o/erpnext/jwks/"])
		self.assertLoggedIn("jane@example.com")

	def test_the_jwks_url_is_read_from_the_discovery_document(self):
		self.run_callback()

		self.assertEqual(self.jwks_urls, [DISCOVERY_DOCUMENT["jwks_uri"]])
		self.assertEqual(
			self.discovery_urls,
			["https://idp.example.com/.well-known/openid-configuration"],
		)

	def test_the_configured_issuer_locates_the_discovery_document(self):
		self.config.issuer = "https://idp.example.com/application/o/erpnext/"
		self.run_callback()

		self.assertEqual(
			self.discovery_urls,
			["https://idp.example.com/application/o/erpnext/.well-known/openid-configuration"],
		)

	def test_the_discovery_document_is_cached_between_logins(self):
		self.run_callback()
		self.assertEqual(len(self.discovery_urls), 1)

		self.run_callback()
		self.assertEqual(self.discovery_urls, [], "the discovery document should be cached")

	def test_an_unreachable_discovery_document_is_survivable(self):
		self.config.jwks_url = DISCOVERY_DOCUMENT["jwks_uri"]

		def unreachable(url, **kwargs):
			raise OSError("connection refused")

		from unittest import mock

		with mock.patch.object(self.callback.requests, "get", side_effect=unreachable):
			self.run_callback_with_unreachable_discovery()

		self.assertLoggedIn("jane@example.com")

	def run_callback_with_unreachable_discovery(self):
		from unittest import mock

		from tests.base import FakeJWKClient, SIGNING_KEY

		state = self.make_state()
		post = mock.Mock()
		post.return_value.json.return_value = {"id_token": self.encode_id_token()}

		def unreachable(url, **kwargs):
			raise OSError("connection refused")

		with mock.patch.object(self.callback.requests, "post", post), mock.patch.object(
			self.callback.requests, "get", side_effect=unreachable
		), mock.patch.object(
			self.callback, "get_jwk_client", side_effect=lambda url: FakeJWKClient(SIGNING_KEY.public_key())
		):
			self.callback.custom(code="auth-code", state=state)

	def test_only_safe_advertised_algorithms_are_accepted(self):
		self.assertEqual(
			self.callback.get_signing_algorithms(
				{"id_token_signing_alg_values_supported": ["RS256", "none", "HS256", "ES256"]}
			),
			["RS256", "ES256"],
		)

	def test_the_default_algorithms_are_used_when_none_are_advertised(self):
		self.assertEqual(
			self.callback.get_signing_algorithms({}), list(self.callback.DEFAULT_SIGNING_ALGORITHMS)
		)
