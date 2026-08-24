"""Back-channel logout: the identity provider ends a session, so we end ours.

Frappe's session is a cookie backed by its own record; nothing about the provider is
consulted after login, so without this a session survives a user being logged out,
deactivated or deleted at the provider until it idles out.
"""

import time
from unittest import mock

from tests.base import ATTACKER_KEY, DISCOVERY_DOCUMENT, SIGNING_KEY, FakeJWKClient, PROVIDER, CallbackTestCase

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class BackchannelLogoutTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		self.user = self.frappe.user_store.add(email="jane@example.com", enabled=1)
		self.user.set_social_login_userid(PROVIDER, userid=self.id_token_claims()["sub"])

	def logout_token_claims(self, **overrides):
		claims = {
			"iss": DISCOVERY_DOCUMENT["issuer"],
			"aud": self.social_login_key.client_id,
			"iat": int(time.time()),
			"jti": "logout-token-0001",
			"sub": self.id_token_claims()["sub"],
			"events": {BACKCHANNEL_LOGOUT_EVENT: {}},
		}
		claims.update(overrides)
		return claims

	def post_logout(self, claims=None, token=None, key=None, path=None, published_key=None):
		self.frappe.request.path = path or f"/api/method/oidc_extended.callback.backchannel_logout/{PROVIDER}"
		if token is None:
			token = self.encode_id_token(
				claims if claims is not None else self.logout_token_claims(), key=key
			)

		def get(url, **kwargs):
			result = mock.Mock()
			result.json.return_value = DISCOVERY_DOCUMENT
			return result

		signing_key = SIGNING_KEY.public_key() if published_key is None else published_key
		with mock.patch.object(self.callback.requests, "get", side_effect=get), mock.patch.object(
			self.callback, "get_jwk_client", side_effect=lambda url: FakeJWKClient(signing_key)
		):
			return self.callback.backchannel_logout(logout_token=token)

	def assertSessionsEnded(self):
		self.assertEqual(
			self.frappe.sessions.cleared,
			[{"user": "jane@example.com", "keep_current": False, "force": True}],
		)

	def assertRefused(self, result=None):
		"""The error belongs at the top level of the body, per Back-Channel Logout 2.8."""
		response = self.frappe.local.response
		self.assertEqual(response.get("http_status_code"), 400, response)
		self.assertEqual(response.get("error"), "invalid_request", response)
		self.assertTrue(response.get("error_description"), response)
		self.assertIsNone(result, "the error goes on the response, not the return value")
		self.assertEqual(self.frappe.sessions.cleared, [], "no session should have been ended")


class TestBackchannelLogout(BackchannelLogoutTestCase):
	def test_a_valid_logout_token_ends_every_session_of_the_user(self):
		self.post_logout()

		self.assertSessionsEnded()
		self.assertIn({"user": "jane@example.com"}, self.frappe.cleared_caches)

	def test_the_endpoint_is_post_only_and_open_to_guests(self):
		"""The provider posts server to server, with no session and no CSRF token."""
		self.assertEqual(self.callback.backchannel_logout.allowed_methods, ["POST"])
		self.assertTrue(self.callback.backchannel_logout.allow_guest)

	def test_a_subject_with_no_user_here_is_not_an_error(self):
		result = self.post_logout(claims=self.logout_token_claims(sub="someone-else"))

		self.assertIsNone(result)
		self.assertNotEqual(self.frappe.local.response.get("http_status_code"), 400)
		self.assertEqual(self.frappe.sessions.cleared, [])

	def test_a_user_is_matched_only_by_subject_never_by_email(self):
		"""`sub` is not an email address; matching one to the other would end the
		sessions of whoever happens to own that address here."""
		result = self.post_logout(claims=self.logout_token_claims(sub="jane@example.com"))

		self.assertIsNone(result)
		self.assertEqual(self.frappe.sessions.cleared, [])


class TestLogoutTokenVerification(BackchannelLogoutTestCase):
	def test_a_token_signed_by_another_key_is_refused(self):
		self.assertRefused(self.post_logout(key=ATTACKER_KEY))

	def test_a_token_for_another_audience_is_refused(self):
		self.assertRefused(self.post_logout(claims=self.logout_token_claims(aud="another-client")))

	def test_a_token_from_another_issuer_is_refused(self):
		self.assertRefused(
			self.post_logout(claims=self.logout_token_claims(iss="https://evil.example.com/"))
		)

	def test_a_missing_token_is_refused(self):
		self.assertRefused(self.post_logout(token=""))

	def test_a_token_without_the_logout_event_is_refused(self):
		claims = self.logout_token_claims()
		claims.pop("events")
		self.assertRefused(self.post_logout(claims=claims))

	def test_an_id_token_replayed_as_a_logout_token_is_refused(self):
		"""An id token has no events claim, and carries a nonce where one was used."""
		self.assertRefused(self.post_logout(claims=self.id_token_claims()))

	def test_a_token_carrying_a_nonce_is_refused(self):
		self.assertRefused(self.post_logout(claims=self.logout_token_claims(nonce="n-0S6_WzA2Mj")))

	def test_a_token_without_a_subject_is_refused(self):
		claims = self.logout_token_claims()
		claims.pop("sub")
		claims["sid"] = "a-session-at-the-provider"
		self.assertRefused(self.post_logout(claims=claims))

	def test_a_token_without_an_identifier_is_refused(self):
		claims = self.logout_token_claims()
		claims.pop("jti")
		self.assertRefused(self.post_logout(claims=claims))

	def test_a_stale_token_is_refused(self):
		self.assertRefused(
			self.post_logout(claims=self.logout_token_claims(iat=int(time.time()) - 3600))
		)

	def test_a_token_from_the_future_is_refused(self):
		self.assertRefused(
			self.post_logout(claims=self.logout_token_claims(iat=int(time.time()) + 3600))
		)

	def test_a_small_clock_difference_is_tolerated(self):
		self.post_logout(claims=self.logout_token_claims(iat=int(time.time()) + 30))
		self.assertSessionsEnded()

	def test_a_replayed_token_is_refused(self):
		self.post_logout()
		self.assertSessionsEnded()

		self.frappe.sessions.cleared.clear()
		self.assertRefused(self.post_logout())

	def test_a_second_logout_with_a_new_identifier_is_accepted(self):
		self.post_logout()
		self.frappe.sessions.cleared.clear()

		self.post_logout(claims=self.logout_token_claims(jti="logout-token-0002"))
		self.assertSessionsEnded()


class TestBackchannelLogoutConfiguration(BackchannelLogoutTestCase):
	def test_it_is_refused_when_token_verification_is_turned_off(self):
		"""The signature is the only thing that says this came from the provider."""
		self.config.verify_id_token_signature = 0
		self.assertRefused(self.post_logout())

	def test_an_unknown_provider_is_refused(self):
		self.assertRefused(
			self.post_logout(path="/api/method/oidc_extended.callback.backchannel_logout/nope")
		)

	def test_a_provider_without_a_configuration_is_refused(self):
		del self.frappe.docs[("OIDC Extended Configuration", PROVIDER)]
		self.assertRefused(self.post_logout())

	def test_a_malformed_url_is_refused(self):
		self.assertRefused(
			self.post_logout(path="/api/method/oidc_extended.callback.backchannel_logout")
		)


class TestLogoutTokenReplayWindow(BackchannelLogoutTestCase):
	def test_a_token_stays_usable_when_ending_the_sessions_failed(self):
		"""Otherwise a transient database error would burn the token and the provider's
		retry would be refused as a replay, losing the logout for good."""
		with mock.patch.object(self.callback, "clear_sessions", side_effect=RuntimeError("db is down")):
			with self.assertRaises(RuntimeError):
				self.post_logout()

		self.post_logout()
		self.assertSessionsEnded()

	def test_an_unknown_subject_still_burns_the_token(self):
		self.post_logout(claims=self.logout_token_claims(sub="someone-else"))
		self.assertRefused(self.post_logout(claims=self.logout_token_claims(sub="someone-else")))

	def test_the_reason_for_an_unknown_provider_is_not_disclosed(self):
		"""Which providers exist, and which are half configured, read the same."""
		self.post_logout(path="/api/method/oidc_extended.callback.backchannel_logout/nope")
		unknown = self.frappe.local.response.get("error_description")

		self.setUp()
		del self.frappe.docs[("OIDC Extended Configuration", PROVIDER)]
		self.post_logout()

		self.assertEqual(self.frappe.local.response.get("error_description"), unknown)
