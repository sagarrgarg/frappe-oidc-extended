"""Every guest-facing endpoint declares a rate limit.

The counting is Frappe's; what is pinned here is that the limits exist and stay
generous enough for an office behind one NAT address and for the burst of logout
tokens that revoking every session at the identity provider produces.
"""

from tests.base import CallbackTestCase


class TestRateLimits(CallbackTestCase):
	def test_the_login_callback_is_limited(self):
		self.assertEqual(self.callback.custom.rate_limit["limit"], 120)
		self.assertEqual(self.callback.custom.rate_limit["seconds"], 60)

	def test_the_start_endpoint_is_limited(self):
		self.assertEqual(self.callback.start.rate_limit["limit"], 120)

	def test_the_logout_endpoint_is_limited_more_loosely(self):
		"""Revoking every session at the provider sends one token per user at once."""
		self.assertGreater(
			self.callback.backchannel_logout.rate_limit["limit"],
			self.callback.custom.rate_limit["limit"],
		)

	def test_the_limits_are_per_ip(self):
		for endpoint in (self.callback.custom, self.callback.start, self.callback.backchannel_logout):
			self.assertTrue(endpoint.rate_limit["ip_based"])
