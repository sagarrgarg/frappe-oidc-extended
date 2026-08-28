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


class TestStateChangingEndpointsRefuseGet(CallbackTestCase):
	"""Frappe checks a CSRF token on everything except GET, so anything that writes
	must not answer one."""

	def test_the_reconciliation_is_post_only(self):
		from oidc_extended import reconciliation

		self.assertEqual(reconciliation.reconcile.allowed_methods, ["POST"])

	def test_the_webhook_is_post_only(self):
		from oidc_extended import reconciliation

		self.assertEqual(reconciliation.webhook.allowed_methods, ["POST"])

	def test_fetching_groups_is_post_only(self):
		from oidc_extended import groups

		self.assertEqual(groups.fetch_groups.allowed_methods, ["POST"])

	def test_the_back_channel_logout_is_post_only(self):
		self.assertEqual(self.callback.backchannel_logout.allowed_methods, ["POST"])
