"""Point 7: a role change must actually invalidate the user's cache and sessions."""

from tests.base import CallbackTestCase


class TestCacheInvalidation(CallbackTestCase):
	def test_a_changed_role_profile_clears_the_user_cache_and_sessions(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=1, role_profile_name="Sales Profile")
		self.map_group_to_role_profile("erp-accounts", "Accounts Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-accounts"]))

		self.assertIn({"user": "jane@example.com"}, self.frappe.cleared_caches)
		self.assertEqual(
			self.frappe.sessions.cleared,
			[{"user": "jane@example.com", "keep_current": True, "force": True}],
		)

	def test_an_unchanged_role_profile_leaves_sessions_alone(self):
		self.frappe.user_store.add(email="jane@example.com", enabled=1, role_profile_name="Sales Profile")
		self.map_group_to_role_profile("erp-sales", "Sales Profile")
		self.run_callback(claims=self.id_token_claims(groups=["erp-sales"]))

		self.assertEqual(self.frappe.sessions.cleared, [])
		self.assertEqual(self.frappe.cleared_caches, [])

	def test_de_provisioning_clears_the_sessions_the_user_already_has(self):
		self.frappe.user_store.add(
			email="jane@example.com", enabled=1, role_profile_name="Sales Profile"
		)
		self.config.unmapped_user_action = "Remove All Roles"
		self.run_callback(claims=self.id_token_claims(groups=["unmapped"]))

		self.assertEqual(
			self.frappe.sessions.cleared,
			[{"user": "jane@example.com", "keep_current": True, "force": True}],
		)

	def test_no_cache_key_named_bhas_role_is_touched(self):
		"""The name never existed in Frappe; the call was silently a no-op."""
		self.run_callback()

		self.assertNotIn("bhas_role", str(self.frappe.cache.deleted))
