"""How often a reconciliation is allowed to run, and that two cannot run at once.

The frequency is enforced inside the task rather than by the scheduler: the scheduler
calls the entry point every quarter of an hour, and the task decides whether that
provider is due. A frequency shorter than the event the job is registered under would
otherwise be a setting that could not take effect.
"""

from unittest import mock

from tests.base import PROVIDER, CallbackTestCase


class ScheduleTestCase(CallbackTestCase):
	def setUp(self):
		super().setUp()
		from oidc_extended import reconciliation

		self.reconciliation = reconciliation
		self.config.enable_reconciliation = 1
		self.frappe.now_value = "2026-08-24 12:00:00"

	def due_after(self, frequency, last_run):
		self.config.reconciliation_frequency = frequency
		self.config.last_reconciled_on = last_run
		return self.reconciliation.is_due(self.config)


class TestTheEntryPointIsCalledOftenEnough(ScheduleTestCase):
	def test_it_is_registered_as_a_quarter_hourly_cron(self):
		from oidc_extended import hooks

		self.assertEqual(
			hooks.scheduler_events["cron"]["*/15 * * * *"],
			["oidc_extended.reconciliation.run_scheduled_reconciliation"],
		)

	def test_it_is_not_registered_under_an_hourly_event(self):
		"""Which would cap the shortest frequency at an hour, whatever the field says."""
		from oidc_extended import hooks

		self.assertNotIn("hourly", hooks.scheduler_events)


class TestWhenARunIsDue(ScheduleTestCase):
	def test_a_provider_that_has_never_run_is_due(self):
		self.config.reconciliation_frequency = "Every 15 Minutes"
		self.assertTrue(self.reconciliation.is_due(self.config))

	def test_every_fifteen_minutes_waits_a_quarter_of_an_hour(self):
		self.assertFalse(self.due_after("Every 15 Minutes", "2026-08-24 11:50:00"))
		self.assertTrue(self.due_after("Every 15 Minutes", "2026-08-24 11:45:00"))
		self.assertTrue(self.due_after("Every 15 Minutes", "2026-08-24 11:30:00"))

	def test_hourly_still_waits_an_hour(self):
		self.assertFalse(self.due_after("Hourly", "2026-08-24 11:45:00"))
		self.assertTrue(self.due_after("Hourly", "2026-08-24 11:00:00"))

	def test_daily_still_waits_a_day(self):
		self.assertFalse(self.due_after("Daily", "2026-08-24 11:00:00"))
		self.assertTrue(self.due_after("Daily", "2026-08-23 12:00:00"))

	def test_an_unset_frequency_is_daily(self):
		self.assertFalse(self.due_after(None, "2026-08-24 11:00:00"))
		self.assertTrue(self.due_after(None, "2026-08-23 12:00:00"))


class TestOverlappingRuns(ScheduleTestCase):
	def run_scheduled(self):
		self.frappe.docs[("OIDC Extended Configuration", PROVIDER)] = self.config
		with mock.patch.object(self.reconciliation, "run_reconciliation") as run:
			self.reconciliation.run_scheduled_reconciliation()
		return run

	def test_a_due_provider_runs_and_the_slot_is_claimed_before_the_work(self):
		run = self.run_scheduled()

		self.assertEqual(run.call_count, 1)
		self.assertEqual(self.config.get("last_reconciled_on"), "2026-08-24 12:00:00")
		self.assertIn(f"oidc_extended_reconciliation_{PROVIDER}", self.frappe.held_locks)

	def test_a_provider_that_is_not_due_is_skipped(self):
		self.config.reconciliation_frequency = "Hourly"
		self.config.last_reconciled_on = "2026-08-24 11:45:00"

		self.assertEqual(self.run_scheduled().call_count, 0)

	def test_reconciliation_that_is_turned_off_is_skipped(self):
		self.config.enable_reconciliation = 0

		self.assertEqual(self.run_scheduled().call_count, 0)

	def test_a_second_run_leaves_the_first_to_finish(self):
		"""Frappe will not queue the scheduled job twice, but a run started by hand can
		still collide with one in flight, and two sweeps writing the same users would
		each act on what the other had half done."""
		self.frappe.locks_are_taken = True

		run = self.run_scheduled()

		self.assertEqual(run.call_count, 0)
		self.assertIsNone(self.config.get("last_reconciled_on"))

	def test_a_failure_is_logged_and_does_not_stop_the_other_providers(self):
		self.frappe.docs[("OIDC Extended Configuration", PROVIDER)] = self.config

		with mock.patch.object(
			self.reconciliation, "run_reconciliation", side_effect=ValueError("the directory is down")
		):
			self.reconciliation.run_scheduled_reconciliation()

		self.assertEqual(self.frappe.db.rollbacks, 1)
		self.assertTrue(
			any("failed" in message for level, message in self.frappe.logger_calls if level == "error")
		)
