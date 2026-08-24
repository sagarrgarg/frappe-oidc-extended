"""Bringing Frappe users back in line with the identity provider, on a schedule.

Removing someone from the identity provider does not reach Frappe on its own. Their
sessions end - back-channel logout sees to that - and they can no longer authenticate,
but the Frappe user stays enabled, keeps every role it was given, keeps counting as a
seat, and keeps whatever local credentials it has: a password reset, an API key. They
are a fully provisioned user who merely cannot sign in through the front door.

Nothing in OpenID Connect fixes that. A logout token says a session ended, not why, and
no standard signal carries "this person left" or "their entitlements shrank". So this
asks the provider directly, and applies what it finds.
"""

import frappe
from frappe.sessions import clear_sessions

from oidc_extended.callback import (
	RESERVED_USERS,
	apply_role_profiles,
	normalize_groups,
	resolve_module_profile,
	resolve_role_profiles,
)
from oidc_extended.directory import EmptyDirectoryError, get_directory

REPORT_ONLY = "Report Only"
REMOVE_ALL_ROLES = "Remove All Roles"
DISABLE_USER = "Disable User"

# A run that would de-provision most of the linked users is far more likely to be
# reading a broken directory response than a mass departure.
MAX_AFFECTED_FRACTION = 0.5


@frappe.whitelist()
def reconcile(provider: str, dry_run: int = 1) -> dict:
	"""Compares Frappe against the directory and reports, or applies, the difference.

	Runs as a dry run unless told otherwise, so the report can be read before anything
	is written.
	"""
	frappe.only_for("System Manager")

	return run_reconciliation(provider, dry_run=frappe.utils.cint(dry_run))


def run_reconciliation(provider: str, dry_run: bool = True) -> dict:
	configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)
	absent_user_action = configuration.get("absent_user_action") or REPORT_ONLY

	directory_users = get_directory(configuration).get_users()

	if not directory_users:
		# Never act on an empty answer: it is a broken API call far more often than an
		# empty directory, and acting on it would de-provision everyone.
		raise EmptyDirectoryError(f"The directory of {provider} returned no users.")

	by_subject = {user["subject"]: user for user in directory_users if user.get("subject")}
	by_email = {user["email"]: user for user in directory_users if user.get("email")}

	report = {
		"provider": provider,
		"dry_run": bool(dry_run),
		"directory_users": len(directory_users),
		"linked_users": 0,
		"absent": [],
		"disabled_at_provider": [],
		"roles_changed": [],
		"unchanged": [],
		"skipped": [],
	}

	for user_name, subject in linked_users(provider):
		if user_name in RESERVED_USERS:
			report["skipped"].append({"user": user_name, "reason": "reserved account"})
			continue

		report["linked_users"] += 1
		user = frappe.get_doc("User", user_name)
		entry = by_subject.get(subject) or by_email.get((user.email or "").lower())

		if not entry:
			report["absent"].append({"user": user_name, "action": absent_user_action})
			continue

		if not entry["enabled"]:
			report["disabled_at_provider"].append({"user": user_name, "action": absent_user_action})
			continue

		role_profiles = resolve_role_profiles(configuration, normalize_groups(entry["groups"]))
		current = current_role_profiles(user)

		if set(current) == set(role_profiles):
			report["unchanged"].append(user_name)
			continue

		report["roles_changed"].append(
			{"user": user_name, "from": current, "to": role_profiles, "groups": entry["groups"]}
		)

	guard_against_mass_change(report)

	if not dry_run:
		apply_report(report, configuration, absent_user_action, by_subject, by_email)

	return report


def linked_users(provider: str) -> list[tuple[str, str]]:
	"""The Frappe users that have signed in through this provider, and their subjects.

	Users who have never signed in through it carry no social login row, so there is
	nothing tying them to a directory entry and they are left alone.
	"""
	rows = frappe.get_all(
		"User Social Login",
		filters={"provider": provider},
		fields=["parent", "userid"],
		limit_page_length=0,
	)

	return [(row["parent"], row["userid"]) for row in rows]


def current_role_profiles(user) -> list[str]:
	if user.get("role_profiles"):
		return [row.get("role_profile") for row in user.get("role_profiles")]

	return [user.get("role_profile_name")] if user.get("role_profile_name") else []


def guard_against_mass_change(report: dict):
	"""Refuses a run that would de-provision most of the linked users."""
	affected = len(report["absent"]) + len(report["disabled_at_provider"])

	if not report["linked_users"] or not affected:
		return

	if affected / report["linked_users"] > MAX_AFFECTED_FRACTION:
		raise EmptyDirectoryError(
			f"{affected} of {report['linked_users']} users linked to {report['provider']} are "
			f"missing or disabled in the directory. Refusing to act on what looks like an "
			f"incomplete answer; run a dry run and check the directory."
		)


def apply_report(report, configuration, absent_user_action, by_subject, by_email):
	"""Writes what the report describes."""
	for entry in report["absent"] + report["disabled_at_provider"]:
		deprovision(entry["user"], absent_user_action)

	for change in report["roles_changed"]:
		user = frappe.get_doc("User", change["user"])
		user.flags.ignore_permissions = True
		groups = normalize_groups(change["groups"])

		apply_role_profiles(user, change["to"])
		user.module_profile = resolve_module_profile(configuration, groups)
		user.save()

		clear_sessions(user=user.name, force=True)
		frappe.clear_cache(user=user.name)
		frappe.logger().info(
			f"Reconciliation moved {user.name} from {change['from']} to {change['to']}."
		)

	frappe.db.commit()


def deprovision(user_name: str, action: str):
	"""Applies the configured action to a user the directory no longer vouches for."""
	if action == REPORT_ONLY:
		frappe.logger().info(f"Reconciliation: {user_name} is gone from the directory (report only).")
		return

	user = frappe.get_doc("User", user_name)
	user.flags.ignore_permissions = True

	# Strip entitlements in both cases: a disabled user that is re-enabled locally
	# should not come back with the roles they had when they left.
	apply_role_profiles(user, [])
	user.module_profile = None

	if action == DISABLE_USER:
		user.enabled = 0

	user.save()
	clear_sessions(user=user_name, force=True)
	frappe.clear_cache(user=user_name)
	frappe.logger().info(f"Reconciliation applied '{action}' to {user_name}.")


def run_scheduled_reconciliation():
	"""Scheduler entry point: runs each configuration that is due."""
	for provider in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)

		if not frappe.utils.cint(configuration.get("enable_reconciliation")):
			continue

		if not is_due(configuration):
			continue

		try:
			run_reconciliation(provider, dry_run=False)
			frappe.db.set_value(
				"OIDC Extended Configuration",
				provider,
				"last_reconciled_on",
				frappe.utils.now(),
				update_modified=False,
			)
			frappe.db.commit()
		except Exception:
			frappe.db.rollback()
			frappe.logger().error(f"Reconciliation of {provider} failed: {frappe.get_traceback()}")


def is_due(configuration) -> bool:
	last_run = configuration.get("last_reconciled_on")

	if not last_run:
		return True

	hours = 1 if configuration.get("reconciliation_frequency") == "Hourly" else 24

	return frappe.utils.time_diff_in_hours(frappe.utils.now(), last_run) >= hours
