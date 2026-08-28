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

import hashlib
import hmac
import json
import re
from contextlib import contextmanager

import frappe
from frappe.rate_limiter import rate_limit
from frappe.sessions import clear_sessions

from oidc_extended.callback import (
	RESERVED_USERS,
	apply_role_grants,
	apply_role_profiles,
	disable_user,
	may_disable,
	disabling_unmapped_users,
	enable_user,
	has_no_mapped_group,
	managed_roles,
	managing_roles,
	normalize_groups,
	resolve_module_profile,
	resolve_role_profiles,
	resolve_roles,
	role_grants_target,
)
from oidc_extended.directory import EmptyDirectoryError, get_directory

REPORT_ONLY = "Report Only"
REMOVE_ALL_ROLES = "Remove All Roles"
DISABLE_USER = "Disable User"

# How long a run has to wait, per "Frequency". The scheduler calls the entry point
# every quarter of an hour and the task decides whether it is due, so the configured
# frequency is honoured however often the scheduler happens to call - and changing it
# takes effect at once rather than at the next migrate.
FREQUENCY_SECONDS = {
	"Every 15 Minutes": 15 * 60,
	"Hourly": 60 * 60,
	"Daily": 24 * 60 * 60,
}
DEFAULT_FREQUENCY_SECONDS = FREQUENCY_SECONDS["Daily"]

# A run that would de-provision most of the linked users is far more likely to be
# reading a broken directory response than a mass departure.
MAX_AFFECTED_FRACTION = 0.5

# A webhook says only "look at this user again"; a burst of group edits at the provider
# is normal, so the limit is loose.
WEBHOOK_RATE_LIMIT = 600
RATE_LIMIT_WINDOW = 60

# Keycloak admin events carry the subject in a resource path: "users/<id>", or
# "users/<id>/groups/<group id>" for a membership change.
# Deliberately permissive about the id's shape: Keycloak uses UUIDs, but nothing is
# taken on the payload's word anyway - whatever is found here is looked up in the
# directory, and an id that means nothing there simply finds no user.
RESOURCE_PATH_USER = re.compile(r"users/([^/?#]+)")


@frappe.whitelist(methods=["POST"])
def reconcile(provider: str, dry_run: int = 1) -> dict:
	"""Compares Frappe against the directory and reports, or applies, the difference.

	Runs as a dry run unless told otherwise, so the report can be read before anything
	is written.

	POST only. With `dry_run=0` this de-provisions users, and Frappe checks a CSRF token
	on everything except GET - so a System Manager who followed a link could otherwise
	have run a live reconciliation without knowing it.
	"""
	frappe.only_for("System Manager")

	return run_reconciliation(provider, dry_run=frappe.utils.cint(dry_run))


def run_reconciliation(provider: str, dry_run: bool = True) -> dict:
	configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)
	absent_user_action = configuration.get("absent_user_action") or REPORT_ONLY
	manage_roles = managing_roles(configuration)
	disable_unmapped = disabling_unmapped_users(configuration)
	managed = managed_roles(configuration) if manage_roles else set()

	# The groups are only worth the request when something reads them: on Keycloak they
	# cost one call per user, which is what stands between a fifteen-minute sweep and an
	# hourly one on a realm of any size.
	directory_users = get_directory(configuration).get_users(with_groups=manage_roles)

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
		"unmapped": [],
		"settled": [],
		"roles_changed": [],
		"unchanged": [],
		"skipped": [],
	}

	for user_name, subject in users_to_reconcile(provider, configuration):
		if user_name in RESERVED_USERS:
			report["skipped"].append({"user": user_name, "reason": "reserved account"})
			continue

		report["linked_users"] += 1
		user = frappe.get_doc("User", user_name)
		entry = by_subject.get(subject) or by_email.get((user.email or "").lower())

		if not entry:
			if nothing_left_to_do(user, absent_user_action, manage_roles):
				report["settled"].append({"user": user_name, "reason": "absent"})
			else:
				report["absent"].append({"user": user_name, "action": absent_user_action})
			continue

		if not entry["enabled"]:
			if nothing_left_to_do(user, absent_user_action, manage_roles):
				report["settled"].append({"user": user_name, "reason": "disabled at the provider"})
			else:
				report["disabled_at_provider"].append(
					{"user": user_name, "action": absent_user_action}
				)
			continue

		if not manage_roles:
			# Sign-in and offboarding only. The directory still vouches for them, and
			# what they may do here is not this app's business - so the groups are not
			# even read.
			report["unchanged"].append(user_name)
			continue

		groups = normalize_groups(entry["groups"])
		role_profiles = resolve_role_profiles(configuration, groups)
		module_profile = resolve_module_profile(configuration, groups)
		granted_roles = resolve_roles(configuration, groups)

		# The same evaluation the login does, so that a scheduled run and a login reach
		# the same verdict about the same user.
		if disable_unmapped and has_no_mapped_group(role_profiles, module_profile, granted_roles):
			if nothing_left_to_do(user, DISABLE_USER, manage_roles):
				report["settled"].append({"user": user_name, "reason": "no mapped group"})
			else:
				report["unmapped"].append({"user": user_name, "groups": entry["groups"]})
			continue

		# The identity provider vouches for them again, and this run is the only thing
		# that will notice: nothing else revisits a user who cannot log in.
		enable = disable_unmapped and not user.enabled
		current = current_role_profiles(user)
		current_roles = [row.get("role") for row in user.get("roles", []) if row.get("role")]
		target_roles = role_grants_target(user, granted_roles, managed)

		if (
			set(current) == set(role_profiles)
			and set(current_roles) == set(target_roles)
			and not enable
		):
			report["unchanged"].append(user_name)
			continue

		report["roles_changed"].append(
			{
				"user": user_name,
				"from": current,
				"to": role_profiles,
				"roles_from": sorted(current_roles),
				"roles_to": sorted(target_roles),
				"groups": entry["groups"],
				"enable": enable,
			}
		)

	guard_against_mass_change(report)

	if not dry_run:
		apply_report(report, configuration, absent_user_action, by_subject, by_email)

	return report


def users_to_reconcile(provider: str, configuration) -> list[tuple[str, str | None]]:
	"""The users this run should look at, and the subject each is known by, if any.

	By default only those who have signed in through this provider: a social login row
	is the one thing tying a Frappe user to a directory entry, so anyone without one is
	not this app's to judge.

	That is too narrow for a site whose reason for running this is offboarding. An
	account somebody created here by hand belongs to a real person who is in the
	directory, and when they leave, nothing closes it. With "Reconcile Every Enabled
	User" on, every enabled user is considered and matched by email address instead.

	The cost of that is real and is why it is off by default: a user the directory has
	never heard of cannot be told apart from one who has left. Service accounts and
	integrations go in the exemption list.

	Even then it reaches enabled System Users only. A site running ERPNext has portal
	accounts - customers, suppliers, applicants - which are enabled users who will never
	appear in a staff directory, and sweeping them in would read every one of them as
	somebody who has left and lock them all out of the portal. There can be thousands of
	them, so the exemption list is no answer and the mass-change guard only catches it
	above half. Anyone who has actually signed in through this provider is included
	whatever their user type, so the accounts this app creates are covered either way.

	Disabled users that are linked are still included, so that one the provider vouches
	for again can be enabled again. A disabled user who is not linked is left out - the
	widened sweep is about the people currently working here.
	"""
	subjects = dict(linked_users(provider))
	exempt = {
		row.get("user")
		for row in configuration.get("reconciliation_exempt_users", [])
		if row.get("user")
	}

	names = set(subjects)

	if frappe.utils.cint(configuration.get("reconcile_all_users")):
		names.update(
			frappe.get_all(
				"User",
				filters={"enabled": 1, "user_type": "System User"},
				pluck="name",
				limit_page_length=0,
			)
		)

	return sorted((name, subjects.get(name)) for name in names if name not in exempt)


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


def nothing_left_to_do(user, action: str, manage_roles: bool = True) -> bool:
	"""Whether an earlier run has already applied this action to this user.

	Reporting somebody every run is not harmless. They are written again each time -
	sessions cleared, record saved, a version row for a change that is not a change -
	and they keep counting towards the mass-change guard below. A site where more than
	half the linked users have left, or have drifted out of every mapped group, would
	eventually refuse to reconcile at all, which stops the runs that would have caught
	the next real departure.

	"Report Only" is exempt: reporting is the whole of what it does.
	"""
	if action == REPORT_ONLY:
		return False

	if action == DISABLE_USER and user.enabled:
		return False

	if not manage_roles:
		# The entitlements are the ERP's, so they are not evidence of anything here, and
		# whether the account is closed is the whole of what was asked for - which the
		# check above has already answered. "Remove All Roles" has nothing to remove, so
		# it is done the moment it is asked; reporting it every run would rewrite
		# nothing and count towards the guard for ever.
		return True

	return not (
		current_role_profiles(user) or user.get("roles") or user.get("module_profile")
	)


def current_role_profiles(user) -> list[str]:
	if user.get("role_profiles"):
		return [row.get("role_profile") for row in user.get("role_profiles")]

	return [user.get("role_profile_name")] if user.get("role_profile_name") else []


def guard_against_mass_change(report: dict):
	"""Refuses a run that would de-provision most of the linked users."""
	affected = (
		len(report["absent"]) + len(report["disabled_at_provider"]) + len(report["unmapped"])
	)

	if not report["linked_users"] or not affected:
		return

	if affected / report["linked_users"] > MAX_AFFECTED_FRACTION:
		raise EmptyDirectoryError(
			f"{affected} of the {report['linked_users']} users this run of {report['provider']} "
			f"considered are missing from the directory, disabled there, or in no group this "
			f"site maps. Refusing to act on what looks like an incomplete answer; run a dry "
			f"run and check the directory."
		)


def apply_report(report, configuration, absent_user_action, by_subject, by_email):
	"""Writes what the report describes."""
	manage_roles = managing_roles(configuration)

	for entry in report["absent"] + report["disabled_at_provider"]:
		deprovision(entry["user"], absent_user_action, strip_entitlements=manage_roles)

	for entry in report["unmapped"]:
		deprovision(
			entry["user"],
			DISABLE_USER,
			reason=f"none of the groups {entry['groups']} grants access to this site",
			strip_entitlements=manage_roles,
		)

	managed = managed_roles(configuration) if manage_roles else set()

	for change in report["roles_changed"]:
		user = frappe.get_doc("User", change["user"])
		user.flags.ignore_permissions = True
		groups = normalize_groups(change["groups"])
		granted_roles = resolve_roles(configuration, groups)

		if change.get("enable"):
			enable_user(user, f"the groups {change['groups']} grant access to this site again")

		apply_role_profiles(user, change["to"], grants_govern_roles=bool(managed))
		apply_role_grants(user, granted_roles, managed)
		user.module_profile = resolve_module_profile(configuration, groups)
		user.save()

		clear_sessions(user=user.name, force=True)
		frappe.clear_cache(user=user.name)
		frappe.logger().info(
			f"Reconciliation moved {user.name} from {change['from']} to {change['to']}."
		)

	frappe.db.commit()


def deprovision(user_name: str, action: str, reason: str = "", strip_entitlements: bool = True):
	"""Applies the configured action to a user the directory no longer vouches for.

	`strip_entitlements` is off in the sign-in and offboarding mode, where the account
	is closed and the roles are left exactly as the ERP set them. A closed account
	grants nothing, and reopening one is a decision somebody makes here.
	"""
	if action == REPORT_ONLY:
		frappe.logger().info(f"Reconciliation: {user_name} is gone from the directory (report only).")
		return

	if action != DISABLE_USER and not strip_entitlements:
		# "Remove All Roles" where the roles are not this app's to remove. The form
		# refuses the combination; this makes sure it cannot write a record to achieve
		# nothing if it ever arrives another way.
		frappe.logger().info(f"Reconciliation has nothing to apply to {user_name}.")
		return

	user = frappe.get_doc("User", user_name)
	user.flags.ignore_permissions = True

	# Read before anything is stripped: whether this is the last account that can
	# administer the site is a question about the roles it still holds. The guard covers
	# the entitlements as well as the flag, because an enabled System Manager without
	# the System Manager role is the same lockout as a disabled one - and "Remove All
	# Roles" would otherwise walk straight into it.
	refusal = may_disable(user)

	if refusal:
		frappe.logger().warning(
			f"Reconciliation is leaving {user_name} exactly as they are: {refusal}. "
			f"The reason to act was: {reason or 'the directory no longer vouches for them'}."
		)
		return

	if action == DISABLE_USER:
		disable_user(user, reason or "the directory no longer vouches for them")

	if strip_entitlements:
		# A disabled user that is re-enabled locally should not come back with the roles
		# they had when they left.
		apply_role_profiles(user, [])
		user.module_profile = None

	user.save()
	clear_sessions(user=user_name, force=True)
	frappe.clear_cache(user=user_name)
	frappe.logger().info(f"Reconciliation applied '{action}' to {user_name}.")


def run_scheduled_reconciliation():
	"""Scheduler entry point: runs each configuration that is due.

	Registered under a cron of every fifteen minutes rather than under Frappe's hourly
	event, because the scheduler cannot call something more often than the event it is
	registered under - a "Frequency" shorter than the event would have been a setting
	that could not take effect. Which of those quarter-hours actually does anything is
	`is_due`, so the frequency is honoured wherever the scheduler happens to land and a
	change to it applies from the next quarter-hour rather than from the next migrate.
	"""
	for provider in frappe.get_all("OIDC Extended Configuration", pluck="name"):
		configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)

		if not frappe.utils.cint(configuration.get("enable_reconciliation")):
			continue

		if not is_due(configuration):
			continue

		try:
			with reconciliation_lock(provider):
				# Claimed before the work starts, not after it finishes: a run that
				# takes longer than the interval would otherwise leave the slot open
				# for the next quarter-hour to walk into.
				frappe.db.set_value(
					"OIDC Extended Configuration",
					provider,
					"last_reconciled_on",
					frappe.utils.now(),
					update_modified=False,
				)
				frappe.db.commit()

				run_reconciliation(provider, dry_run=False)
				frappe.db.commit()
		except AlreadyRunningError:
			frappe.logger().info(
				f"A reconciliation of {provider} is already running; leaving it to finish."
			)
		except Exception:
			frappe.db.rollback()
			frappe.logger().error(f"Reconciliation of {provider} failed: {frappe.get_traceback()}")


class AlreadyRunningError(Exception):
	"""Another reconciliation of this provider holds the lock."""


@contextmanager
def reconciliation_lock(provider: str):
	"""Holds a provider to one reconciliation at a time.

	Frappe will not queue this job while a previous one is still queued or running
	(`ScheduledJobType.is_job_in_queue`), so the scheduled runs are already serialised.
	This covers the rest: a run started by hand from the console or the API while the
	scheduled one is in flight. Two sweeps writing the same users at once would have
	each acting on what the other had half done.
	"""
	from frappe.utils.file_lock import LockTimeoutError
	from frappe.utils.synchronization import filelock

	try:
		with filelock(f"oidc_extended_reconciliation_{provider}", timeout=0):
			yield
	except LockTimeoutError:
		raise AlreadyRunningError(provider)


def is_due(configuration) -> bool:
	"""Whether enough time has passed since the last run for another to be allowed."""
	last_run = configuration.get("last_reconciled_on")

	if not last_run:
		return True

	wait = FREQUENCY_SECONDS.get(
		configuration.get("reconciliation_frequency"), DEFAULT_FREQUENCY_SECONDS
	)

	return frappe.utils.time_diff_in_seconds(frappe.utils.now(), last_run) >= wait


@frappe.whitelist(allow_guest=True, methods=["POST"])
@rate_limit(limit=WEBHOOK_RATE_LIMIT, seconds=RATE_LIMIT_WINDOW)
def webhook():
	"""Acts on one user as soon as the identity provider says something changed.

	URL: /api/method/oidc_extended.reconciliation.webhook/<provider name>

	Keycloak has no webhook of its own - it has an event listener SPI, and the
	community providers built on it send admin events (USER, GROUP, GROUP_MEMBERSHIP)
	over HTTP in whatever shape their author chose. So nothing in the body is trusted
	beyond an identifier: the user is then looked up in the directory through the admin
	API, and what that says is what gets applied. A forged body can at most ask for a
	user to be re-checked against the truth.

	Answers 200 whenever there is nothing to do, including for a user this site does
	not have, so that the endpoint cannot be used to find out who does.
	"""
	provider = provider_from_path()

	if not provider:
		return webhook_error("Unknown provider.")

	configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)
	body = frappe.request.get_data() or b""

	if not webhook_call_is_authentic(configuration, body):
		frappe.logger().warning(f"A webhook call for {provider} did not authenticate.")
		return webhook_error("Not authorised.", http_status_code=401)

	subject, email = identifiers_in(body)

	if not (subject or email):
		frappe.logger().info(f"A webhook call for {provider} named no user; nothing to do.")
		return

	try:
		reconcile_user(provider, subject=subject, email=email)
	except Exception:
		frappe.db.rollback()
		frappe.logger().error(f"A webhook call for {provider} failed: {frappe.get_traceback()}")
		return webhook_error("The change could not be applied.", http_status_code=500)


def provider_from_path() -> str | None:
	parts = frappe.request.path[1:].split("/")

	if len(parts) != 4 or not parts[3]:
		return None

	provider = parts[3]

	if not frappe.db.exists("OIDC Extended Configuration", provider):
		return None

	return provider


def webhook_call_is_authentic(configuration, body: bytes) -> bool:
	"""Either a shared secret presented as a bearer token, or an HMAC of the body.

	Which one depends on the event listener deployed into Keycloak, so both are
	accepted. Without a secret configured the endpoint is closed: an open one would let
	anyone spend the site's directory calls.
	"""
	secret = configuration.get_password("webhook_secret") if configuration.get("webhook_secret") else None

	if not secret:
		return False

	presented = (frappe.get_request_header("Authorization") or "").removeprefix("Bearer ").strip()

	if presented and hmac.compare_digest(presented, secret):
		return True

	for header in ("X-Hub-Signature-256", "X-Keycloak-Signature", "X-Signature-256"):
		signature = (frappe.get_request_header(header) or "").removeprefix("sha256=").strip()

		if signature:
			expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

			if hmac.compare_digest(signature.lower(), expected):
				return True

	return False


def identifiers_in(body: bytes) -> tuple[str | None, str | None]:
	"""The user id and email address anywhere in the payload, whatever its shape."""
	try:
		payload = json.loads(body or b"{}")
	except ValueError:
		return None, None

	found = {"subject": None, "email": None}

	def walk(node):
		if isinstance(node, dict):
			for key, value in node.items():
				lowered = key.lower()

				if isinstance(value, str):
					if not found["subject"] and lowered in ("userid", "user_id", "sub", "id"):
						found["subject"] = value
					elif not found["subject"] and lowered in ("resourcepath", "resource_path"):
						match = RESOURCE_PATH_USER.search(value)
						if match:
							found["subject"] = match.group(1)
					elif not found["email"] and lowered == "email":
						found["email"] = value.strip().lower()

				walk(value)
		elif isinstance(node, list):
			for item in node:
				walk(item)

	walk(payload)

	return found["subject"], found["email"]


def webhook_error(description: str, http_status_code: int = 400):
	frappe.local.response["http_status_code"] = http_status_code
	frappe.local.response["error"] = description


def reconcile_user(provider: str, subject: str | None = None, email: str | None = None) -> dict:
	"""Re-checks one user against the directory and applies what it says."""
	configuration = frappe.get_cached_doc("OIDC Extended Configuration", provider)
	absent_user_action = configuration.get("absent_user_action") or REPORT_ONLY

	user_name = find_linked_user(provider, subject, email)

	if not user_name:
		frappe.logger().info(f"A change at {provider} named a user this site does not have.")
		return {"user": None, "action": "none"}

	if user_name in RESERVED_USERS:
		return {"user": user_name, "action": "skipped"}

	entry = get_directory(configuration).get_user(
		subject=subject, email=email, with_groups=managing_roles(configuration)
	)
	user = frappe.get_doc("User", user_name)
	user.flags.ignore_permissions = True

	manage_roles = managing_roles(configuration)

	if not entry or not entry["enabled"]:
		if nothing_left_to_do(user, absent_user_action, manage_roles):
			return {"user": user_name, "action": "unchanged"}

		deprovision(user_name, absent_user_action, strip_entitlements=manage_roles)
		frappe.db.commit()
		return {"user": user_name, "action": absent_user_action}

	if not manage_roles:
		# Sign-in and offboarding only: the directory still has them, so there is
		# nothing this app has an opinion about.
		return {"user": user_name, "action": "unchanged"}

	groups = normalize_groups(entry["groups"])
	role_profiles = resolve_role_profiles(configuration, groups)
	module_profile = resolve_module_profile(configuration, groups)
	granted_roles = resolve_roles(configuration, groups)
	managed = managed_roles(configuration)
	disable_unmapped = disabling_unmapped_users(configuration)

	if disable_unmapped and has_no_mapped_group(role_profiles, module_profile, granted_roles):
		if nothing_left_to_do(user, DISABLE_USER, manage_roles):
			return {"user": user_name, "action": "unchanged"}

		deprovision(
			user_name,
			DISABLE_USER,
			reason=f"none of the groups {entry['groups']} grants access to this site",
		)
		frappe.db.commit()
		return {"user": user_name, "action": DISABLE_USER}

	enable = disable_unmapped and not user.enabled
	current_roles = [row.get("role") for row in user.get("roles", []) if row.get("role")]
	target_roles = role_grants_target(user, granted_roles, managed)

	if (
		set(current_role_profiles(user)) == set(role_profiles)
		and set(current_roles) == set(target_roles)
		and not enable
	):
		return {"user": user_name, "action": "unchanged"}

	if enable:
		enable_user(user, f"the groups {entry['groups']} grant access to this site again")

	apply_role_profiles(user, role_profiles, grants_govern_roles=bool(managed))
	apply_role_grants(user, granted_roles, managed)
	user.module_profile = module_profile
	user.save()

	clear_sessions(user=user_name, force=True)
	frappe.clear_cache(user=user_name)
	frappe.db.commit()
	frappe.logger().info(f"A change at {provider} moved {user_name} to {role_profiles}.")

	return {"user": user_name, "action": "roles changed", "role_profiles": role_profiles}


def find_linked_user(provider: str, subject: str | None, email: str | None) -> str | None:
	"""The Frappe user this change is about, if it has ever signed in through here."""
	if subject:
		matched = frappe.db.get_value(
			"User Social Login", {"provider": provider, "userid": subject}, "parent"
		)

		if matched:
			return matched

	if email:
		matched = frappe.db.exists("User", email.strip().lower())

		if matched and frappe.db.get_value(
			"User Social Login", {"provider": provider, "parent": matched}, "parent"
		):
			return matched

	return None
