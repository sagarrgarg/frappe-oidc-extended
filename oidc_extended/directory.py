"""Reading users and their groups from the identity provider's own API.

OpenID Connect has nothing to say about a user who has left. A logout token says a
session ended, not why, and no standard signal carries "this person's entitlements
changed" - so the only way to learn that someone was disabled, deleted or removed from
a group is to ask the provider. That is what these clients do.

Each returns the same shape, so the reconciliation does not care which provider it is
talking to:

    {"subject": str | None, "email": str, "enabled": bool, "groups": [str]}
"""

import frappe
import requests

KEYCLOAK = "Keycloak"
AUTHENTIK = "Authentik"

PAGE_SIZE = 100

# A directory that answers with nothing is far more likely to be broken than to be
# empty, and acting on it would de-provision everyone at once.
class EmptyDirectoryError(Exception):
	pass


def get_directory(configuration):
	"""The client for the directory this configuration names."""
	directory_type = configuration.get("directory_type")

	if directory_type == KEYCLOAK:
		return KeycloakDirectory(configuration)

	if directory_type == AUTHENTIK:
		return AuthentikDirectory(configuration)

	frappe.throw(f"No directory type is configured for {configuration.get('provider')}.")


class Directory:
	def __init__(self, configuration):
		self.configuration = configuration
		self.url = (configuration.get("directory_url") or "").rstrip("/")

		if not self.url:
			frappe.throw(f"No directory URL is configured for {configuration.get('provider')}.")

	def get_users(self) -> list[dict]:
		raise NotImplementedError

	def get(self, url, **kwargs):
		response = requests.get(url, timeout=30, **kwargs)
		response.raise_for_status()
		return response.json()


class KeycloakDirectory(Directory):
	"""Keycloak's admin REST API, reached with a service account.

	The client needs "Client authentication" and "Service account roles" on, and the
	service account needs `view-users` from realm-management. `directory_url` is the
	realm URL - the same base URL the Social Login Key uses, for example
	https://idp.example.com/realms/erp.
	"""

	def __init__(self, configuration):
		super().__init__(configuration)
		# https://idp/realms/erp -> https://idp/admin/realms/erp
		base, _, realm = self.url.rpartition("/realms/")
		self.admin_url = f"{base}/admin/realms/{realm}"

	def get_token(self) -> str:
		response = requests.post(
			f"{self.url}/protocol/openid-connect/token",
			data={
				"grant_type": "client_credentials",
				"client_id": self.configuration.get("directory_client_id"),
				"client_secret": self.configuration.get_password("directory_client_secret"),
			},
			timeout=30,
		)
		response.raise_for_status()
		return response.json()["access_token"]

	def get_users(self) -> list[dict]:
		headers = {"Authorization": f"Bearer {self.get_token()}"}
		users = []
		first = 0

		while True:
			page = self.get(
				f"{self.admin_url}/users",
				headers=headers,
				params={"first": first, "max": PAGE_SIZE},
			)

			if not page:
				break

			for entry in page:
				# Keycloak's user id is the `sub` of the tokens it issues.
				groups = self.get(f"{self.admin_url}/users/{entry['id']}/groups", headers=headers)
				users.append(
					{
						"subject": entry.get("id"),
						"email": (entry.get("email") or "").strip().lower(),
						"enabled": bool(entry.get("enabled")),
						# `path` carries the full group path, which is what a group
						# membership mapper with "Full group path" on puts in the token.
						"groups": [group.get("path") or group.get("name") for group in groups],
					}
				)

			if len(page) < PAGE_SIZE:
				break

			first += PAGE_SIZE

		return users


class AuthentikDirectory(Directory):
	"""authentik's API, reached with a token.

	Matching is by email address: what authentik puts in `sub` depends on the
	provider's subject mode, so the user id here is not necessarily the subject of
	its tokens.
	"""

	def get_users(self) -> list[dict]:
		headers = {"Authorization": f"Bearer {self.configuration.get_password('directory_api_token')}"}
		users = []
		page = 1

		while True:
			result = self.get(
				f"{self.url}/api/v3/core/users/",
				headers=headers,
				params={"page": page, "page_size": PAGE_SIZE},
			)
			entries = result.get("results") or []

			for entry in entries:
				groups = entry.get("groups_obj") or []
				users.append(
					{
						"subject": None,
						"email": (entry.get("email") or "").strip().lower(),
						"enabled": bool(entry.get("is_active")),
						"groups": [group.get("name") for group in groups if group.get("name")],
					}
				)

			if not result.get("pagination", {}).get("next") or not entries:
				break

			page += 1

		return users
