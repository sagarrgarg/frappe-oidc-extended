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


class ClientNotFoundError(Exception):
	"""The provider has no client under the id the Social Login Key presents."""
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

	def get_user(self, subject: str | None = None, email: str | None = None) -> dict | None:
		raise NotImplementedError

	def get_group_names(self, client_id: str | None = None) -> tuple[list[str], str]:
		"""The group names this site could map, and where they were read from.

		Returns the vocabulary, not anybody's membership: it is what fills the mapping
		tables in, so an administrator picks profiles from a list the provider gave
		rather than copying strings by hand and finding out at the next login that one
		of them had a typo.
		"""
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


	def get_group_names(self, client_id: str | None = None) -> tuple[list[str], str]:
		"""The client's own roles, falling back to the realm's groups.

		Client roles first, because they are scoped by construction: a group membership
		mapper is realm-wide, so every client of the realm sees every group and "this
		user has no group here" never means anything. A client role belongs to one
		client and is invisible to the others. Bind the directory group to the client
		role in Keycloak and the membership still flows through unchanged - what
		changes is that the absence of one becomes a statement worth acting on.

		Realms that map realm groups into the token instead are not left out: when the
		client defines no roles, the group paths are read instead, which is what a
		membership mapper with "Full group path" on puts in the claim.
		"""
		headers = {"Authorization": f"Bearer {self.get_token()}"}
		roles = self.get_client_roles(client_id, headers) if client_id else []

		if roles:
			return roles, f"the roles of the {client_id} client"

		return self.get_group_paths(headers), "the groups of the realm"

	def get_client_roles(self, client_id: str, headers: dict) -> list[str]:
		"""The roles defined on one client, by its client id rather than its uuid."""
		clients = self.get(
			f"{self.admin_url}/clients", headers=headers, params={"clientId": client_id}
		)

		if not clients:
			raise ClientNotFoundError(client_id)

		roles = self.get(f"{self.admin_url}/clients/{clients[0]['id']}/roles", headers=headers)

		return [role["name"] for role in roles if role.get("name")]

	def get_group_paths(self, headers: dict) -> list[str]:
		"""Every group path in the realm, subgroups included."""
		paths = []

		def collect(groups):
			for group in groups:
				path = group.get("path") or group.get("name")

				if path:
					paths.append(path)

				collect(group.get("subGroups") or [])

		first = 0

		while True:
			page = self.get(
				f"{self.admin_url}/groups", headers=headers, params={"first": first, "max": PAGE_SIZE}
			)
			collect(page)

			if len(page) < PAGE_SIZE:
				break

			first += PAGE_SIZE

		return paths

	def get_user(self, subject: str | None = None, email: str | None = None) -> dict | None:
		"""One user, for acting on a single change rather than sweeping everyone."""
		headers = {"Authorization": f"Bearer {self.get_token()}"}

		try:
			if subject:
				entry = self.get(f"{self.admin_url}/users/{subject}", headers=headers)
			elif email:
				matches = self.get(
					f"{self.admin_url}/users", headers=headers, params={"email": email, "exact": True}
				)
				entry = matches[0] if matches else None
			else:
				return None
		except requests.HTTPError as exception:
			if exception.response is not None and exception.response.status_code == 404:
				# Deleted at the provider, which is a fact worth acting on.
				return None
			raise

		if not entry:
			return None

		groups = self.get(f"{self.admin_url}/users/{entry['id']}/groups", headers=headers)

		return {
			"subject": entry.get("id"),
			"email": (entry.get("email") or "").strip().lower(),
			"enabled": bool(entry.get("enabled")),
			"groups": [group.get("path") or group.get("name") for group in groups],
		}


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

	def get_group_names(self, client_id: str | None = None) -> tuple[list[str], str]:
		"""authentik's groups. It has no per-client role vocabulary to prefer."""
		headers = {"Authorization": f"Bearer {self.configuration.get_password('directory_api_token')}"}
		names = []
		page = 1

		while True:
			result = self.get(
				f"{self.url}/api/v3/core/groups/",
				headers=headers,
				params={"page": page, "page_size": PAGE_SIZE},
			)
			entries = result.get("results") or []
			names.extend(entry["name"] for entry in entries if entry.get("name"))

			if not result.get("pagination", {}).get("next") or not entries:
				break

			page += 1

		return names, "the groups of the directory"

	def get_user(self, subject: str | None = None, email: str | None = None) -> dict | None:
		if not email:
			return None

		headers = {"Authorization": f"Bearer {self.configuration.get_password('directory_api_token')}"}
		result = self.get(
			f"{self.url}/api/v3/core/users/", headers=headers, params={"email": email}
		)

		for entry in result.get("results") or []:
			if (entry.get("email") or "").strip().lower() == email.strip().lower():
				return {
					"subject": None,
					"email": email.strip().lower(),
					"enabled": bool(entry.get("is_active")),
					"groups": [g.get("name") for g in entry.get("groups_obj") or [] if g.get("name")],
				}

		return None
