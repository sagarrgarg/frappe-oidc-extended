"""An in-memory stand-in for the parts of Frappe that `oidc_extended.callback` uses.

These tests run without a bench: `install()` registers fake `frappe`, `frappe.utils`,
`frappe.utils.oauth`, `frappe.sessions` and
`frappe.integrations.doctype.social_login_key.social_login_key` modules in `sys.modules`
before the app is imported. Behaviour mirrors Frappe v15/v16 where the callback depends
on it (single-use OAuth state, `User` autonamed by email, role profiles replacing roles
on save, permlevel-guarded fields), so a passing test says something about the real thing.
"""

import sys
import types


class DoesNotExistError(Exception):
	pass


class DuplicateEntryError(Exception):
	pass


class ValidationError(Exception):
	pass


class WebPageResponse(Exception):
	"""Raised by nothing - collected, so tests can assert on `respond_as_web_page` calls."""


class FakeDoc:
	"""Duck-typed Frappe Document: attribute access over a dict, child tables as lists."""

	def __init__(self, data=None, store=None):
		object.__setattr__(self, "_data", dict(data or {}))
		object.__setattr__(self, "_store", store)
		object.__setattr__(self, "flags", types.SimpleNamespace(ignore_permissions=False))
		object.__setattr__(self, "save_count", 0)

	# -- attribute / item access -------------------------------------------------
	def __getattr__(self, key):
		try:
			return object.__getattribute__(self, "_data")[key]
		except KeyError:
			return None

	def __setattr__(self, key, value):
		if key in ("flags", "save_count", "_data", "_store"):
			object.__setattr__(self, key, value)
		else:
			self._data[key] = value

	def get(self, key, default=None):
		value = self._data.get(key, default)
		return value if value is not None else default

	def set(self, key, value):
		self._data[key] = value

	def append(self, key, value):
		row = value if isinstance(value, FakeDoc) else FakeDoc(value)
		self._data.setdefault(key, []).append(row)
		return row

	def as_dict(self):
		return dict(self._data)

	def get_password(self, fieldname, raise_exception=True):
		return self._data.get(fieldname) or "secret"

	def is_new(self):
		return not self._data.get("__saved")

	# -- social login ------------------------------------------------------------
	def get_social_login_userid(self, provider):
		for row in self._data.get("social_logins", []):
			if row.get("provider") == provider:
				return row.get("userid")
		return None

	def set_social_login_userid(self, provider, userid, username=None):
		for row in self._data.get("social_logins", []):
			if row.get("provider") == provider:
				row.set("userid", userid)
				return
		self.append("social_logins", {"provider": provider, "userid": userid, "username": username})

	# -- persistence -------------------------------------------------------------
	def save(self, ignore_permissions=False):
		self.save_count += 1
		store = self._store
		if store is not None:
			store.save(self)
		self._data["__saved"] = True
		return self

	def insert(self, ignore_permissions=False, ignore_if_duplicate=False):
		return self.save()

	def db_set(self, key, value, **kwargs):
		self._data[key] = value


class UserStore:
	"""Emulates the `User` table: named by email, with Frappe's save-time role logic."""

	def __init__(self, frappe_module):
		self.users = {}
		self.frappe = frappe_module

	def add(self, **fields):
		# Child table values may be given as plain dicts for brevity.
		fields = {
			key: [row if isinstance(row, FakeDoc) else FakeDoc(row) for row in value]
			if isinstance(value, list)
			else value
			for key, value in fields.items()
		}
		doc = FakeDoc(fields, store=self)
		doc._data.setdefault("name", fields.get("email"))
		doc._data["__saved"] = True
		self.users[doc.name] = doc
		return doc

	def save(self, doc):
		# Frappe autonames User by email; a second insert with the same email raises.
		name = doc.get("name") or doc.get("email")
		if doc.is_new() and name in self.users:
			raise DuplicateEntryError(f"User {name} already exists")
		doc._data["name"] = name

		# Mirror User.validate(): a set role profile replaces the role table wholesale
		# (frappe/core/doctype/user/user.py::populate_role_profile_roles on v15,
		# the role_profiles child table on v16).
		meta = self.frappe.get_meta("User")
		profiles = []
		if meta.has_field("role_profiles"):
			profiles = [r.role_profile for r in doc.get("role_profiles", [])]
		elif doc.get("role_profile_name"):
			profiles = [doc.get("role_profile_name")]

		if profiles:
			roles = []
			for profile in profiles:
				roles.extend(self.frappe.flags.role_profile_roles.get(profile, []))
			doc.set("roles", [FakeDoc({"role": r}) for r in dict.fromkeys(roles)])

		if meta.has_field("role_profiles"):
			# Mirror User.sync_role_profile_name(): the deprecated Link field is kept in
			# step with the first row of the child table, for the list view.
			doc.set("role_profile_name", profiles[0] if profiles else None)

		# Mirror User.set_system_user(): the two standard types are derived from whether
		# any assigned role has desk access; a custom User Type is kept as set.
		if doc.get("user_type") in self.frappe.flags.standard_user_types or not doc.get("user_type"):
			has_desk_access = any(
				row.get("role") in self.frappe.flags.desk_roles for row in doc.get("roles", [])
			)
			doc.set("user_type", "System User" if has_desk_access else "Website User")

		self.users[name] = doc
		return doc


def _make_logger():
	calls = []

	class _Logger:
		def __getattr__(self, level):
			def _log(*args, **kwargs):
				calls.append((level, args[0] if args else ""))

			return _log

	logger = _Logger()
	logger_calls = calls
	return logger, logger_calls


def install():
	"""Register the fake modules in sys.modules and return the fake `frappe` module."""
	frappe = types.ModuleType("frappe")

	# -- exceptions / misc -------------------------------------------------------
	frappe.__version__ = "15.116.1"
	frappe.DoesNotExistError = DoesNotExistError
	frappe.DuplicateEntryError = DuplicateEntryError
	frappe.ValidationError = ValidationError
	frappe.flags = types.SimpleNamespace(
		role_profile_roles={},
		module_profiles={},
		signup_disabled=False,
		standard_user_types={"System User", "Website User"},
		desk_roles=set(),
	)
	frappe.session = types.SimpleNamespace(user="Guest")
	frappe._ = lambda msg, *a, **kw: msg
	frappe.generate_hash = lambda length=56: "h" * (length or 56)
	frappe.throw = _throw

	def whitelist(allow_guest=False, xss_safe=False, methods=None):
		def decorator(fn):
			fn.is_whitelisted = True
			fn.allow_guest = allow_guest
			fn.allowed_methods = methods or ["GET", "POST", "PUT", "DELETE"]
			return fn

		return decorator

	frappe.whitelist = whitelist

	# frappe.rate_limiter.rate_limit - it is NOT an attribute of the frappe module.
	frappe.msgprint = lambda *a, **kw: None

	logger, logger_calls = _make_logger()
	frappe.logger = lambda *a, **kw: logger
	frappe.logger_calls = logger_calls

	# -- responses ---------------------------------------------------------------
	frappe.web_pages = []

	def respond_as_web_page(title, html, **kwargs):
		frappe.web_pages.append({"title": title, "html": html, **kwargs})

	frappe.respond_as_web_page = respond_as_web_page

	# -- request / response / session -------------------------------------------
	frappe.request = types.SimpleNamespace(
		path="/api/method/oidc_extended.callback.custom/authentik",
		url="https://erp.example.com/api/method/oidc_extended.callback.custom/authentik",
	)

	class _LoginManager:
		def __init__(self):
			self.user = None
			self.post_login_calls = 0
			self.login_as_calls = []

		def post_login(self, *args, **kwargs):
			self.post_login_calls += 1
			frappe.local.response["message"] = "Logged In"

		def login_as(self, user, **kwargs):
			self.login_as_calls.append(user)
			self.user = user
			self.post_login()

	frappe.local = types.SimpleNamespace(response={}, login_manager=_LoginManager())

	# -- doc access --------------------------------------------------------------
	frappe.docs = {}  # (doctype, name) -> FakeDoc
	frappe.user_store = UserStore(frappe)

	def get_doc(*args, **kwargs):
		if args and isinstance(args[0], dict):
			data = dict(args[0])
			doctype = data.get("doctype")
			if doctype == "User":
				return FakeDoc(data, store=frappe.user_store)
			return FakeDoc(data)
		doctype, name = args[0], args[1]
		if doctype == "User":
			doc = frappe.user_store.users.get(name)
			if not doc:
				raise DoesNotExistError(f"User {name} not found")
			return doc
		doc = frappe.docs.get((doctype, name))
		if doc is None:
			raise DoesNotExistError(f"{doctype} {name} not found")
		return doc

	frappe.get_doc = get_doc
	frappe.get_cached_doc = get_doc
	frappe.new_doc = lambda doctype: FakeDoc(
		{"doctype": doctype}, store=frappe.user_store if doctype == "User" else None
	)

	# -- meta --------------------------------------------------------------------
	frappe.user_fields = {  # default: Frappe v15
		"name", "email", "username", "first_name", "last_name", "enabled",
		"user_type", "role_profile_name", "module_profile", "roles", "block_modules",
	}

	class _Meta:
		def __init__(self, doctype):
			self.doctype = doctype

		def has_field(self, fieldname):
			if self.doctype != "User":
				return True
			return fieldname in frappe.user_fields

	frappe.get_meta = _Meta

	# -- db ----------------------------------------------------------------------
	class _DB:
		def __init__(self):
			self.commits = 0
			self.rollbacks = 0

		def exists(self, doctype, filters=None):
			if doctype == "User":
				if isinstance(filters, str):
					return filters if filters in frappe.user_store.users else None
				for name, doc in frappe.user_store.users.items():
					if all(doc.get(k) == v for k, v in filters.items()):
						return name
				return None
			if isinstance(filters, str):
				return filters if (doctype, filters) in frappe.docs else None
			return None

		def get_value(self, doctype, name, fieldname=None, **kwargs):
			if doctype == "User Social Login" and isinstance(name, dict):
				# Child table lookup: returns the parent User, as Frappe does.
				for user_name, user in frappe.user_store.users.items():
					for row in user.get("social_logins", []):
						if all(row.get(k) == v for k, v in name.items()):
							return user_name if fieldname == "parent" else row.get(fieldname)
				return None

			doc = frappe.docs.get((doctype, name))
			if doctype == "User":
				doc = frappe.user_store.users.get(name)
			if not doc:
				return None
			if isinstance(fieldname, list | tuple):
				return [doc.get(f) for f in fieldname]
			return doc.get(fieldname)

		def commit(self):
			self.commits += 1

		def rollback(self):
			self.rollbacks += 1

	frappe.db = _DB()

	# -- cache -------------------------------------------------------------------
	class _Cache:
		def __init__(self):
			self.store = {}
			self.deleted = []

		def __call__(self):
			return self

		def set_value(self, key, value, expires_in_sec=None):
			self.store[key] = value

		def get_value(self, key):
			return self.store.get(key)

		def delete_value(self, key):
			self.deleted.append(key)
			return self.store.pop(key, None)

		def hdel(self, name, key):
			self.deleted.append((name, key))

	frappe.cache = _Cache()
	frappe.cleared_caches = []
	frappe.clear_cache = lambda **kwargs: frappe.cleared_caches.append(kwargs)

	# -- conf --------------------------------------------------------------------
	frappe.conf = {}
	frappe.get_conf = lambda *a, **kw: frappe.conf

	# -- frappe.utils ------------------------------------------------------------
	utils = types.ModuleType("frappe.utils")
	utils.get_url = lambda path="", **kw: f"https://erp.example.com{path}" if str(path).startswith("/") else (path or "https://erp.example.com")
	frappe.log_level_calls = []
	utils.logger = types.SimpleNamespace(
		set_log_level=lambda level: frappe.log_level_calls.append(level)
	)
	utils.cint = lambda v: int(v or 0)

	def escape_html(text):
		"""As frappe.utils.escape_html does: the message of a web page is raw HTML."""
		for character, escaped in (
			("&", "&amp;"), ("<", "&lt;"), (">", "&gt;"), ('"', "&quot;"), ("'", "&#39;")
		):
			text = str(text).replace(character, escaped)
		return text

	utils.escape_html = escape_html
	frappe.utils = utils

	# -- frappe.utils.oauth ------------------------------------------------------
	oauth = types.ModuleType("frappe.utils.oauth")
	OAUTH_LOGIN_FLOW_CACHE_PREFIX = "frappe_oauth_login"

	def create_oauth_state(redirect_to):
		state = "s" * 32
		frappe.cache.set_value(f"{OAUTH_LOGIN_FLOW_CACHE_PREFIX}:{state}", redirect_to or "")
		return state

	def consume_oauth_state(state):
		if not state:
			return None
		key = f"{OAUTH_LOGIN_FLOW_CACHE_PREFIX}:{state}"
		redirect_to = frappe.cache.get_value(key)
		frappe.cache.delete_value(key)
		return redirect_to

	def build_oauth_url(base_url, url=None):
		from urllib.parse import urlparse

		if url is None:
			return base_url
		parsed = urlparse(url)
		if not (parsed.scheme and parsed.netloc):
			return base_url + url
		return url

	oauth.build_oauth_url = build_oauth_url
	oauth.create_oauth_state = create_oauth_state
	oauth.consume_oauth_state = consume_oauth_state
	oauth.authorize_urls = []

	def get_oauth2_authorize_url(provider, redirect_to):
		state = create_oauth_state(redirect_to)
		url = f"https://idp.example.com/authorize?provider={provider}&state={state}"
		oauth.authorize_urls.append(url)
		return url

	oauth.get_oauth2_authorize_url = get_oauth2_authorize_url
	frappe.utils.oauth = oauth

	# -- frappe.www.login --------------------------------------------------------
	www = types.ModuleType("frappe.www")
	login = types.ModuleType("frappe.www.login")

	def sanitize_redirect(redirect):
		"""Same-site redirects only, as frappe.www.login.sanitize_redirect does."""
		from urllib.parse import urlparse

		if not redirect:
			return redirect

		parsed = urlparse(redirect)
		if parsed.netloc and parsed.netloc != urlparse(frappe.request.url).netloc:
			return "/app"
		return parsed.path or "/app"

	login.sanitize_redirect = sanitize_redirect

	# -- frappe.rate_limiter -----------------------------------------------------
	rate_limiter = types.ModuleType("frappe.rate_limiter")

	def rate_limit(key=None, limit=5, seconds=24 * 60 * 60, methods="ALL", ip_based=True):
		"""Records the declared limit; the counting itself is Frappe's, not ours."""

		def decorator(fn):
			fn.rate_limit = {"limit": limit, "seconds": seconds, "ip_based": ip_based}
			return fn

		return decorator

	rate_limiter.rate_limit = rate_limit
	frappe.rate_limiter = rate_limiter

	# -- frappe.sessions ---------------------------------------------------------
	sessions = types.ModuleType("frappe.sessions")
	sessions.cleared = []
	sessions.clear_sessions = lambda user=None, keep_current=False, force=False: sessions.cleared.append(
		{"user": user, "keep_current": keep_current, "force": force}
	)
	frappe.sessions = sessions

	# -- frappe.integrations.doctype.social_login_key.social_login_key -----------
	integrations = types.ModuleType("frappe.integrations")
	int_doctype = types.ModuleType("frappe.integrations.doctype")
	slk_pkg = types.ModuleType("frappe.integrations.doctype.social_login_key")
	slk = types.ModuleType("frappe.integrations.doctype.social_login_key.social_login_key")

	def provider_allows_signup(provider):
		doc = frappe.docs.get(("Social Login Key", provider))
		sign_ups = doc.get("sign_ups") if doc else None
		if not sign_ups:
			# Frappe falls back to the site's website signup setting.
			return not frappe.flags.signup_disabled
		return sign_ups == "Allow"

	slk.provider_allows_signup = provider_allows_signup

	# -- register ----------------------------------------------------------------
	for name, module in (
		("frappe", frappe),
		("frappe.utils", utils),
		("frappe.utils.oauth", oauth),
		("frappe.sessions", sessions),
		("frappe.rate_limiter", rate_limiter),
		("frappe.www", www),
		("frappe.www.login", login),
		("frappe.integrations", integrations),
		("frappe.integrations.doctype", int_doctype),
		("frappe.integrations.doctype.social_login_key", slk_pkg),
		("frappe.integrations.doctype.social_login_key.social_login_key", slk),
	):
		sys.modules[name] = module

	return frappe


def _throw(msg, exc=ValidationError, **kwargs):
	raise exc(msg)
