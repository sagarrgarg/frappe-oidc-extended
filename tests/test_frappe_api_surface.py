"""Checks the app against the real Frappe, not against the stand-in.

The stand-in in tests/frappe_stub.py defines whatever the app asks for, so a call to
something Frappe does not actually have passes every other test and then fails at import
time on a real site. This walks the app's source for `frappe.<name>` and
`from frappe.<module> import <name>`, and checks each against the Frappe beside it in
the bench. Skipped when there is no bench to check against.
"""

import ast
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FRAPPE_ROOT = REPO_ROOT.parent / "frappe" / "frappe"
APP_SOURCES = sorted((REPO_ROOT / "oidc_extended").rglob("*.py"))


def resolve_module(module: str, level: int, source: Path) -> Path | None:
	"""The file a `from ... import` refers to, relative or absolute."""
	base = source.parent if level else FRAPPE_ROOT
	for _ in range(max(level - 1, 0)):
		base = base.parent

	parts = (module or "").split(".")
	if not level and parts and parts[0] == "frappe":
		parts = parts[1:]

	candidate = base.joinpath(*parts) if parts else base

	if candidate.with_suffix(".py").is_file():
		return candidate.with_suffix(".py")

	if (candidate / "__init__.py").is_file():
		return candidate / "__init__.py"

	return None


def module_level_names(path: Path, seen: set[Path] | None = None) -> set[str]:
	"""Every name a module defines or imports at its top level, star imports included."""
	seen = seen if seen is not None else set()

	if path in seen:
		return set()

	seen.add(path)
	names = set()
	tree = ast.parse(path.read_text())

	for node in tree.body:
		if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
			names.add(node.name)
		elif isinstance(node, ast.Assign):
			names.update(t.id for t in node.targets if isinstance(t, ast.Name))
		elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
			names.add(node.target.id)
		elif isinstance(node, ast.Import | ast.ImportFrom):
			if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
				# `from x import *`: everything that module exports lands here too, which
				# is how frappe.escape_html and frappe.DuplicateEntryError exist at all.
				starred = resolve_module(node.module, node.level, path)

				if starred:
					names |= module_level_names(starred, seen)

			names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
		elif isinstance(node, ast.If | ast.Try):
			# Names defined under `if TYPE_CHECKING:` or in a try/except import guard.
			for inner in ast.walk(node):
				if isinstance(inner, ast.Assign):
					names.update(t.id for t in inner.targets if isinstance(t, ast.Name))
				elif isinstance(inner, ast.AnnAssign) and isinstance(inner.target, ast.Name):
					names.add(inner.target.id)
				elif isinstance(inner, ast.Import | ast.ImportFrom):
					names.update((a.asname or a.name).split(".")[0] for a in inner.names)

	return names


@unittest.skipUnless(FRAPPE_ROOT.is_dir(), "no Frappe beside this app to check against")
class TestFrappeApiSurface(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.frappe_names = module_level_names(FRAPPE_ROOT / "__init__.py")
		cls.frappe_names |= {
			path.stem if path.is_file() else path.name
			for path in FRAPPE_ROOT.iterdir()
			if path.suffix == ".py" or (path.is_dir() and (path / "__init__.py").exists())
		}

	def test_every_frappe_attribute_used_exists(self):
		for source in APP_SOURCES:
			tree = ast.parse(source.read_text())

			for node in ast.walk(tree):
				if (
					isinstance(node, ast.Attribute)
					and isinstance(node.value, ast.Name)
					and node.value.id == "frappe"
				):
					self.assertIn(
						node.attr,
						self.frappe_names,
						f"{source.relative_to(REPO_ROOT)}:{node.lineno} uses frappe.{node.attr}, "
						f"which the Frappe in this bench does not define",
					)

	def test_every_name_imported_from_frappe_exists(self):
		for source in APP_SOURCES:
			tree = ast.parse(source.read_text())

			for node in ast.walk(tree):
				if not isinstance(node, ast.ImportFrom) or not (node.module or "").startswith("frappe"):
					continue

				parts = node.module.split(".")[1:]
				module_path = FRAPPE_ROOT.joinpath(*parts)
				module_file = module_path.with_suffix(".py")

				if not module_file.is_file():
					module_file = module_path / "__init__.py"

				self.assertTrue(
					module_file.is_file(),
					f"{source.relative_to(REPO_ROOT)}:{node.lineno} imports from {node.module}, "
					f"which does not exist in this bench",
				)

				defined = module_level_names(module_file)

				for alias in node.names:
					self.assertIn(
						alias.name,
						defined,
						f"{source.relative_to(REPO_ROOT)}:{node.lineno} imports {alias.name} from "
						f"{node.module}, which does not define it",
					)
