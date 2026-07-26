"""N-177 + N-351 structural pin — backup collector iterates the ondisk-artifact registry, not a bare literal.

Original N-177 (2026-06-27) checked that `backup.py::build_full_bundle` calls
`.glob("msal_cache*.json")` at least once — a LITERAL shape check that failed
to catch a future artifact family added to `providers/_ondisk_artifacts.py`
but forgotten in the backup collector.

N-351 rewrite (2026-07-04, census DISCOVERED MED wf_1296c6ba-9b8): the pin now
walks the registry as a membership check. It asserts:

  (a) `build_full_bundle` imports (or receives via module-scope import) the
      `PER_ACCOUNT_ARTIFACT_GLOBS` name from `_ondisk_artifacts`.
  (b) `PER_ACCOUNT_ARTIFACT_GLOBS` is referenced INSIDE the fn body — the
      registry is actually iterated, not just imported for decoration.
  (c) The registry is non-empty at import time — a future refactor that
      empties it would silently drop every per-account artifact from every
      backup.
  (d) LEGACY: at least one `.glob("msal_cache*.json")` call remains for the
      transitional literal-shim documented in `backup.py:1197-1204` (kept
      only until the shim is removed in a follow-up commit).

The teeth-test plants a `build_full_bundle` shape that BOTH lacks the
registry reference AND has the bare literal — the new pin's (b) check must
fire.
"""
from __future__ import annotations

import ast

from tests._pin_harness import SRC_ROOT, parse_module


BACKUP = SRC_ROOT / "backup.py"


def _find_fn(tree: ast.AST, name: str) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    return None


def _names_referenced(fn: ast.AST) -> set[str]:
    """Every Name.id + Attribute.attr referenced anywhere in `fn`'s body."""
    seen: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Name):
            seen.add(n.id)
        elif isinstance(n, ast.Attribute):
            seen.add(n.attr)
        elif isinstance(n, ast.ImportFrom):
            for alias in n.names:
                seen.add(alias.name)
                if alias.asname:
                    seen.add(alias.asname)
    return seen


def test_backup_iterates_ondisk_artifact_registry():
    """N-351 — the collector MUST route per-account artifact enumeration
    through the `PER_ACCOUNT_ARTIFACT_GLOBS` registry, so a NEW artifact
    added to `_ondisk_artifacts.py` is picked up automatically."""
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None, "build_full_bundle not found in backup.py"

    referenced = _names_referenced(fn)
    assert "PER_ACCOUNT_ARTIFACT_GLOBS" in referenced, (
        "N-351 regression: build_full_bundle no longer references the "
        "PER_ACCOUNT_ARTIFACT_GLOBS registry — a new per-account artifact "
        "added to _ondisk_artifacts.py would silently drop from every backup"
    )


def test_registry_is_non_empty_at_import_time():
    """N-351 — an empty registry silently drops every artifact from every
    backup, even with the pin above green."""
    from email_triage.providers._ondisk_artifacts import PER_ACCOUNT_ARTIFACT_GLOBS
    assert len(PER_ACCOUNT_ARTIFACT_GLOBS) >= 1, (
        "PER_ACCOUNT_ARTIFACT_GLOBS is empty — the collector iterates it "
        "but there is nothing to iterate. Restore at least the msal_cache "
        "glob or explain in a comment why the registry is legitimately empty."
    )


def test_backup_no_bare_msal_cache_literal():
    """N-351 R31 (2026-07-05) — replaces LEGACY N-177 literal-glob check.
    The `test_backup_uses_glob_not_bare_singleton_LEGACY` test was removed
    together with the `data_dir.glob('msal_cache*.json')` shim at
    backup.py:1204. This pin retains the bare-literal ban so a future
    edit reverting to `msal_cache.json` string constants in
    `build_full_bundle` still fires."""
    tree = parse_module(BACKUP)
    assert tree is not None, "backup.py failed to parse"
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None

    for n in ast.walk(fn):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            if n.value in ("data/msal_cache.json", "msal_cache.json"):
                raise AssertionError(
                    f"bare '{n.value}' literal in build_full_bundle at line "
                    f"{getattr(n, 'lineno', '?')} — N-177 regression: should "
                    f"route via registry PER_ACCOUNT_ARTIFACT_GLOBS + glob"
                )


def test_pin_has_teeth():
    """N-351 teeth — a bad shape that references neither the registry NOR
    routes through a glob call MUST fail the registry-reference check
    (a) + the bare-literal-ban check (c)."""
    bad = """
def build_full_bundle(**kw):
    files = []
    msal_path = data_dir / "msal_cache.json"  # bare literal — N-177 regression
    if msal_path.is_file():
        files.append(_BundleFile(path="data/msal_cache.json", data=msal_path.read_bytes(), mode=0o600))
    return files
"""
    tree = ast.parse(bad)
    fn = _find_fn(tree, "build_full_bundle")
    assert fn is not None

    # (a) N-351 registry reference must be ABSENT in bad shape
    referenced = _names_referenced(fn)
    assert "PER_ACCOUNT_ARTIFACT_GLOBS" not in referenced, (
        "teeth: bad shape must not reference the registry"
    )

    # (c) bare literal must be PRESENT in bad shape
    bare_hits = [n for n in ast.walk(fn)
                 if isinstance(n, ast.Constant) and isinstance(n.value, str)
                 and n.value in ("data/msal_cache.json", "msal_cache.json")]
    assert bare_hits, "teeth: bad shape must contain a bare singleton literal"
