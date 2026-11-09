"""N-335b R31 — function-scope SHADOW-import walker + pin.

Complementary to N-338c AST name-resolution walker (which catches
unresolved names) and N-295 py_compile pin (which catches SyntaxError
only).

Scope of this pin: a **function-scope** ``import X`` / ``from Y import
X`` statement whose target name ``X`` is ALSO imported at module scope
in the same file. These are always defects:

* The module-scope import satisfies the name; the function-scope
  re-import is dead code that adds noise and drift risk.
* The class matches N-323 / N-269b / N-319 / Phase-4 LOW-N-344 (all
  "function-scope shadow import"), and the underlying pattern
  ``incident_2026-06-11_topic_digest_dead_in_prod`` demonstrated the
  cousin failure mode: a function-scope import whose top-level twin
  is missing → the top-level ``py_compile`` never fires; the function
  imports at RUNTIME and only the executed path surfaces the missing
  symbol. When the shadow twin IS present at module scope, the
  runtime import is silent noise; when the shadow twin is MISSING at
  module scope but a function-scope import satisfies it, the top-
  level pin is fail-open. Either shape is a defect class this
  walker catches.

The pin uses a **(file, name) allow-list** baseline at N-335b landing
(15 pairs across 9 files, 2026-07-08). Each entry is a MIGRATION
IOU — tranches (queued as the backlog follow-ups) delete the shadow
imports, shrinking the allow-list monotonically. NEW files (not in
the allow-list) MUST NOT introduce a function-scope shadow import.

TYPE_CHECKING-guarded imports are exempt — they never execute at
runtime (only the type-checker sees them) so they cannot be dead
code; they are the canonical way to break a circular-import chain
for annotations only.
"""
from __future__ import annotations

import ast

import pytest

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath


# Baseline shadow-import sites at N-335b landing (2026-07-08). Each entry
# is (file, name). The tuple is closed against the shadow-detection
# predicate (see ``_walk`` below). Migration cycle deletes these sites +
# shrinks the set monotonically. Adding a new file/name entry requires
# an explanatory comment in the migration commit.
_ALLOWLIST_SHADOW: frozenset[tuple[str, str]] = frozenset({
    # 15 (file, name) pairs at N-335b landing (2026-07-08) — the walker's
    # SHADOW predicate says: this name is bound at BOTH module scope AND
    # a function body. Migration tranches (queued as the backlog follow-
    # ups) delete the function-scope re-imports, shrinking this set
    # monotonically.
    ("cli.py", "json"),
    ("cli.py", "os"),
    ("db/accounts.py", "json"),
    ("db/accounts.py", "load_json_col"),
    ("providers/imap.py", "email"),
    ("secrets.py", "os"),
    ("triage_logging.py", "sys"),
    ("web/routers/ui/_shared.py", "read_secret"),
    ("web/routers/ui/profile.py", "get_user_by_email"),
})


def _module_scope_names(tree: ast.Module) -> set[str]:
    """Names bound by module-scope Import / ImportFrom statements.

    TYPE_CHECKING-guarded imports are EXCLUDED — they never execute at
    runtime so a function-scope re-import is legitimate (breaks a
    circular annotation-only chain).
    """
    names: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            for a in node.names:
                names.add(a.asname or a.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for a in node.names:
                names.add(a.asname or a.name)
        elif isinstance(node, ast.If):
            # if TYPE_CHECKING: block — do NOT harvest names from
            # inside (those are type-only forward references).
            if _is_type_checking_guard(node.test):
                continue
            # Non-TYPE_CHECKING If at module scope — harvest recursively.
            for sub in ast.walk(node):
                if isinstance(sub, ast.Import):
                    for a in sub.names:
                        names.add(a.asname or a.name.split(".")[0])
                elif isinstance(sub, ast.ImportFrom):
                    for a in sub.names:
                        names.add(a.asname or a.name)
    return names


def _is_type_checking_guard(test: ast.expr) -> bool:
    """Is this ``if TYPE_CHECKING:`` or ``if typing.TYPE_CHECKING:``?"""
    if isinstance(test, ast.Name) and test.id == "TYPE_CHECKING":
        return True
    if isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING":
        return True
    return False


def _fn_names_from_import(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Import):
        return [a.asname or a.name.split(".")[0] for a in node.names]
    if isinstance(node, ast.ImportFrom):
        return [a.asname or a.name for a in node.names]
    return []


def _walk() -> list[tuple[str, int, str]]:
    """Return (relpath, lineno, name) for every function-scope shadow import."""
    sites: list[tuple[str, int, str]] = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None or not isinstance(tree, ast.Module):
            continue
        module_names = _module_scope_names(tree)
        rp = relpath(path)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for sub in ast.walk(node):
                if sub is node:
                    continue
                if not isinstance(sub, (ast.Import, ast.ImportFrom)):
                    continue
                for name in _fn_names_from_import(sub):
                    if name in module_names:
                        sites.append((rp, sub.lineno, name))
    return sites


def test_no_new_function_scope_shadow_imports():
    """Every function-scope shadow import must be in the baseline.

    Fails if a NEW file (not in the allow-list) introduces a shadow
    import. Also fails if an EXISTING allow-listed (file, name) is
    removed from the source but the allow-list still carries it —
    ratchet-shrink discipline.
    """
    live_sites = _walk()
    live_pairs = {(rp, name) for rp, _lineno, name in live_sites}

    # New offenders — sites not in the baseline allow-list.
    new_offenders = live_pairs - _ALLOWLIST_SHADOW
    assert not new_offenders, (
        "NEW function-scope shadow imports detected — the enclosing "
        "function re-imports a name that is ALREADY imported at module "
        "scope. Delete the function-scope import (the module-scope "
        "import already satisfies the name), OR — if breaking a "
        "genuine circular import — move the shadow twin under an "
        "``if TYPE_CHECKING:`` guard at module scope (annotation-only) "
        "OR add the site to ``_ALLOWLIST_SHADOW`` with an explanatory "
        "comment in the commit:\n" +
        "\n".join(sorted(f"  {rp}:{lineno} name={name}" for rp, lineno, name in live_sites if (rp, name) in new_offenders))
    )

    # Stale allow-list entries — baseline entry no longer has a live site.
    stale = _ALLOWLIST_SHADOW - live_pairs
    assert not stale, (
        "Ratchet-shrink: allow-list entries are no longer live — "
        "REMOVE them from ``_ALLOWLIST_SHADOW`` (baseline shrinks "
        "monotonically):\n" +
        "\n".join(sorted(f"  ({rp!r}, {name!r})" for rp, name in stale))
    )


def test_walk_returns_expected_baseline_shape():
    """Sanity — the walker's live-site enumeration is non-empty at
    landing (15 pairs across 9 files, 2026-07-08).

    Guards against a walker mis-implementation that silently returns
    an empty set — which would make ``new_offenders`` vacuously pass
    forever (fail-OPEN, exactly the class Prime Directive #8 forbids).
    """
    sites = _walk()
    assert sites, (
        "walker returned zero live sites — the shadow-detection "
        "predicate is likely broken. At N-335b landing (2026-07-08) "
        "the baseline is 15 (file,name) pairs; zero-return is a walker defect."
    )
    files = {rp for rp, _l, _n in sites}
    assert len(files) >= 5, (
        f"walker returned live sites in only {len(files)} file(s); "
        f"expected ≥ 5 at N-335b landing. Likely walker defect."
    )
