""" — AST structural pin on the migration checksum algorithm.

What this pins
--------------
The production checksum path (``Migration.checksum`` →
``_checksum_for``) MUST hash the AST-normalized body — the
post-#228 shape. The legacy raw-source SHA helper
(``_legacy_raw_checksum``) is fenced to the backward-compat dual-
check inside ``run_migrations``; it must NOT be invoked from the
production hot path.

Why a structural pin rather than only a behavioural one
-------------------------------------------------------
A behavioural test (compute the SHA, assert it equals a hard-coded
value) is fragile — the moment anyone reflows the migration body's
docstring, the expected hex changes and the test needs maintenance.
A structural pin walks the AST of the algorithm itself and asserts
"this code path normalizes before hashing" / "that code path does
not normalize." The check stays stable across cosmetic refactors
and breaks only when the *algorithm shape* changes — which is
exactly when we want to be told.

This is the count-agnostic structural-drift catch shape (see
``pattern_count_agnostic_structural_drift_catch`` standing pattern
from Cycle 8): the pin asserts a property of the code, not a count
or a literal, so it survives unrelated edits and fires only on the
property regression.

Cycle history
-------------
The bug being pinned: a future "simplify the checksum" refactor
could silently swap _checksum_for back to a raw-source SHA (one
fewer call → fewer cycles per migration body in test runs), or
accidentally point Migration.checksum at _legacy_raw_checksum. Both
would re-introduce the c163d4b → 0de1999 deploy break that 
fixes. The pin catches either before it ships.
"""

from __future__ import annotations

import ast
import inspect

from email_triage.web import migrations as mig_mod


def _module_tree() -> ast.Module:
    """Parse the migrations module's source once per call (cheap)."""
    src = inspect.getsource(mig_mod)
    return ast.parse(src)


def _find_function_def(tree: ast.Module, name: str) -> ast.FunctionDef:
    """Return the top-level ``def name(...)`` node from a parsed module."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(
        f"top-level def {name!r} not found in migrations module — "
        f"the pin's target moved or was renamed"
    )


def _calls_in(node: ast.AST) -> list[str]:
    """Return the bare name of every ``Call`` inside ``node`` (qualified
    or unqualified — ``foo.bar()`` and ``bar()`` both yield ``"bar"``)."""
    names: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name):
                names.append(sub.func.id)
            elif isinstance(sub.func, ast.Attribute):
                names.append(sub.func.attr)
    return names


# ---------------------------------------------------------------------------
# Pin 1 — Migration.checksum() must delegate to _checksum_for, nothing else.
# ---------------------------------------------------------------------------

def test_migration_checksum_method_delegates_to_normalized_path():
    """The dataclass method ``Migration.checksum`` must contain exactly
    one return statement of the form ``return _checksum_for(self.body)``.

    If a future edit replaces the delegation with a direct
    ``hashlib.sha256(...)`` call, or swaps the target to
    ``_legacy_raw_checksum``, this pin fires.
    """
    tree = _module_tree()
    # Find the Migration class, then its checksum method.
    cls_node: ast.ClassDef | None = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Migration":
            cls_node = node
            break
    assert cls_node is not None, "class Migration not found"

    method: ast.FunctionDef | None = None
    for node in cls_node.body:
        if isinstance(node, ast.FunctionDef) and node.name == "checksum":
            method = node
            break
    assert method is not None, "Migration.checksum method not found"

    calls = _calls_in(method)
    assert calls == ["_checksum_for"], (
        f"Migration.checksum must delegate to exactly _checksum_for "
        f"(post-#228 normalized shape). Found calls: {calls}. If the "
        f"algorithm is being intentionally changed, update this pin AND "
        f"the backward-compat dual-check in run_migrations together."
    )
    assert "_legacy_raw_checksum" not in calls, (
        "Migration.checksum must not invoke _legacy_raw_checksum — the "
        "legacy SHA is fenced to the dual-check in run_migrations only "
        "(#286)."
    )


# ---------------------------------------------------------------------------
# Pin 2 — _checksum_for() must normalize before hashing.
# ---------------------------------------------------------------------------

def test_checksum_for_hashes_normalized_body():
    """``_checksum_for`` must call ``_normalize_body`` and feed the
    result into ``hashlib.sha256`` — exactly the post-#228 algorithm.

    A regression that drops the ``_normalize_body`` call (so we hash
    raw ``inspect.getsource`` again) would re-introduce the original
    pre-#228 hash shape on every install — every freshly-applied
    migration would record a legacy-shape checksum, and the dual-check
    in run_migrations would have nothing to reconcile against. The
    deploy break wouldn't surface until a *different* algorithm change
    landed.
    """
    tree = _module_tree()
    fn = _find_function_def(tree, "_checksum_for")
    calls = _calls_in(fn)
    assert "_normalize_body" in calls, (
        "_checksum_for must normalize the body before hashing (post-#228 "
        f"contract). Found calls: {calls}"
    )
    assert "sha256" in calls, (
        f"_checksum_for must use hashlib.sha256. Found calls: {calls}"
    )
    # And the legacy raw-source helper must NOT appear here — it lives
    # in its own function for the compare-branch fallback.
    assert "_legacy_raw_checksum" not in calls


# ---------------------------------------------------------------------------
# Pin 3 — _legacy_raw_checksum() must NOT normalize.
# ---------------------------------------------------------------------------

def test_legacy_raw_checksum_does_not_normalize():
    """``_legacy_raw_checksum`` must reproduce the pre-#228 algorithm
    BYTE-FOR-BYTE: SHA-256 over the raw ``inspect.getsource`` output
    with no AST normalization. If anyone "improves" it to call
    ``_normalize_body`` first, it stops matching the live-DB checksums
    that the dual-check exists to reconcile — the deploy break 
    fixes silently returns.
    """
    tree = _module_tree()
    fn = _find_function_def(tree, "_legacy_raw_checksum")
    calls = _calls_in(fn)
    assert "_normalize_body" not in calls, (
        "_legacy_raw_checksum must NOT normalize — it reproduces the "
        "pre-#228 raw-source SHA shape exactly. Found calls: "
        f"{calls}"
    )
    assert "getsource" in calls, (
        "_legacy_raw_checksum must hash inspect.getsource(body). Found "
        f"calls: {calls}"
    )
    assert "sha256" in calls


# ---------------------------------------------------------------------------
# Pin 4 — _legacy_raw_checksum is reachable only from run_migrations.
# ---------------------------------------------------------------------------

def test_legacy_raw_checksum_reachable_only_from_dual_check():
    """Module-wide grep (over the AST): the only call site of
    ``_legacy_raw_checksum`` outside its own definition must be
    ``run_migrations``. Any other production call site would re-route
    the hot path through the legacy shape and re-open the c163d4b
    deploy break.

    Test files calling it for verification are fine — they are not in
    this module — but no production helper or property should reach
    for it.
    """
    tree = _module_tree()
    # Collect, per top-level def/class, every Call name inside its body.
    legacy_callers: list[str] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == "_legacy_raw_checksum":
                continue  # the function itself doesn't count
            if "_legacy_raw_checksum" in _calls_in(node):
                legacy_callers.append(node.name)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if "_legacy_raw_checksum" in _calls_in(sub):
                        legacy_callers.append(f"{node.name}.{sub.name}")
    assert legacy_callers == ["run_migrations"], (
        "_legacy_raw_checksum must be reachable only from "
        "run_migrations (the backward-compat dual-check). Found "
        f"additional production callers: {legacy_callers}. If a new "
        "call site is intentional, update this pin and document the "
        "reason in the call site's docstring."
    )
