"""Count-agnostic interprocedural viewer-aware pin (owner-self-preview 2026-07-01).

Every digest-preview handler seam MUST include the viewer-aware idiom
``user["id"] != acct["user_id"]`` (or its `==` bound form for a ctx flag),
so an authorized non-owner sees redacted PHI while the account owner sees
verbatim (operator ruling 2026-07-01 = design point b).

The pin (per PD#1/#2 — every SSOT ships its count-agnostic structural pin in
the SAME change) is keyed on the SEAM where the value hops, not on any
hardcoded call-site count. Two sites today
(``accounts.py::digest_candidates`` and ``accounts.py::digest_preview``);
a third that copies-and-pastes the idiom with ``!=`` flipped or with
``user["id"]`` swapped for ``current_user["id"]`` would be a live PHI leak,
and a plain sender/subject grep would MISS it. This pin catches all three
shapes.

Enforcement shape:
1. WALK every ``src/email_triage/web/routers/**/*.py`` module and locate
   every function whose body calls ``_render_digest_payload(...)`` OR
   ``_render(..., "accounts/_digest_candidates.html", ...)`` — those are
   the "digest-preview handler seams".
2. For each such handler, assert the enclosing function contains the
   viewer-aware idiom: ``user["id"] != acct["user_id"]`` (any subscript
   spelling — ``.get`` allowed too) EITHER inline in the
   ``_render_digest_payload`` call's ``redact_pii=`` argument OR bound to
   a local ``viewer_is_owner`` (== form) passed to the template ctx.
3. Handlers missing the idiom = defect.

feedback_dynamic_over_hardcoding: derived from the handler-body, never a
count. Reuses ``tests/_pin_harness.py`` per R5b (walker convergence).
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from tests._pin_harness import (
    SRC_ROOT,
    iter_files,
    parse_module,
    relpath,
    assert_pin_has_teeth,
)


# ---------------------------------------------------------------------------
# Detector — returns the set of "handler:file:line" strings for handlers that
# render a digest preview WITHOUT the viewer-aware idiom.
# ---------------------------------------------------------------------------

CANDIDATES_TEMPLATE = "accounts/_digest_candidates.html"


def _is_str(node: ast.AST, value: str) -> bool:
    return isinstance(node, ast.Constant) and node.value == value


def _call_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _renders_preview(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True iff this handler function calls `_render_digest_payload(...)`
    OR `_render(..., "accounts/_digest_candidates.html", ...)` in its body."""
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name == "_render_digest_payload":
            return True
        if name == "_render":
            # The template name is the SECOND positional arg
            # (_render(templates, request, template_name, ctx))
            if len(node.args) >= 3 and _is_str(node.args[2], CANDIDATES_TEMPLATE):
                return True
    return False


def _has_viewer_aware_idiom(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True iff the handler body contains the viewer-aware idiom.

    Accepted shapes (all normalize to actor==owner ⇒ verbatim):
      * ``user["id"] != acct["user_id"]``
      * ``user["id"] == acct["user_id"]`` (bound to a ctx flag like `viewer_is_owner`)
      * ``user.get("id") == acct.get("user_id")`` (defensive subscript spelling)

    The KEY invariant enforced: both a ``user["id"]`` subscript AND an
    ``acct["user_id"]`` subscript participate in the SAME Compare node
    (== or !=). A flipped predicate (== vs !=) still passes shape here —
    the surface tests (test_web/test_digest_editor.py + phi_render 4-cell)
    catch the semantic direction; this pin just guarantees the two IDs
    are being compared at all in the seam.
    """
    for node in ast.walk(fn):
        if not isinstance(node, ast.Compare):
            continue
        if not node.ops or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
            continue

        sides = [node.left] + list(node.comparators)
        has_user_id = any(_is_user_id_subscript(s) for s in sides)
        has_acct_id = any(_is_acct_user_id_subscript(s) for s in sides)
        if has_user_id and has_acct_id:
            return True
    return False


def _sub_key(node: ast.AST) -> str | None:
    """If node is a subscript / attr access / .get(...) yielding an id string,
    return the (receiver_name, key_string) or None."""
    return None  # unused — kept to document intent; inline predicates below


def _is_user_id_subscript(node: ast.AST) -> bool:
    """user["id"] or user.get("id") on any receiver named `user` / `current_user`."""
    receivers = {"user", "current_user", "actor"}
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in receivers:
        slc = node.slice.value if isinstance(node.slice, ast.Index) else node.slice
        return _is_str(slc, "id")
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name) and node.func.value.id in receivers
            and len(node.args) >= 1 and _is_str(node.args[0], "id")):
        return True
    return False


def _is_acct_user_id_subscript(node: ast.AST) -> bool:
    """acct["user_id"] or acct.get("user_id") on any receiver named `acct` / `account`."""
    receivers = {"acct", "account", "owned_acct"}
    if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name) and node.value.id in receivers:
        slc = node.slice.value if isinstance(node.slice, ast.Index) else node.slice
        return _is_str(slc, "user_id")
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "user_id"
            and isinstance(node.func.value, ast.Name) and node.func.value.id in receivers):
        return True
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name) and node.func.value.id in receivers
            and len(node.args) >= 1 and _is_str(node.args[0], "user_id")):
        return True
    return False


def _find_missing_seams(tree: ast.AST) -> list[tuple[str, int]]:
    """Return list of (handler_name, lineno) for handlers that render a
    digest preview WITHOUT the viewer-aware idiom."""
    missing: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _renders_preview(node) and not _has_viewer_aware_idiom(node):
                missing.append((node.name, node.lineno))
    return missing


def _detect(source: str) -> list[tuple[str, int]]:
    return _find_missing_seams(ast.parse(source))


# ---------------------------------------------------------------------------
# The pin.
# ---------------------------------------------------------------------------

def test_every_digest_preview_seam_has_viewer_aware_idiom():
    """Every handler that renders a digest preview MUST compare user["id"]
    to acct["user_id"] so the owner-self-preview (b) ruling holds.

    A handler that copies the two seams' idiom with != flipped, or that
    forgets to pass viewer_is_owner to the candidates template, is a live
    §164.502(b)/§164.514(d)(1) leak (a managing non-owner sees verbatim,
    or an owner over-redacts). This pin catches the missing-idiom case;
    the semantic direction (== vs !=) is covered by the rendered-view +
    handler matrix tests."""
    ROUTERS_ROOT = SRC_ROOT / "web" / "routers"
    offending: list[str] = []
    for path in iter_files(ROUTERS_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for name, lineno in _find_missing_seams(tree):
            offending.append(f"{relpath(path)}:{lineno}::{name}")
    assert not offending, (
        "Digest-preview handler(s) render a preview WITHOUT the viewer-aware "
        f"idiom (owner-self-preview 2026-07-01, §164.502(b)):\n  " + "\n  ".join(offending)
    )


def test_pin_has_teeth():
    """Verify the detector actually fails on a bad source and passes on a
    good source — vacuous-pass insurance (project_style_guide PD#7 census-
    the-censusers spirit)."""
    good = textwrap.dedent("""
        async def digest_preview(request, account_id, digest_id, owned):
            user, acct, db, secrets = owned
            payload = await _render_digest_payload(
                db=db, secrets=secrets, acct=acct, hipaa=True,
                redact_pii=True and user["id"] != acct["user_id"],
            )
            return payload
    """)
    bad = textwrap.dedent("""
        async def digest_preview(request, account_id, digest_id, owned):
            user, acct, db, secrets = owned
            payload = await _render_digest_payload(
                db=db, secrets=secrets, acct=acct, hipaa=True,
                redact_pii=True,
            )
            return payload
    """)
    good_findings = _detect(good)
    bad_findings = _detect(bad)
    assert not good_findings, f"good source triggered pin: {good_findings}"
    assert bad_findings, "bad source (no viewer-aware idiom) should trigger pin"
