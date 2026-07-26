"""D2 fix pin (2026-07-16) — the owned regulatory-clock ``enabled`` toggle SSOT.

**Why this exists — D2 (2026-07-16 audit):**
The delete-refusal string in
``src/email_triage/db/regulatory_clock.py:544-547`` directs the operator to
"turn it off instead of deleting it, so past records stay intact." Before
D2 landed, NO code path set ``enabled=0`` on an owned regulatory-clock
def — no route, no writer helper, no UI toggle. The user-facing copy
named a mechanism the code didn't deliver (COPY-AS-CONTRACT violation;
sibling class to the  cache-flush regression).

D2 wires the mechanism end-to-end:
  1. ``db/regulatory_clock.py::set_owned_clock_def_enabled`` — the sole
     post-create writer of the ``enabled`` column on owned rows.
  2. ``web/routers/ui/profile.py::profile_regulatory_clocks_set_enabled``
     — the POST route at ``/profile/regulatory-clocks/set-enabled``.
  3. ``web/templates/profile/regulatory_clocks.html`` — the toggle form
     with a "Turn off" / "Turn on" button whose label matches the
     delete-refusal directive verbatim.
  4. ``list_owned_clock_defs(..., include_disabled=False)`` — the default
     filter hides off rows from downstream read-only consumers; the
     editor passes ``True`` so operators can restore them.

This pin locks the SSOT: PD#1 (count-agnostic — a property over every
site in the module) + PD#5 (routing SSOT) + PD#7 (census the censusers).
Reuses ``_pin_harness`` per PD#6 (never fork a second scanner).

**No module-level allow-lists.** The three writer names are hard-coded
inline (a tiny closed set); no ``_ALLOW`` / ``_KNOWN`` / ``_EXEMPT`` /
``_APPROVED`` / ``_WHITELIST`` module-level collection is introduced,
so the VALK vacuous-allow-list-killer pin has nothing new to
register. (If a future writer joins the SSOT, extend
:data:`_ENABLED_WRITER_SSOT_FUNCS` and re-run the pin — the widening
is a conscious diff, not a silent drift.)
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    REPO_ROOT,
    SRC_ROOT,
    assert_pin_has_teeth,
    enclosing_fn,
    module_declares_function,
    parse_module,
)


# The three functions in ``db/regulatory_clock.py`` that are legitimately
# allowed to write to the ``enabled`` column on ``regulatory_clock_def``.
# Function-local set — NOT a module-level allow-list — so VALK stays out
# of scope AND a future addition is a legible one-line diff.
_ENABLED_WRITER_SSOT_FUNCS: frozenset[str] = frozenset({
    "set_owned_clock_def_enabled",     # D2 SSOT (post-create toggle)
    "create_owned_clock_def",          # create-time literal 1 for owned rows
    "seed_regulatory_clock_catalog",   # create-time literal 1 for base rows
})

# The module the pin scopes to.
_TARGET_RELPATH = "db/regulatory_clock.py"
_TARGET_PATH = SRC_ROOT / _TARGET_RELPATH

# The route path the D2 wiring MUST expose in profile.py AND link from the
# template. String-equality on this literal in BOTH files closes the
# copy-to-mechanism loop.
_SET_ENABLED_ROUTE = "/profile/regulatory-clocks/set-enabled"

# Repo-relpath of the two files that must reference the route.
_ROUTE_SITE_PY = "src/email_triage/web/routers/ui/profile.py"
_ROUTE_SITE_TPL = "src/email_triage/web/templates/profile/regulatory_clocks.html"

# The write-context needle patterns. A string literal is a "write" if it
# names the ``enabled`` column in one of two shapes:
#   (a) exact ``"enabled"`` — the column-name-in-cols-tuple shape (this is
#       how the two create-time INSERTs reference the column).
#   (b) SQL substring ``SET enabled`` (case-insensitive, whitespace-
#       tolerant) — the UPDATE shape (this is how the toggle writer
#       references the column).
# Docstrings and comments mention "enabled" only in prose (never equal to
# the bare word, never as ``SET enabled``) so they fall through cleanly.
_SET_ENABLED_RE = re.compile(r"\bset\s+enabled\b", re.IGNORECASE)


def _is_enabled_write_string(s: str) -> bool:
    """True if ``s`` is a string literal that references the ``enabled``
    column in a WRITE context (column-name element OR ``SET enabled = ?``
    UPDATE). Kept in one place (PD#6) — the sole-SSOT test and the
    teeth-probe both consume it."""
    if s == "enabled":
        return True
    if _SET_ENABLED_RE.search(s):
        return True
    return False


def _collect_enabled_write_offenders(tree: ast.AST) -> list[tuple[str, int]]:
    """Return ``(enclosing_fn_name, lineno)`` for every string-constant in
    ``tree`` that satisfies :func:`_is_enabled_write_string` AND sits
    inside an enclosing FunctionDef that is NOT in
    :data:`_ENABLED_WRITER_SSOT_FUNCS`. Empty = pin GREEN."""
    offenders: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if not _is_enabled_write_string(node.value):
            continue
        fn_name = enclosing_fn(node)
        if fn_name in _ENABLED_WRITER_SSOT_FUNCS:
            continue
        offenders.append((fn_name, node.lineno))
    return offenders


def test_enabled_writer_is_sole_ssot():
    """PD#1 (count-agnostic) + PD#5 (routing SSOT): the ``enabled``
    column on ``regulatory_clock_def`` may only be written by the three
    allow-listed functions in :data:`_ENABLED_WRITER_SSOT_FUNCS`. A
    twin writer elsewhere forks the enable-state control surface — a
    route or helper that flips ``enabled`` outside this SSOT skips both
    the owner-guard AND the governance audit the profile route wraps
    around every call."""
    tree = parse_module(_TARGET_PATH)
    assert tree is not None, f"could not parse {_TARGET_PATH}"
    offenders = _collect_enabled_write_offenders(tree)
    assert not offenders, (
        f"Non-SSOT write to the ``enabled`` column detected in "
        f"{_TARGET_RELPATH}. Only these functions may write it: "
        f"{sorted(_ENABLED_WRITER_SSOT_FUNCS)}. Offenders "
        f"(enclosing_fn, lineno):\n  "
        + "\n  ".join(f"{fn}:{ln}" for fn, ln in offenders)
    )


def test_list_owned_clock_defs_default_filters_disabled():
    """PD#8 (fail-CLOSED default): ``list_owned_clock_defs`` defaults to
    ``include_disabled=False``, and its default-path SQL literal must
    filter ``enabled = 1`` — else a disabled template would leak into
    downstream read-only consumers (the compliance display, the
    route-action picker). The editor overrides to True (documented in
    the function docstring) so operators can restore off rows."""
    tree = parse_module(_TARGET_PATH)
    assert tree is not None, f"could not parse {_TARGET_PATH}"
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "list_owned_clock_defs"):
            fn_node = node
            break
    assert fn_node is not None, (
        f"list_owned_clock_defs missing from {_TARGET_RELPATH} — "
        "D2 fix regressed."
    )

    # Assert kwarg ``include_disabled`` with default False.
    kw_defaults = list(zip(fn_node.args.kwonlyargs, fn_node.args.kw_defaults))
    match = next(
        ((arg, default) for arg, default in kw_defaults
         if arg.arg == "include_disabled"),
        None,
    )
    assert match is not None, (
        "list_owned_clock_defs must declare ``include_disabled`` as a "
        "keyword-only arg — D2 fix regressed."
    )
    _arg, default = match
    assert (isinstance(default, ast.Constant) and default.value is False), (
        "list_owned_clock_defs ``include_disabled`` default must be False "
        "(fail-CLOSED); got "
        f"{ast.dump(default) if default is not None else 'None'}."
    )

    # Assert the default-path emits SQL containing ``enabled = 1``. We
    # find any string-constant descendant of the function whose value
    # contains ``enabled = 1`` (whitespace-tolerant).
    filter_re = re.compile(r"\benabled\s*=\s*1\b", re.IGNORECASE)
    found_filter = False
    for sub in ast.walk(fn_node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if filter_re.search(sub.value):
                found_filter = True
                break
    assert found_filter, (
        "list_owned_clock_defs default path must emit SQL containing "
        "``enabled = 1`` — the disabled-row filter is missing."
    )


_ROUTE_HANDLER_NAME = "profile_regulatory_clocks_set_enabled"


def test_set_enabled_route_wired_to_ui():
    """PD#17 (test the rendered VIEW) applied at the COPY layer:
    ``/profile/regulatory-clocks/set-enabled`` MUST appear as a string
    literal in the profile ROUTER (that is the @router decorator; no
    substitute), AND the TEMPLATE MUST reach the route via EITHER the
    literal path OR a ``url_for('profile_regulatory_clocks_set_enabled')``
    equivalent (FastAPI/Starlette route-reversal). If the button posts
    to a route the router doesn't serve, the user hits a 404 and the D2
    recurrence class is back.

    DA panel-1 MF-4 fold (2026-07-16): the template match was relaxed to
    accept ``url_for``-style route reversal so a legitimate template
    refactor (using the route function name instead of a hard-coded
    URL) doesn't fire a misleading `wiring broken` message. The router
    literal remains required — the decorator IS the route.
    """
    router_path = REPO_ROOT / _ROUTE_SITE_PY
    assert router_path.is_file(), f"D2 wiring site missing: {router_path}"
    router_text = router_path.read_text(encoding="utf-8")
    assert _SET_ENABLED_ROUTE in router_text, (
        f"{_ROUTE_SITE_PY} does not reference {_SET_ENABLED_ROUTE!r} — the "
        "D2 route decorator is missing. This IS the route; a url_for-style "
        "reference is not a substitute here."
    )
    tpl_path = REPO_ROOT / _ROUTE_SITE_TPL
    assert tpl_path.is_file(), f"D2 wiring site missing: {tpl_path}"
    tpl_text = tpl_path.read_text(encoding="utf-8")
    tpl_has_literal = _SET_ENABLED_ROUTE in tpl_text
    tpl_has_url_for = _ROUTE_HANDLER_NAME in tpl_text
    assert tpl_has_literal or tpl_has_url_for, (
        f"{_ROUTE_SITE_TPL} does not reference {_SET_ENABLED_ROUTE!r} "
        f"(literal) NOR the handler function name {_ROUTE_HANDLER_NAME!r} "
        "(via url_for or equivalent) — the D2 UI wiring is broken (button "
        "posts to a route the router doesn't serve)."
    )


def test_pin_has_teeth():
    """PD#7 (census the censusers) — the sole-SSOT detector fires on a
    planted twin writer OUTSIDE the allow-listed functions and stays
    quiet on a well-formed SSOT write INSIDE them. A pin that silently
    matches nothing is worse than no pin."""
    bad = (
        "def rogue_toggle(conn, def_id):\n"
        "    conn.execute('UPDATE regulatory_clock_def SET enabled = 0 "
        "WHERE id = ?', (def_id,))\n"
    )
    good = (
        "def set_owned_clock_def_enabled(conn, *, def_id, account_id, "
        "actor_user_id, enabled):\n"
        "    conn.execute('UPDATE regulatory_clock_def SET enabled = ? "
        "WHERE id = ? AND config_owner_account_id = ?', "
        "(int(bool(enabled)), int(def_id), int(account_id)))\n"
    )

    def _detector(tree: ast.AST) -> bool:
        return bool(_collect_enabled_write_offenders(tree))

    assert_pin_has_teeth(_detector, bad, good)


def test_target_module_declares_set_enabled_writer():
    """Complementary structural probe (PD#7 rot-guard): the SSOT
    module MUST declare :func:`set_owned_clock_def_enabled`. A file
    rename / deletion that removed the writer would otherwise leave
    the sole-SSOT test green-and-vacuous (the allow-list would still
    contain the name but no writes would exist to check)."""
    tree = parse_module(_TARGET_PATH)
    assert tree is not None
    assert module_declares_function(tree, "set_owned_clock_def_enabled"), (
        f"{_TARGET_RELPATH} must declare set_owned_clock_def_enabled — "
        "D2 SSOT regressed."
    )
