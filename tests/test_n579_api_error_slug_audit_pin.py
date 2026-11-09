"""Punch 579 — an error response's fixed slug reaches its ``access_log`` row,
and nothing but a fixed slug can.

Main ``1a007bcd`` and before: ``AccessAuditMiddleware`` wrote ``outcome`` from
the status alone (400 -> ``error``) and no ``detail``, so a refused
cross-account watch bind (400 ``account_id_must_match_path``) looked like any
other 400, and §164.308(a)(1)(ii)(D) review could not find attempted
cross-account binds (hipaa-sme F5 Q3). The fix: the app's HTTPException
handler stashes the slug (``error_surface.stash_error_slug``), and the
middleware writes ``{"error": <slug>}`` into ``detail`` through the
``record_access_event`` emitter. ``outcome`` is unchanged. The runtime half is
``tests/test_web/test_f5_watch_scope.py::TestErrorSlugInAccessLog``.

ARMS (each a property over every parseable file under ``src/email_triage``,
``walk_src``; count-agnostic; each with teeth):

1. **The closed set is the derived set.** ``error_surface.AUDITED_ERROR_SLUGS``
   EQUALS the set of slug-shaped string literals an HTTPException is raised
   with: the first argument (or ``exc=`` / ``detail=``) of ``raise_api_error``
   and ``HTTPException``, and of ``_WatchWriteRefused``, whose ``.slug`` the
   agent API re-raises through ``raise_api_error``. A new slug left out of the
   set is never recorded; an entry no raise uses is stale. Known members are
   checked so a green run is not a run over nothing.
2. **Every member is a slug.** Lowercase snake case, so no free text and no
   request data can be a member.
3. **The write carries it.** Every ``_record_access_event`` reference in
   ``web/access_audit.py`` sits in a call that passes ``detail=``, and the
   HTTPException handler in ``web/app.py`` calls ``stash_error_slug``.

WHAT A GREEN RUN DOES NOT PROVE (each fails toward recording LESS, never
toward recording request data, because the runtime filter admits only set
members):

* A slug reaching ``raise_api_error`` through a variable other than
  ``_WatchWriteRefused.slug`` is not followed, so it can be missing from the
  set (unrecorded).
* ``api_error_response`` RETURNS a JSONResponse and never raises, so its slugs
  (WebAuthn, integrations) never pass the handler and are out of scope.
* Arm 3 checks that ``detail=`` is passed, not what it holds; the runtime
  tests carry that.
"""

from __future__ import annotations

import ast
import re

from _pin_harness import (
    SRC_ROOT, assert_pin_has_teeth, parse_module, parse_source, walk_src,
)

_SLUG = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_RAISERS = frozenset({"raise_api_error", "HTTPException", "_WatchWriteRefused"})
_KNOWN = frozenset({
    "account_id_must_match_path", "notify_email_not_settable",
    "not_watch_creator", "watch_unattributed", "watch_creator_out_of_scope",
    "invalid_json", "rate_limited",
})


def _name_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def raised_slugs(tree: ast.AST) -> set[str]:
    """Slug-shaped literals an HTTPException is raised with in ``tree``."""
    out: set[str] = set()
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and _name_of(n.func) in _RAISERS):
            continue
        arg = n.args[0] if n.args else next(
            (k.value for k in n.keywords if k.arg in ("exc", "detail")), None)
        if (isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                and _SLUG.match(arg.value)):
            out.add(arg.value)
    return out


def emits_without_detail(tree: ast.AST) -> list[int]:
    """Lines where ``_record_access_event`` is called (directly, or as the
    first argument of a ``db_call``) without a ``detail=`` keyword."""
    out = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        direct = _name_of(n.func) == "_record_access_event"
        hop = bool(n.args) and _name_of(n.args[0]) == "_record_access_event"
        if (direct or hop) and not any(k.arg == "detail" for k in n.keywords):
            out.append(n.lineno)
    return out


def _derived() -> set[str]:
    found: set[str] = set()
    for _p, _rel, tree in walk_src():
        found |= raised_slugs(tree)
    return found


def test_closed_set_equals_every_raised_slug():
    from email_triage.web.error_surface import AUDITED_ERROR_SLUGS
    derived = _derived()
    assert _KNOWN <= derived, f"slug scan found {sorted(derived)}; missing {sorted(_KNOWN - derived)}"
    missing = derived - AUDITED_ERROR_SLUGS
    stale = AUDITED_ERROR_SLUGS - derived
    assert not missing, (
        f"error slug(s) raised but not in AUDITED_ERROR_SLUGS: {sorted(missing)}. "
        "Add them, or an access_log row for that error says only its status.")
    assert not stale, f"AUDITED_ERROR_SLUGS entries no raise uses: {sorted(stale)}"


def test_every_member_is_a_slug():
    from email_triage.web.error_surface import AUDITED_ERROR_SLUGS
    bad = sorted(s for s in AUDITED_ERROR_SLUGS if not _SLUG.match(s))
    assert not bad, f"not a fixed slug (free text could carry request data): {bad}"


def test_the_write_and_the_handler_carry_the_slug():
    audit = parse_module(SRC_ROOT / "web/access_audit.py")
    assert any(_name_of(n) == "_record_access_event" for n in ast.walk(audit)), (
        "access_audit no longer references _record_access_event (a run over nothing)")
    bad = emits_without_detail(audit)
    assert not bad, f"access_log emit(s) without detail= at web/access_audit.py:{bad}"
    app = parse_module(SRC_ROOT / "web/app.py")
    handler = next(
        n for n in ast.walk(app)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "_auth_error_handler")
    assert any(isinstance(n, ast.Call) and _name_of(n.func) == "stash_error_slug"
               for n in ast.walk(handler)), (
        "the HTTPException handler no longer stashes the error slug (punch 579)")


def test_arms_have_teeth():
    assert_pin_has_teeth(
        lambda t: raised_slugs(t) - {"account_not_found"},
        "def f():\n    raise raise_api_error('new_slug_here', status_code=400)\n",
        "def f(e, x):\n"
        "    raise raise_api_error('account_not_found', status_code=404)\n"
        "    raise raise_api_error('watch not found', status_code=404)\n"
        "    raise raise_api_error(f'batch_too_large: {x}', status_code=400)\n"
        "    raise raise_api_error(e, status_code=502)\n",
    )
    assert raised_slugs(parse_source(
        "raise HTTPException(status_code=429, detail='rate_limited')\n"
        "r = _WatchWriteRefused('watch_unattributed', 409, 'm')\n")) == {
        "rate_limited", "watch_unattributed"}
    assert_pin_has_teeth(
        emits_without_detail,
        "async def w():\n    await _db_call(_record_access_event, db, outcome='ok')\n",
        "async def w():\n    await _db_call(_record_access_event, db, detail=d)\n"
        "def v():\n    return _record_access_event(db, detail=None)\n",
    )
