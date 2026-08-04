"""UI admin-gate SSOT pin (divergence census 2026-06-09 class #3).

The tuple-style UI admin gate — ``user = get_current_user(request); if None →
(None, redirect); if role != admin → (None, Forbidden); else (user, None)`` —
was copy-pasted byte-identically into 8 routers (auth_keys, backup, integrations,
tls_csr, ai_backends_crud, embedding_install, retry_queue, and
``_shared._require_admin_user``). Eight independent admin gates = eight places a
future edit could silently relax the privilege check (R16/R19). They now all
delegate to one SSOT ``web/dependencies.require_admin_ui``.

Allowed exception: ``web/routers/api.py`` keeps its OWN exception-style
``_require_admin`` (``-> dict``, raises ``HTTPException(403)``, uses the API
auth helper, never a ``/login`` redirect) — a deliberately-distinct API contract,
NOT a UI-tuple duplicate. It is allow-listed by repo-relative path (R38: never
basename).

Count-agnostic: assert no ``_require_admin`` / ``_require_admin_user`` FunctionDef
exists under ``web/routers/**`` outside the allow-list (never ``len()==N``).
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath, parse_source

ROUTERS_SUBDIR = "web/routers"
DEPS = SRC_ROOT / "web" / "dependencies.py"

_GATE_NAMES = {"_require_admin", "_require_admin_user"}
# Repo-relative (NOT basename) — only this API-contract gate may define its own.
_ALLOWED_RELPATHS = {"web/routers/api.py"}


def _gate_defs(tree: ast.AST) -> list[str]:
    return [
        f"{n.name}:{n.lineno}" for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        and n.name in _GATE_NAMES
    ]


def test_no_hand_rolled_admin_gate_def_in_routers():
    offenders = []
    for p in iter_src_files(ROUTERS_SUBDIR):
        rel = relpath(p)
        if rel in _ALLOWED_RELPATHS:
            continue
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        defs = _gate_defs(tree)
        if defs:
            offenders.append(f"{rel}: {defs}")
    assert not offenders, (
        "A hand-rolled UI admin gate was defined under web/routers/ outside the "
        f"allow-list {_ALLOWED_RELPATHS}: {offenders}. Import "
        "web.dependencies.require_admin_ui (the tuple-style SSOT) instead — "
        "eight copies of the privilege check is eight ways to silently relax it."
    )


def test_ssot_exists():
    tree = parse_module(DEPS); assert tree is not None  # N-350 R31 harness SSOT
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "require_admin_ui" in names, "the require_admin_ui SSOT vanished from dependencies.py"


def test_allowlisted_api_gate_still_distinct():
    """Guard the allow-list: api.py's gate must remain the exception-style one
    (raises, no /login redirect) — if it became a UI-tuple copy it should be
    collapsed, not allow-listed."""
    src = (SRC_ROOT / "web" / "routers" / "api.py").read_text(encoding="utf-8")
    assert "def _require_admin" in src
    assert "HTTPException" in src  # raises rather than returning a tuple


def test_pin_has_teeth(tmp_path):
    bad = tmp_path / "m.py"
    bad.write_text(
        "def _require_admin(request):\n"
        "    user = get_current_user(request)\n"
        "    if user.get('role') != 'admin':\n"
        "        return None, 'forbidden'\n"
        "    return user, None\n",
        encoding="utf-8",
    )
    tree = parse_module(bad); assert tree is not None
    assert _gate_defs(tree)


def test_pin_alias_import_is_not_flagged(tmp_path):
    """An alias-import (the fix shape) is NOT a def → not flagged."""
    ok = tmp_path / "p.py"
    ok.write_text(
        "from email_triage.web.dependencies import require_admin_ui as _require_admin\n",
        encoding="utf-8",
    )
    tree = parse_module(ok); assert tree is not None
    assert not _gate_defs(tree)


# ---------------------------------------------------------------------------
# Inline admin-gate coverage (divergence census run12 — the 16-site blind spot)
#
# The def-pin above only catches a hand-rolled ``_require_admin`` *FunctionDef*.
# It was structurally blind to the far more common shape: an admin gate written
# INLINE in a handler body —
#     if user["role"] != "admin":
#         return HTMLResponse("Forbidden", status_code=403)
# — which has no def to match. Census run12 found 16 such copies (admin.py ×9,
# users.py ×6, categories.py ×1), each independently re-deciding the privilege
# check and bypassing the SSOT uncaught. They now route through
# ``web/dependencies.admin_gate_response`` — the admin-ROLE predicate that
# ``require_admin_ui`` also funnels through (one predicate; PD#5/PD#6). This pin
# makes the inline shape a defect: in the UI routers an inline
# ``user role vs "admin"`` compare that produces a 403 must go through the
# predicate, not hand-roll the response.
#
# Scope = ``web/routers/ui/`` only (the HTMLResponse / 303-redirect UI contract).
# The JSON / HTTPException API-style gates (``api.py`` / ``health.py`` /
# ``webhook.py``) are a DISTINCT response contract — a separate sub-class with
# its own SSOT — and live OUTSIDE ``routers/ui/``, so they are out of scope here
# by path, no allow-list needed. ``_shared.py``'s banner helpers compare role but
# ``return None`` (optional-content gating, never a 403) → not matched by
# construction. Count-agnostic + interprocedural: a property over every UI-router
# FunctionDef, keyed on the SSOT seam (no inline 403), never ``len()==N``.
# ---------------------------------------------------------------------------

UI_ROUTERS_SUBDIR = "web/routers/ui"


def _is_user_role_expr(node: ast.AST) -> bool:
    """True for ``user["role"]`` or ``user.get("role")`` (the gate's left side)."""
    if (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name)
            and node.value.id == "user"):
        key = node.slice
        return isinstance(key, ast.Constant) and key.value == "role"
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "user"):
        return (bool(node.args) and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "role")
    return False


def _is_admin_role_compare(node: ast.AST) -> bool:
    """A compare of the user's role against the ``"admin"`` literal — EITHER an
    ``==``/``!=`` against the bare ``"admin"`` constant, OR an ``in``/``not in``
    against a SINGLE-element ``("admin",)`` collection (the equivalent admin-only
    shape; db-sme run12 pin-hardening — the most plausible drift-reintroduction).

    A MULTI-role collection (``role in ("admin", "power_user")``) is deliberately
    NOT matched: that is a genuinely-different gate (categories.py:191/219
    admin-OR-power_user) which must stay un-converted — the admin-only predicate
    would wrongly 403 a power_user.

    Caveat (db-sme + devils-advocate): this keys on the literal
    ``user["role"]`` / ``user.get("role")`` role expression. An admin-only gate
    written against a RENAMED role local (``user_role != "admin"``) would be
    invisible to it. No such site exists today — every renamed-var site in the UI
    routers is an ownership compound — but flag it if a future admin-only gate is
    written against a renamed role var."""
    if not isinstance(node, ast.Compare) or not node.ops:
        return False
    op = node.ops[0]
    if isinstance(op, (ast.Eq, ast.NotEq)):
        operands = [node.left, *node.comparators]
        return (any(_is_user_role_expr(o) for o in operands)
                and any(isinstance(o, ast.Constant) and o.value == "admin"
                        for o in operands))
    if isinstance(op, (ast.In, ast.NotIn)) and node.comparators:
        right = node.comparators[0]
        if (_is_user_role_expr(node.left)
                and isinstance(right, (ast.Tuple, ast.List, ast.Set))):
            elts = right.elts
            return (len(elts) == 1 and isinstance(elts[0], ast.Constant)
                    and elts[0].value == "admin")
    return False


def _is_user_none_check(node: ast.AST) -> bool:
    """``user is None`` / ``user is not None`` (the anon half of the gate test)."""
    return (isinstance(node, ast.Compare) and node.ops
            and isinstance(node.ops[0], (ast.Is, ast.IsNot))
            and isinstance(node.left, ast.Name) and node.left.id == "user"
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value is None)


def _is_pure_admin_gate_test(test: ast.AST) -> bool:
    """The ``if`` test is a PURE admin/identity gate — a role-vs-``"admin"``
    compare, alone or combined ONLY with a ``user is None`` check, and nothing
    else. This is the precise tell that separates the admin-only gate (the 16
    sites + ``if user is None or user['role'] != 'admin'``) from the DIFFERENT
    ownership-with-admin-override class — ``is_admin = user['role'] == 'admin'``
    captured into a variable, then ``if not owner and not is_admin: 403`` — whose
    test references an ownership/`is_admin` local, NOT ``user`` directly. The
    latter belongs to the ``web/account_scope.py`` manageable-set SSOT (census
    run12 #1); forcing it through the admin-only predicate would 403 a non-admin
    OWNER. So it must NOT be flagged here."""
    if _is_admin_role_compare(test):
        return True
    if isinstance(test, ast.BoolOp):
        parts = test.values
        if not any(_is_admin_role_compare(p) for p in parts):
            return False
        return all(_is_admin_role_compare(p) or _is_user_none_check(p) for p in parts)
    return False


def _if_body_produces_403(if_node: ast.If) -> bool:
    """A 403 status or ``"Forbidden"`` literal in the ``if`` body/orelse (NOT the
    test) — i.e. the role gate's branch directly hand-rolls the 403."""
    for child in (*if_node.body, *if_node.orelse):
        for n in ast.walk(child):
            if isinstance(n, ast.Constant) and (n.value == 403 or n.value == "Forbidden"):
                return True
    return False


def _inline_admin_gate_fns(tree: ast.AST) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for node in ast.walk(fn):
            if (isinstance(node, ast.If) and _is_pure_admin_gate_test(node.test)
                    and _if_body_produces_403(node)):
                key = f"{fn.name}:{node.lineno}"
                if key not in seen:
                    seen.add(key)
                    out.append(key)
    return out


def test_no_inline_admin_403_gate_in_ui_routers():
    offenders = []
    for p in iter_src_files(UI_ROUTERS_SUBDIR):
        tree = parse_module(p)
        if tree is None:  # pragma: no cover
            continue
        gates = _inline_admin_gate_fns(tree)
        if gates:
            offenders.append(f"{relpath(p)}: {gates}")
    assert not offenders, (
        "Inline admin gate(s) found in web/routers/ui/ — an inline "
        '`user["role"] != "admin"` check that returns a 403 instead of routing '
        f"through the SSOT: {offenders}. Replace with `_admin_err = "
        "admin_gate_response(user); if _admin_err is not None: return _admin_err` "
        "(the predicate require_admin_ui also funnels through). Inline copies are "
        "exactly the 16-site bypass census run12 caught past the def-only pin."
    )


def test_inline_admin_gate_pin_has_teeth():
    bad = (
        "async def h(request, user):\n"
        "    if user['role'] != 'admin':\n"
        "        return HTMLResponse('Forbidden', status_code=403)\n"
        "    return ok()\n"
    )
    good = (
        "async def h(request, user):\n"
        "    _admin_err = admin_gate_response(user)\n"
        "    if _admin_err is not None:\n"
        "        return _admin_err\n"
        "    return ok()\n"
    )
    assert _inline_admin_gate_fns(ast.parse(bad)), (
        "pin failed to catch an inline admin gate"
    )
    assert not _inline_admin_gate_fns(ast.parse(good)), (
        "pin false-flags the SSOT-routed shape"
    )
    # The anon-OR-non-admin shape (users.py) is still a pure admin gate → caught.
    anon_or = (
        "async def h(request, user):\n"
        "    if user is None or user['role'] != 'admin':\n"
        "        return HTMLResponse('Forbidden', status_code=403)\n"
        "    return ok()\n"
    )
    assert _inline_admin_gate_fns(ast.parse(anon_or)), (
        "pin missed the `user is None or role != admin` admin-gate shape"
    )
    # db-sme hardening: the `role not in ("admin",)` 1-element shape is the same
    # admin-only gate → caught.
    notin_one = (
        "async def h(request, user):\n"
        "    if user['role'] not in ('admin',):\n"
        "        return HTMLResponse('Forbidden', status_code=403)\n"
        "    return ok()\n"
    )
    assert _inline_admin_gate_fns(ast.parse(notin_one)), (
        "pin missed the `role not in ('admin',)` admin-only shape (db-sme hardening)"
    )
    # ...but the MULTI-role `not in ("admin", "power_user")` is a DIFFERENT gate
    # (admin-OR-power_user, categories.py:191/219) → must NOT be caught (the
    # admin-only predicate would wrongly 403 a power_user).
    notin_multi = (
        "async def h(request, user):\n"
        "    if user['role'] not in ('admin', 'power_user'):\n"
        "        return HTMLResponse('Forbidden', status_code=403)\n"
        "    return ok()\n"
    )
    assert not _inline_admin_gate_fns(ast.parse(notin_multi)), (
        "pin over-matched the admin-OR-power_user multi-role gate (must stay "
        "un-converted — admin_gate_response would 403 a power_user)"
    )


def test_inline_admin_gate_pin_excludes_ownership_override():
    """The ``is_admin = user['role'] == 'admin'`` capture + ``if not owner and
    not is_admin: 403`` ownership-with-admin-override shape is a DIFFERENT authz
    class (the ``web/account_scope.py`` manageable-set SSOT, census run12 #1), NOT
    the admin-only gate. The pin must NOT flag it — routing a non-admin OWNER
    through the admin-only predicate would wrongly 403 them. This locks the
    narrowing in (it is the exact false-positive the first cut produced on 8
    sites: accounts/oauth/profile/routes/triage_classify)."""
    src = (
        "async def h(request, user, account):\n"
        "    is_admin = user['role'] == 'admin'\n"
        "    if account['owner_id'] != user['id'] and not is_admin:\n"
        "        return HTMLResponse('Forbidden', status_code=403)\n"
        "    return ok()\n"
    )
    assert not _inline_admin_gate_fns(parse_source(src)), (
        "pin over-matched the ownership-with-admin-override shape (account-scope "
        "class) — it must stay scoped to the admin-only inline gate"
    )


def test_admin_gate_predicate_ssot_exists():
    """The predicate the inline sites now funnel through must stay present."""
    tree = parse_module(DEPS); assert tree is not None  # N-350 R31 harness SSOT
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "admin_gate_response" in names, (
        "admin_gate_response (the admin-role predicate SSOT) vanished from "
        "dependencies.py — the inline UI gates funnel through it"
    )


# ---------------------------------------------------------------------------
# API raise-contract admin gate (divergence census run12 #1, API sub-class)
#
# The API routers gate admin-only with a RAISE contract: ``HTTPException(403)``
# (FastAPI renders JSON ``{"detail": …}``), via ``api.py::_require_admin``
# (dispatched ``db_call(_require_admin)`` 8×) which now routes its role-check
# through the SSOT ``web/dependencies.assert_admin`` (the raise-twin of
# ``admin_gate_response``). Two stragglers carried divergent inline copies — the
# ``/metrics`` endpoint returned a one-off ``PlainTextResponse("forbidden",403)``
# (its own comment says it wants "the same gate /logs uses"), and
# ``webhook.py`` inlined ``if role != "admin": raise HTTPException`` AFTER its
# ``_require_user`` rate-limit. Both now route through ``assert_admin`` (webhook
# keeps ``_require_user`` so the per-key rate-limit is preserved). This pin makes
# the inline raise/return-403 admin gate a defect in the API raise-contract
# routers.
#
# Scope = ``web/routers/api.py`` + ``web/routers/agent_api.py`` (the raise
# contract). REUSES the same `_is_pure_admin_gate_test` + `_if_body_produces_403`
# helpers (a 403 is a 403 whether raised or returned). The compound ownership/
# conditional gates (api.py:595 owner-or-admin, api.py:744 cross_user-and-admin)
# are BoolOps with non-role operands → excluded by `_is_pure_admin_gate_test`,
# exactly as the UI ownership-override class is.
#
# ``health.py``'s ``/health/detail`` gate IS shape-matched by this detector —
# running ``_inline_admin_gate_fns`` on health.py returns ``['health_detail']``
# (an ``ast.If`` with a pure admin test + a 403 body). It is excluded purely BY
# PATH-SCOPE (health.py is deliberately NOT in ``_API_RAISE_ROUTERS``), NOT by any
# structural property of the gate — stating otherwise would be the backwards
# reasoning the devils-advocate flagged. That scoping choice is justified, not a
# dodge: the gate is a genuine single-site contract (anon →
# ``RedirectResponse("/login")``, non-admin → ``JSONResponse({"error": "admin
# role required"}, 403)`` — ``git grep "admin role required"`` is exactly ONE
# hit), so PD#5 (collapse DUPLICATED predicates) has nothing to converge it with;
# a 3rd 1-caller JSON-gate SSOT would be over-engineering. Tracked in N-116 as the
# one inline role-gate intentionally left as a documented unique contract. If a
# SECOND redirect+JSON-403 admin gate is ever written, add a JSON-gate SSOT +
# fold both in (and add health.py here).
# ---------------------------------------------------------------------------

_API_RAISE_ROUTERS = ("web/routers/api.py", "web/routers/agent_api.py")


def test_no_inline_admin_403_gate_in_api_raise_routers():
    offenders = []
    for rel in _API_RAISE_ROUTERS:
        tree = parse_module(SRC_ROOT / rel)
        if tree is None:  # pragma: no cover
            continue
        gates = _inline_admin_gate_fns(tree)
        if gates:
            offenders.append(f"{rel}: {gates}")
    assert not offenders, (
        "Inline admin gate(s) in the API raise-contract routers — an inline "
        '`user["role"] != "admin"` that raises/returns a 403 instead of routing '
        f"through the SSOT: {offenders}. Use `assert_admin(user)` (the raise-twin "
        "of admin_gate_response) after auth, or `_require_admin` for the combined "
        "auth+admin gate. Census run12 #1 API sub-class."
    )


def test_assert_admin_ssot_exists():
    """The API raise-contract role SSOT must stay present."""
    tree = parse_module(DEPS); assert tree is not None  # N-350 R31 harness SSOT
    names = {
        n.name for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert "assert_admin" in names, (
        "assert_admin (the API raise-contract admin-role SSOT) vanished from "
        "dependencies.py — api.py/_require_admin + webhook route through it"
    )
