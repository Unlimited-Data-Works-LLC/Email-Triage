"""Classification-list RULE access SSOT — unit + count-agnostic pin (N-60).

Loop-5 divergence census surfaced a horizontal privilege over-grant: the
list-RULE gates (add/edit/delete/read a rule) bypassed on
``role in ("admin", "power_user")`` with NO ``is_global`` check, so a
``power_user`` could touch classification rules on ANY other user's PERSONAL
list (README scopes power_user to own-personal + GLOBAL only). Classification
rules drive PHI routing, so this is a §164.308(a)(4)/§164.312(a)(1) access bug.

The fix routes all 6 rule gates through the SSOT
``email_triage.web._list_authz.is_list_writable_by``. This file:
  1. unit-tests the SSOT decision table, and
  2. ships the count-agnostic pin: no inline ``owner_id``-vs-user AND
     power_user-role gate may live OUTSIDE the SSOT (the buggy shape can't
     re-appear in a new rule handler).
"""

from __future__ import annotations

import ast

from email_triage.web._list_authz import (
    is_list_writable_by,
    may_manage_global_lists,
)

from _pin_harness import SRC_ROOT, iter_src_files, parse_module, relpath, walk_src  # N-350 R31

_SSOT_REL = "web/_list_authz.py"


# ---------------------------------------------------------------------------
# 1. SSOT decision table
# ---------------------------------------------------------------------------

def _list(owner_id: int, is_global: bool) -> dict:
    return {"owner_id": owner_id, "is_global": 1 if is_global else 0}


def test_owner_always_writable():
    assert is_list_writable_by(_list(7, False), user_id=7, role="user") is True
    assert is_list_writable_by(_list(7, True), user_id=7, role="user") is True


def test_admin_always_writable():
    assert is_list_writable_by(_list(7, False), user_id=99, role="admin") is True


def test_power_user_only_on_global():
    # The fix: power_user passes on a GLOBAL list ...
    assert is_list_writable_by(_list(7, True), user_id=99, role="power_user") is True
    # ... but NOT on another user's PERSONAL list (the N-60 hole).
    assert is_list_writable_by(_list(7, False), user_id=99, role="power_user") is False


def test_plain_user_cannot_touch_another_users_list():
    assert is_list_writable_by(_list(7, False), user_id=99, role="user") is False
    assert is_list_writable_by(_list(7, True), user_id=99, role="user") is False


def test_fail_closed_on_unknown_role_or_missing_is_global():
    assert is_list_writable_by(_list(7, False), user_id=99, role=None) is False
    assert is_list_writable_by(_list(7, False), user_id=99, role="moderator") is False
    # missing is_global for a non-owner power_user → refuse (fail-closed)
    assert is_list_writable_by({"owner_id": 7}, user_id=99, role="power_user") is False
    # missing owner_id → refuse for EVERYONE (fail-closed on malformed input —
    # a real list_row always carries owner_id, so this only guards a bug).
    assert is_list_writable_by({"is_global": 1}, user_id=99, role="admin") is False
    assert is_list_writable_by({"is_global": 1}, user_id=99, role="power_user") is False
    assert is_list_writable_by({}, user_id=99, role="user") is False
    # the owner still matches when owner_id IS present (sanity vs the above).
    assert is_list_writable_by({"owner_id": 99, "is_global": 0}, user_id=99, role="user") is True


def test_fail_closed_on_real_sqlite_row_missing_column():
    """db-sme C1 (N-60): a real ``sqlite3.Row`` raises ``IndexError`` — NOT
    ``KeyError`` — on a missing column. A dict-only fail-closed test masks
    that: the guard must catch IndexError or a malformed Row would 500 instead
    of refusing. Drive the real Row type so the fail-closed contract holds
    against what production actually passes."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE t (is_global INTEGER)")
        conn.execute("INSERT INTO t (is_global) VALUES (1)")
        row = conn.execute("SELECT * FROM t").fetchone()  # Row, NO owner_id col
        assert isinstance(row, sqlite3.Row)
        # owner_id missing on a real Row → fail-closed False for EVERY role,
        # no IndexError escaping to a 500.
        assert is_list_writable_by(row, user_id=1, role="admin") is False
        assert is_list_writable_by(row, user_id=1, role="power_user") is False
        assert is_list_writable_by(row, user_id=1, role="user") is False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# 2. Count-agnostic pin — the inline owner_id+power_user rule-gate shape
#    must not exist outside the SSOT.
# ---------------------------------------------------------------------------

# run17 #2 §3g: the inline-rule-gate pin now walks ALL src via _pin_harness
# walk_src (was a hardcoded 3-module tuple — invisible to the meta-pin union +
# blind to a future list-rule gate in a new module). The per-function
# classification_lists scoping keeps it false-positive-free.
_ROLE_STRINGS = {"admin", "power_user"}
_LIST_TABLE = "classification_lists"
_SSOT_FNS = {"is_list_writable_by", "is_list_readable_by", "is_list_deletable_by"}


def _has_owner_id_subscript(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
                and n.slice.value == "owner_id"):
            return True
    return False


def _has_role_or_admin_check(node: ast.AST) -> bool:
    """A role / admin / is_global authz check inside ``node`` — a Compare against a
    role string ("admin"/"power_user", single OR in a tuple), a reference to the
    ``is_admin`` / ``is_global`` name, or an ``["is_global"]`` subscript. BROADENED
    from the power_user-tuple-only tell (census run15 #2 — the 3 inline gates that
    slipped used single-string ``role != "admin"`` / a bare ``is_admin`` var)."""
    for n in ast.walk(node):
        if isinstance(n, ast.Compare):
            for comp in n.comparators:
                if isinstance(comp, ast.Constant) and comp.value in _ROLE_STRINGS:
                    return True
                if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                    if any(isinstance(e, ast.Constant) and e.value in _ROLE_STRINGS
                           for e in comp.elts):
                        return True
        if isinstance(n, ast.Name) and n.id in {"is_admin", "is_global"}:
            return True
        if (isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Constant)
                and n.slice.value == "is_global"):
            return True
    return False


def _references_list_table(node: ast.AST) -> bool:
    """``node`` mentions the ``classification_lists`` table in a string (a SELECT /
    DELETE / INSERT) — scopes the gate detection to LIST handlers so an
    ``owner_id``+role gate on a DIFFERENT table isn't false-flagged.

    LITERAL-DEPENDENT (db-sme + DA run15 #2): a dynamic / split table name
    (``'classification_' + 'lists'``) or a gate whose SELECT lives in a CROSS-
    function helper (the function has the owner_id+role BoolOp but no table literal)
    is a false-NEGATIVE. ZERO such sites today (all 3 converged gates co-locate a
    literal SELECT; the per-function ``ast.walk`` descends into the db_call
    closures); same literal/co-location dependence as the prior pin — accepted, the
    census backstops."""
    return any(
        isinstance(n, ast.Constant) and isinstance(n.value, str) and _LIST_TABLE in n.value
        for n in ast.walk(node)
    )


def _inline_rule_gate_lines(tree: ast.AST) -> list[int]:
    """Lines of an inline list-authz gate: a ``BoolOp(And)`` combining an
    ``["owner_id"]`` subscript with a role/admin/is_global check, inside a function
    that references ``classification_lists`` (so it IS a list gate) — outside the
    SSOT. Interprocedural: ``ast.walk`` per-FunctionDef descends into the ``db_call``
    closures where two of the three gates lived (census run15 #2)."""
    out: set[int] = set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _references_list_table(fn):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.BoolOp) and isinstance(n.op, ast.And):
                if _has_owner_id_subscript(n) and _has_role_or_admin_check(n):
                    out.add(n.lineno)
    return sorted(out)


def test_no_inline_owner_plus_power_user_rule_gate_outside_ssot():
    """The owner_id-AND-power_user gate shape (the N-60 over-grant) must route
    through ``is_list_writable_by`` — never re-inlined in a rule handler. A new
    rule gate that hand-rolls ``row["owner_id"] != uid and role in
    (admin,power_user)`` (forgetting the is_global scoping) is caught here.

    SCOPE (DA SF-1 — honest layer, not a proof): catches a RECURRENCE of the
    exact prior shape (a ``BoolOp(And)`` with an ``["owner_id"]`` subscript +
    an ``("admin","power_user")`` literal). KNOWN evasions it does NOT catch:
    owner_id via a local var (not a subscript); the role test as
    ``role == "power_user" or role == "admin"`` (no tuple literal); the two
    checks split across nested ``if``s. The SSOT + the behavioural
    ``TestPowerUserRuleAuthz`` live-route tests are the real guarantee; this
    pin is the recurrence-of-the-known-shape layer."""
    offenders = []
    for _path, rel, tree in walk_src():
        if rel == _SSOT_REL:
            continue
        for ln in _inline_rule_gate_lines(tree):
            offenders.append(f"{rel}:{ln}")
    assert offenders == [], (
        "inline owner_id + (admin,power_user) rule gate outside the SSOT "
        f"email_triage.web._list_authz.is_list_writable_by: {offenders}. The "
        "list-create-global / global-flag gates (which legitimately allow "
        "power_user) check is_global WITHOUT an owner_id comparison, so they "
        "don't trip this; only the buggy rule-access shape does. Route it "
        "through is_list_writable_by(list_row, user_id=…, role=…)."
    )


def test_dormant_rule_mutator_has_no_router_caller():
    """DA MF-2 (N-60) — ``db.set_rule_provider_labels`` is a standalone
    ``UPDATE list_rules … WHERE id`` rule-mutator that does NO list-ownership
    check (bare rule_id). It is dormant (no router caller today) and the
    structural pin above is BLIND to it (db.py is not a rule-gate module and it
    has no owner_id+role shape). Tripwire: if a router/handler ever references
    it, this fails — forcing the dev to gate the call on ``is_list_writable_by``
    FIRST (gate at the actuator, PD#9), then add the caller here with a
    justification."""
    offenders = []
    for p in iter_src_files("web/routers"):
        tree = parse_module(p); assert tree is not None  # N-350 R31
        for n in ast.walk(tree):
            if isinstance(n, ast.Name) and n.id == "set_rule_provider_labels":
                offenders.append(f"{relpath(p)}:{n.lineno}")
            elif isinstance(n, ast.Attribute) and n.attr == "set_rule_provider_labels":
                offenders.append(f"{relpath(p)}:{n.lineno}")
    assert offenders == [], (
        "set_rule_provider_labels (an UNAUTHENTICATED list_rules mutator) is "
        f"now referenced from a router/handler: {offenders}. It does NO "
        "ownership check — gate the call on is_list_writable_by(list_row, "
        "user_id=…, role=…) FIRST (N-60 / PD#9 gate-at-the-actuator), then "
        "add the caller to this test's allow-list with a justification."
    )


def test_pin_has_teeth():
    # The N-60 tuple shape — flagged (the function references classification_lists).
    bad_tuple = (
        "def h(db, row, uid, role):\n"
        "    db.execute('SELECT * FROM classification_lists WHERE id=?', (1,))\n"
        "    if row['owner_id'] != uid and role in ('admin', 'power_user'):\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(bad_tuple)) == [3]
    # census run15 #2 — the SINGLE-STRING admin evasion that slipped the old pin.
    bad_single = (
        "def h(db, row, uid, role):\n"
        "    db.execute('DELETE FROM classification_lists WHERE id=?', (1,))\n"
        "    if row['owner_id'] != uid and role != 'admin':\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(bad_single)) == [3]
    # census run15 #2 — the bare is_admin-var evasion (the db_call-closure shape).
    bad_isadmin = (
        "def h(db, row, uid, is_admin):\n"
        "    db.execute('SELECT * FROM classification_lists WHERE id=?', (1,))\n"
        "    if row['owner_id'] != uid and not is_admin:\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(bad_isadmin)) == [3]
    # The create-global shape (role tuple, NO owner_id compare) must NOT trip.
    ok = (
        "def c(db, body, role):\n"
        "    db.execute('INSERT INTO classification_lists (is_global) VALUES (1)')\n"
        "    if body.is_global and role not in ('admin', 'power_user'):\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(ok)) == []
    # An owner_id+role gate on a DIFFERENT table (no classification_lists ref) is
    # NOT flagged — the per-function table scoping prevents false-positives.
    other = (
        "def t(db, row, uid, role):\n"
        "    db.execute('SELECT * FROM topics WHERE id=?', (1,))\n"
        "    if row['owner_id'] != uid and role != 'admin':\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(other)) == []
    # The converged SSOT call is NOT flagged (no inline BoolOp gate).
    good = (
        "def h(db, row, uid, role):\n"
        "    db.execute('DELETE FROM classification_lists WHERE id=?', (1,))\n"
        "    if not is_list_deletable_by(row, user_id=uid, role=role):\n"
        "        return 'forbidden'\n"
    )
    assert _inline_rule_gate_lines(ast.parse(good)) == []


def test_readable_and_deletable_decision_tables():
    """census run15 #2 — the READ twin (is_global = public-read) + the DELETE-LIST
    twin (stricter: owner|admin, NO power_user-global)."""
    from email_triage.web._list_authz import is_list_readable_by, is_list_deletable_by

    def L(o, g):
        return {"owner_id": o, "is_global": 1 if g else 0}

    # READ: owner | admin | ANY global list (public read).
    assert is_list_readable_by(L(7, False), user_id=7, role="user") is True       # owner
    assert is_list_readable_by(L(7, False), user_id=9, role="admin") is True       # admin
    assert is_list_readable_by(L(7, True), user_id=9, role="user") is True         # global -> public
    assert is_list_readable_by(L(7, False), user_id=9, role="user") is False       # other's personal
    assert is_list_readable_by(L(7, False), user_id=9, role="power_user") is False  # no special read
    assert is_list_readable_by({}, user_id=7, role="user") is False                # fail-closed
    # DELETE-LIST: owner | admin ONLY — a power_user may NOT delete a global list.
    assert is_list_deletable_by(L(7, False), user_id=7, role="user") is True       # owner
    assert is_list_deletable_by(L(7, False), user_id=9, role="admin") is True      # admin
    assert is_list_deletable_by(L(7, True), user_id=9, role="power_user") is False  # NOT power_user
    assert is_list_deletable_by(L(7, True), user_id=9, role="user") is False
    assert is_list_deletable_by({}, user_id=7, role="user") is False               # fail-closed


# ---------------------------------------------------------------------------
# 3. may_manage_global_lists SSOT (census run17 #2 D2) + count-agnostic pin
# ---------------------------------------------------------------------------

def test_may_manage_global_lists_decision_table():
    """The create-global ROLE gate: admin|power_user may; everyone else (incl.
    None / unknown) may not. Behaviour-identical to the three inline
    ``role in ("admin","power_user")`` tests it converged."""
    assert may_manage_global_lists("admin") is True
    assert may_manage_global_lists("power_user") is True
    assert may_manage_global_lists("user") is False
    assert may_manage_global_lists(None) is False
    assert may_manage_global_lists("moderator") is False


_GLOBAL_LIST_ROLE_SET = frozenset({"admin", "power_user"})


def _inline_create_global_role_gate_lines(tree: ast.AST) -> list[int]:
    """Lines of an inline create-global role gate — a membership ``Compare``
    (``in`` / ``not in``) whose comparator is a tuple/list/set of string
    Constants == EXACTLY {"admin","power_user"} (the may_manage_global_lists
    decision). A 3-role ``choices=[…,"user"]`` list, or a different role set,
    won't match (exact set-equality, not a subset)."""
    out: set[int] = set()
    for n in ast.walk(tree):
        if not isinstance(n, ast.Compare):
            continue
        if not any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops):
            continue
        for comp in n.comparators:
            if isinstance(comp, (ast.Tuple, ast.List, ast.Set)):
                vals = {
                    e.value for e in comp.elts
                    if isinstance(e, ast.Constant) and isinstance(e.value, str)
                }
                if vals == set(_GLOBAL_LIST_ROLE_SET):
                    out.add(n.lineno)
    return sorted(out)


def test_no_inline_create_global_role_gate_outside_ssot():
    """run17 #2 D2 (PD#5): the create-global role decision
    (``role in ("admin","power_user")``) must route through
    ``email_triage.web._list_authz.may_manage_global_lists`` — never re-inlined.
    Was duplicated across api_create_list / global_rules_page / create_list.
    Count-agnostic over ALL src (walk_src); the SSOT module is exempt."""
    offenders = []
    for _path, rel, tree in walk_src():
        if rel == _SSOT_REL:
            continue
        for ln in _inline_create_global_role_gate_lines(tree):
            offenders.append(f"{rel}:{ln}")
    assert offenders == [], (
        "inline ('admin','power_user') role-membership gate outside the SSOT "
        f"email_triage.web._list_authz.may_manage_global_lists: {offenders}. "
        "Route the create-global decision through "
        "may_manage_global_lists(user['role'])."
    )


def test_create_global_pin_has_teeth():
    # the inline tuple membership -> flagged
    bad = (
        "def h(user, body):\n"
        "    if body.is_global and user['role'] not in ('admin', 'power_user'):\n"
        "        return 'forbidden'\n"
    )
    assert _inline_create_global_role_gate_lines(ast.parse(bad)) == [2]
    # reversed-order tuple -> also flagged (set-equality, order-independent)
    rev = "x = role in ('power_user', 'admin')\n"
    assert _inline_create_global_role_gate_lines(ast.parse(rev)) == [1]
    # the converged SSOT call -> NOT flagged
    good = (
        "def h(user, body):\n"
        "    if body.is_global and not may_manage_global_lists(user['role']):\n"
        "        return 'forbidden'\n"
    )
    assert _inline_create_global_role_gate_lines(ast.parse(good)) == []
    # a 3-role choices list (the cli argparse) -> NOT flagged (exact-set mismatch)
    choices = "p.add_argument('--role', choices=['admin', 'power_user', 'user'])\n"
    assert _inline_create_global_role_gate_lines(ast.parse(choices)) == []
