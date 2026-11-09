"""N-466 structural pin — a system HIPAA flip never uses a self-committing writer.

THE DEFECT (measured 2026-09-12, ``da_boundary_probe.py`` arm B): the canonical
HIPAA off-ramp wrote its ``runtime_settings`` row through the own-commit
``set_setting`` and only THEN emitted its boundary event through the own-commit
``record_hipaa_boundary``. ``_chain_insert`` is fail-closed BY DESIGN on an
HMAC-key gap (Directive 12), so in a rotation window (version set, key absent)
the safeguard-DISABLING settings row committed durably while the boundary event
raised — and ``/admin/security/save`` is in no ``_PHI_ROUTE_PREFIXES``, so
``hipaa_boundary_events`` is the SOLE durable witness for that route. Total
loss of the witness, not partial.

WHAT THIS PINS (count-agnostic, PD#1 — a PROPERTY over every site, never
``len(X)==N``):

1. ``test_no_hipaa_flip_site_calls_a_self_committing_writer`` — for EVERY
   source location that passes ``allow_hipaa_change=True`` (the in-tree SSOT
   token for "this is a system HIPAA flip"; ``test_runtime_settings_hipaa_gate``
   separately pins that the token has exactly one call site and lives in
   ``admin.py``), neither the innermost enclosing function NOR any ancestor
   function up to module scope may call ``set_setting`` or
   ``record_hipaa_boundary``. The ancestor walk is what stops the trivial
   evasion of hoisting the own-commit call out of the nested ``_db_work``
   closure into the handler body, where an innermost-scope-only pin goes blind.
2. ``test_hipaa_flip_site_routes_through_the_atomic_funnel`` — the same scope
   chain must call ``record_system_hipaa_flip``. Pins the ROUTE, not the
   output (R1(a)): asserting only "no own-commit call" is satisfiable by
   deleting the audit write entirely.
3. ``test_every_boundary_chain_insert_is_in_the_txn_sibling`` — the INVERSE
   arm (PD#3/PD#5): every ``_chain_insert(..., "hipaa_boundary_events", ...)``
   in src is inside ``record_hipaa_boundary_txn``, so one function authors
   every row of that table and a new in-txn writer cannot re-fork the shape.
4. ``test_the_funnel_invalidates_the_cache_on_every_exit_edge`` — the
   non-negotiable N-466 precondition, read off the AST: the funnel's
   ``invalidate_setting_cache`` call is in a ``Try.finalbody``, not after the
   commit. On rollback there is no commit, so an after-COMMIT invalidation
   never runs and the conversion REOPENS N-464 through a cached phantom.
5. ``test_the_funnel_does_not_mutate_the_process_flag`` — ``_apply_runtime_settings``
   must not be CALLED BY the funnel (a callee-name check over the funnel's own
   body, not a reachability proof over its module): the live-flag mutation
   belongs AFTER the commit, in the handler.
6. ``test_multi_row_boundary_writers_pin_a_shared_timestamp`` — a regression
   guard on THIS conversion, found during its own review: collapsing two inline
   ``_chain_insert`` copies onto one sibling gave each row its own
   ``now_utc_iso()``, so ``set_account_hipaa``'s ``"cascade"`` row became
   strictly later than the ``"on"`` flip it describes and would have won
   ``latest_hipaa_boundary``. Nothing in the existing suite asserted which row
   is latest after a cascade, so the whole green sweep was blind to it.

SCOPE CAVEAT (R2, honest): the scan is per-file and name-keyed. What it does
NOT cover, enumerated rather than implied:

* A self-committing write smuggled through a *locally defined helper* called
  from the flip scope (``def _w(): set_setting(...)`` then ``_w()``), or a
  cross-module wrapper. (A by-reference ``db_call(set_setting, …)`` IS covered
  since DA-422-1 — see ``_called_names``.)
* ``getattr(wdb, name)(...)`` — a computed attribute. ``wdb.set_setting(...)``
  IS caught, because ``Attribute.attr`` is matched.
* Arm 3 (``_chain_insert`` into the boundary table) matches the table name
  only as a literal ``ast.Constant``: ``_T = "hipaa_boundary_events"`` then
  ``_chain_insert(conn, _T, …)`` evades it (DA-422-4, accepted-with-caveat).
  Bounded by ``test_n260_raw_audit_insert_pin`` still covering raw
  ``INSERT INTO``, and by this file's ``assert seen`` vacuity guard, which
  keeps finding the real site — so arm 3 cannot go silently vacuous.
* The shared-``ts`` arm follows ONE helper hop (DA-422-3); a two-hop chain, a
  cross-module helper, or a by-reference dispatch of the helper still evade it.
  It compares ``ast.unparse`` of the ``ts=`` expressions, so two textually
  different expressions that happen to evaluate equal are reported (false
  ALARM, the safe direction).
* None of it proves the funnel's transaction is correct at RUNTIME; that is
  what ``test_n466_hipaa_flip_route_atomicity.py`` measures through the real
  route, and the settings-cache residual is measured by
  ``test_web/test_n466_settings_cache_rollback_pin.py``.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    enclosing_scope_chain,
    iter_files,
    parse_module,
    parse_source,
    relpath,
)

# The token that MARKS a system-HIPAA-flip source location. Not a curated site
# list (which is `len(X)==N` in disguise): it is the privileged kwarg the
# process-flag gate itself requires, so a NEW flip site must carry it to work
# at all and therefore auto-enrols in this pin.
_FLIP_TOKEN = "allow_hipaa_change"

# The self-committing writers a flip site must not use. Both commit on their
# own, so calling them in sequence is the N-466 defect by construction.
_SELF_COMMITTING = frozenset({"set_setting", "record_hipaa_boundary"})

# The atomic funnel every flip must route through.
_FUNNEL = "record_system_hipaa_flip"

# The ONE txn-aware chain-writer for `hipaa_boundary_events`.
_BOUNDARY_TXN = "record_hipaa_boundary_txn"
_BOUNDARY_TABLE = "hipaa_boundary_events"

_FUNNEL_MODULE = "db/audit.py"


def _called_names(node: ast.AST) -> set[str]:
    """Every callee name reachable under ``node`` — ``f(...)`` by ``Name.id``
    and ``mod.f(...)`` by ``Attribute.attr``, so an aliased-module call is
    caught as well as a bare one.

    DA-422-1 / PD#2 — ALSO collects bare ``ast.Name`` ARGUMENTS of every call,
    because the dominant idiom in this codebase hands the writer to a
    dispatcher BY REFERENCE: ``db_call(set_setting, db, KEY, v)``
    (``web/db_threadpool.db_call(sync_fn, /, *args, **kwargs)``), and
    ``admin.py`` already drives this very handler through ``db_call``. A pin
    keyed on ``Call.func`` alone is blind to the seam Prime Directive 2 names
    verbatim: the write would still happen, the pin would still read green,
    and the register's closure evidence would cite a passing pin — the pin
    defending the bug. Measured green-on-the-defect by devils-advocate before
    this change.

    Widening cost: a bare Name that merely SHARES a writer's name (a local
    variable ``set_setting = ...``) is now reported. Accepted — the names in
    ``_SELF_COMMITTING`` are module-level DB writers, shadowing one is itself
    worth a look, and the failure direction is a false ALARM, not a false
    all-clear.
    """
    out: set[str] = set()
    for n in ast.walk(node):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        if isinstance(f, ast.Name):
            out.add(f.id)
        elif isinstance(f, ast.Attribute):
            out.add(f.attr)
        # By-reference: positional AND keyword args that name a function.
        for a in list(n.args) + [k.value for k in n.keywords]:
            if isinstance(a, ast.Name):
                out.add(a.id)
            elif isinstance(a, ast.Attribute):
                out.add(a.attr)
    return out


def _flip_sites(tree: ast.AST) -> list[int]:
    """Linenos of every Call passing ``allow_hipaa_change=True``."""
    hits: list[int] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        for kw in n.keywords:
            if kw.arg != _FLIP_TOKEN:
                continue
            if isinstance(kw.value, ast.Constant) and kw.value.value is True:
                hits.append(n.lineno)
    return hits


def _names_in_flip_scope_chain(tree: ast.AST, lineno: int) -> set[str]:
    """Union of callee names across every FUNCTION scope containing ``lineno``
    — the innermost one plus each ancestor function. The union is what closes
    the hoist-it-one-level-out evasion (move the own-commit call from the
    nested ``_db_work`` closure into the handler body and an innermost-only
    pin reads green).

    MODULE scope is deliberately EXCLUDED, and that exclusion is the pin's
    precision boundary, not laziness: ``enclosing_scope_chain`` appends the
    module last, and unioning it would make every assertion FILE-global —
    ``admin.py``'s ``/config/save`` handler legitimately calls ``set_setting``
    (guarded by its own N-464 refuse-predicate) and would be reported as a
    HIPAA-flip offender. A flip site is always inside a request handler, so no
    module-level statement can be an enclosing EXECUTABLE scope of one."""
    names: set[str] = set()
    for scope in enclosing_scope_chain(tree, lineno):
        if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names |= _called_names(scope)
    return names


def _self_committing_in_flip_scope(tree: ast.AST) -> list[str]:
    """DETECTOR (shared by the pin and its teeth test): offending
    ``lineno:name`` pairs for self-committing writers in a flip scope chain."""
    out: list[str] = []
    for lineno in _flip_sites(tree):
        for bad in sorted(_SELF_COMMITTING & _names_in_flip_scope_chain(tree, lineno)):
            out.append(f"{lineno}:{bad}")
    return out


def _flip_scope_missing_funnel(tree: ast.AST) -> list[int]:
    """DETECTOR: flip-site linenos whose scope chain never calls the funnel."""
    return [
        lineno for lineno in _flip_sites(tree)
        if _FUNNEL not in _names_in_flip_scope_chain(tree, lineno)
    ]


def _iter_flip_sites_across_src():
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        sites = _flip_sites(tree)
        if sites:
            yield relpath(path), tree, sites


def test_flip_site_net_is_not_vacuous():
    """VACUOUS-PASS GUARD. Every assertion below is quantified over the
    ``allow_hipaa_change=True`` net; if the walker stops finding it, all of
    them pass while pinning nothing."""
    found = [(rel, sites) for rel, _t, sites in _iter_flip_sites_across_src()]
    assert found, (
        f"no source location passes {_FLIP_TOKEN}=True — the flip-site walker "
        "found nothing, so every N-466 assertion in this file is vacuous. "
        "Either the token was renamed (update _FLIP_TOKEN and "
        "tests/test_web/test_runtime_settings_hipaa_gate.py together) or the "
        "walk broke."
    )


def test_no_hipaa_flip_site_calls_a_self_committing_writer():
    """THE INVARIANT. A HIPAA-flip scope must not call ``set_setting`` or
    ``record_hipaa_boundary`` — both commit on their own, which is exactly how
    N-466 left a durable safeguard-disabling row with no witness."""
    offenders: list[str] = []
    for rel, tree, _sites in _iter_flip_sites_across_src():
        for hit in _self_committing_in_flip_scope(tree):
            offenders.append(f"{rel}:{hit}")
    assert not offenders, (
        "N-466: a system HIPAA-flip site (or an enclosing scope of one) calls "
        "a SELF-COMMITTING writer. The settings row and its boundary event "
        "must land or roll back together — route both through "
        f"`{_FUNNEL}`, which uses the `set_setting_txn` / "
        f"`{_BOUNDARY_TXN}` siblings inside one transaction.\n\n"
        + "\n".join(offenders)
    )


def test_hipaa_flip_site_routes_through_the_atomic_funnel():
    """Pins the ROUTE, not the absence: deleting the audit write satisfies the
    test above and is a worse defect."""
    missing: list[str] = []
    for rel, tree, _sites in _iter_flip_sites_across_src():
        for lineno in _flip_scope_missing_funnel(tree):
            missing.append(f"{rel}:{lineno}")
    assert not missing, (
        f"N-466: a system HIPAA-flip site does not route through `{_FUNNEL}`. "
        "The durable write + its boundary event must go through the atomic "
        "funnel, not be written ad hoc (or dropped).\n\n" + "\n".join(missing)
    )


def _boundary_chain_inserts(tree: ast.AST) -> list[int]:
    """Linenos of ``_chain_insert(..., "hipaa_boundary_events", ...)`` calls."""
    hits: list[int] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = (f.id if isinstance(f, ast.Name)
                else f.attr if isinstance(f, ast.Attribute) else None)
        if name != "_chain_insert":
            continue
        if any(
            isinstance(a, ast.Constant) and a.value == _BOUNDARY_TABLE
            for a in n.args
        ):
            hits.append(n.lineno)
    return hits


def test_every_boundary_chain_insert_is_in_the_txn_sibling():
    """INVERSE arm (PD#3/PD#5): ONE function authors every
    ``hipaa_boundary_events`` row. Before N-466 there were two inline
    ``_chain_insert`` copies of the row shape (``record_hipaa_boundary`` and
    ``db/accounts.set_account_hipaa``) plus a third about to be added — two
    mirrored copies WILL drift."""
    offenders: list[str] = []
    seen = 0
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for lineno in _boundary_chain_inserts(tree):
            seen += 1
            chain = [
                s.name for s in enclosing_scope_chain(tree, lineno)
                if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if _BOUNDARY_TXN not in chain:
                offenders.append(f"{relpath(path)}:{lineno} in {chain or ['<module>']}")
    assert seen, (
        f"vacuous-pass guard: no `_chain_insert(..., {_BOUNDARY_TABLE!r}, ...)` "
        "call found anywhere in src — the boundary-table writer walk broke."
    )
    assert not offenders, (
        f"N-466: a raw `_chain_insert` into {_BOUNDARY_TABLE} outside "
        f"`{_BOUNDARY_TXN}`. Route it through that sibling so the row shape "
        "has one author.\n\n" + "\n".join(offenders)
    )


def _is_boundary_txn_call(n: ast.AST) -> bool:
    return (
        isinstance(n, ast.Call)
        and (getattr(n.func, "id", None) == _BOUNDARY_TXN
             or getattr(n.func, "attr", None) == _BOUNDARY_TXN)
    )


def _boundary_txn_calls_one_hop(fn, by_name: dict) -> list[ast.Call]:
    """Boundary-emit calls in ``fn``, plus those in any same-module helper
    ``fn`` calls by name (ONE hop).

    DA-422-3 — the unit was the FUNCTION, so moving the cascade emit into a
    helper went blind, and ``_hipaa_flip_on_cascade`` already exists inside
    that transaction and is exactly where a future author would put the row.
    One hop covers that refactor. It is NOT a fixpoint: a two-hop chain, a
    cross-module helper or a by-reference dispatch of the helper still evade
    it — stated in the SCOPE CAVEAT rather than left implied.
    """
    calls = [n for n in ast.walk(fn) if _is_boundary_txn_call(n)]
    for n in ast.walk(fn):
        if not isinstance(n, ast.Call):
            continue
        callee = getattr(n.func, "id", None) or getattr(n.func, "attr", None)
        helper = by_name.get(callee) if callee else None
        if helper is not None and helper is not fn:
            calls.extend(h for h in ast.walk(helper) if _is_boundary_txn_call(h))
    return calls


def _unshared_ts_boundary_calls(tree: ast.AST) -> list[str]:
    """DETECTOR: functions that emit SEVERAL boundary rows in one transaction
    without pinning them to a shared ``ts``.

    Count-agnostic over functions, not over a named site list. The invariant is
    a consequence of how the table is READ, not of style: ``latest_hipaa_boundary``
    is ``ORDER BY ts DESC LIMIT 1`` and ``latest_hipaa_boundaries_for_accounts``
    is ``ts = MAX(ts)`` with "duplicate-tick collisions keep the first". Two
    rows written by one logical event must therefore tie, or the LAST-written one
    wins the "latest boundary" render — ``set_account_hipaa``'s ``"cascade"``
    row would be reported as the account's current direction instead of the
    ``"on"`` flip it is a side effect of.
    """
    out: list[str] = []
    fns = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    by_name = {f.name: f for f in fns}
    for fn in fns:
        calls = _boundary_txn_calls_one_hop(fn, by_name)
        if len(calls) < 2:
            continue
        exprs: set[str] = set()
        for c in calls:
            kw = next((k for k in c.keywords if k.arg == "ts"), None)
            if kw is None:
                out.append(f"{fn.name}:{c.lineno}")
                continue
            exprs.add(ast.unparse(kw.value))
            # DA-422-2, strengthened past the fix it prescribed. Comparing
            # `ast.unparse` alone does NOT catch the seat's own worked
            # example: `ts=now_utc_iso()` on both calls unparses IDENTICALLY
            # and still yields two different timestamps, because the
            # expression is RE-EVALUATED at each site. The invariant is not
            # "same text" but "same VALUE", and the only statically decidable
            # form of that is a bound reference — a Name or an Attribute
            # evaluated once above the calls. Any Call inside the `ts=`
            # expression re-evaluates.
            if any(isinstance(x, ast.Call) for x in ast.walk(kw.value)):
                out.append(
                    f"{fn.name}:{c.lineno}: ts={ast.unparse(kw.value)} is "
                    "re-evaluated per call site; bind it once and pass the name"
                )
        # PRESENT is not SHARED: differing expressions are not one timestamp.
        if len(exprs) > 1:
            out.append(
                f"{fn.name}: ts= expressions differ across "
                f"{len(calls)} calls: {sorted(exprs)}"
            )
    return out


def test_multi_row_boundary_writers_pin_a_shared_timestamp():
    """REGRESSION GUARD on this very conversion. Collapsing the two inline
    ``_chain_insert`` copies onto one sibling silently gave each row its OWN
    ``now_utc_iso()``, making the cascade row strictly later than the flip it
    describes — a behaviour change no existing test asserted, because nothing
    checked WHICH row is latest after a cascade."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        tree = parse_module(path)
        if tree is None:
            continue
        for hit in _unshared_ts_boundary_calls(tree):
            offenders.append(f"{relpath(path)}:{hit}")
    assert not offenders, (
        f"a function emits several {_BOUNDARY_TABLE} rows for ONE logical event "
        f"without passing an explicit shared `ts=` to `{_BOUNDARY_TXN}`. The "
        "rows must tie, or the last one written wins `latest_hipaa_boundary` "
        "and the compliance page reports the wrong direction.\n\n"
        + "\n".join(offenders)
    )


def test_shared_ts_detector_has_teeth():
    assert_pin_has_teeth(
        _unshared_ts_boundary_calls,
        'def f(conn):\n'
        '    record_hipaa_boundary_txn(conn, s, "on", ts=now)\n'
        '    record_hipaa_boundary_txn(conn, s, "cascade")\n',
        'def f(conn):\n'
        '    record_hipaa_boundary_txn(conn, s, "on", ts=now)\n'
        '    record_hipaa_boundary_txn(conn, s, "cascade", ts=now)\n',
    )


def test_shared_ts_detector_rejects_two_distinct_now_calls():
    """DA-422-2. The re-dressed form of the SAME defect: both calls carry a
    ``ts=``, so a presence check is satisfied, and the two timestamps still
    differ — cascade strictly later than the flip it describes."""
    bad = parse_source(
        'def f(conn):\n'
        '    record_hipaa_boundary_txn(conn, s, "on", ts=now_utc_iso())\n'
        '    record_hipaa_boundary_txn(conn, s, "cascade", ts=now_utc_iso())\n'
    )
    assert _unshared_ts_boundary_calls(bad), (
        "the detector accepted two DISTINCT ts= expressions while its own "
        "message promises they are SHARED"
    )


def test_shared_ts_detector_follows_one_helper_hop():
    """DA-422-3. `_hipaa_flip_on_cascade` already runs inside that
    transaction, so relocating the emit into a helper is an ordinary refactor,
    not a mistake."""
    bad = parse_source(
        'def _cascade(conn, s):\n'
        '    record_hipaa_boundary_txn(conn, s, "cascade")\n'
        'def set_account_hipaa(conn, s):\n'
        '    record_hipaa_boundary_txn(conn, s, "on", ts=now)\n'
        '    _cascade(conn, s)\n'
    )
    assert _unshared_ts_boundary_calls(bad), (
        "the detector missed a boundary emit moved one hop into a same-module "
        "helper called from the transaction"
    )


def test_self_committing_detector_sees_a_by_reference_dispatch():
    """DA-422-1 / PD#2. `db_call(set_setting, db, KEY, v)` is the seam the
    Prime Directive names by name, and `admin.py` already drives this handler
    through `db_call`."""
    bad = parse_source(
        'def handler():\n'
        '    def _work():\n'
        '        record_system_hipaa_flip(db, settings_key=KEY, new_runtime=n,\n'
        '                                 direction="off")\n'
        '        db_call(set_setting, db, "runtime:extra", n)\n'
        '    db_call(_work)\n'
        '    _apply_runtime_settings(n, allow_hipaa_change=True)\n'
    )
    assert _self_committing_in_flip_scope(bad), (
        "a self-committing writer handed to the db_call dispatcher BY "
        "REFERENCE read green — the PD#2 blind spot"
    )


def test_shared_ts_detector_ignores_a_single_row_writer():
    """A lone boundary write needs no shared timestamp — flagging it would make
    the pin noise that gets allow-listed away."""
    assert not _unshared_ts_boundary_calls(
        parse_source('def f(conn):\n    record_hipaa_boundary_txn(conn, s, "on")\n')
    )


def _funnel_def(tree: ast.AST):
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == _FUNNEL:
            return n
    return None


def test_the_funnel_invalidates_the_cache_on_every_exit_edge():
    """THE PRECONDITION, read off the AST. ``invalidate_setting_cache`` must
    sit in a ``Try.finalbody`` inside the funnel — a call placed after the
    commit covers the commit edge only, and the rollback edge is the one that
    reopens N-464 (a racing reader caches the UNCOMMITTED row; the rollback
    discards the row but not the cache entry)."""
    tree = parse_module(SRC_ROOT / _FUNNEL_MODULE)
    assert tree is not None, f"{_FUNNEL_MODULE} did not parse"
    fn = _funnel_def(tree)
    assert fn is not None, (
        f"`{_FUNNEL}` is not defined in {_FUNNEL_MODULE}. It is the atomic "
        "funnel the other assertions in this file are about; if it moved, "
        "update _FUNNEL_MODULE rather than deleting this test."
    )
    in_finally = [
        n.lineno
        for t in ast.walk(fn) if isinstance(t, ast.Try)
        for stmt in t.finalbody
        for n in ast.walk(stmt)
        if isinstance(n, ast.Call)
        and (getattr(n.func, "id", None) == "invalidate_setting_cache"
             or getattr(n.func, "attr", None) == "invalidate_setting_cache")
    ]
    assert in_finally, (
        f"N-466 PRECONDITION VIOLATED: `{_FUNNEL}` does not call "
        "`invalidate_setting_cache` from a `finally:` block. Invalidation must "
        "run on EVERY exit edge — commit AND rollback. Measured 2026-09-12: "
        "without the rollback edge, settings rows = 0 while `get_setting` "
        "serves `{'hipaa': False}` and the live flag is True (N-464 reopened "
        "through a cached phantom)."
    )


def test_the_funnel_does_not_mutate_the_process_flag():
    """The live-flag apply belongs AFTER the commit, in the handler. Folding
    ``_apply_runtime_settings`` into the transaction is the mirror divergence:
    the process flag flips while the row rolls back (the shape the /config/save
    N-464 comment already warns about)."""
    tree = parse_module(SRC_ROOT / _FUNNEL_MODULE)
    fn = _funnel_def(tree)
    assert fn is not None
    called = _called_names(fn)
    assert "_apply_runtime_settings" not in called, (
        f"`{_FUNNEL}` applies the in-process runtime settings inside its "
        "transaction. That call has side effects (the HIPAA flag, the log "
        "level) and cannot be rolled back — on rollback the process would "
        "report the NEW posture while the DB holds the old one. Apply it in "
        "the handler, after db_call returns."
    )


# ---------------------------------------------------------------------------
# Teeth — each detector FLAGS a planted bad shape and PASSES a good one.
# A hand-rolled re-implementation in a teeth test passes even when the real
# detector is dead; these call the same functions the pins call.
# ---------------------------------------------------------------------------

_BAD_SAME_SCOPE = '''
def handler():
    def _work():
        set_setting(db, KEY, new)
        _apply_runtime_settings(new, allow_hipaa_change=True)
        record_hipaa_boundary(db, "system", "off")
    db_call(_work)
'''

_BAD_HOISTED_ONE_LEVEL_OUT = '''
def handler():
    def _work():
        _apply_runtime_settings(new, allow_hipaa_change=True)
    db_call(_work)
    record_hipaa_boundary(db, "system", "off")
'''

_GOOD = '''
def handler():
    def _work():
        record_system_hipaa_flip(db, settings_key=KEY, new_runtime=new,
                                 direction="off")
        return new
    new = db_call(_work)
    _apply_runtime_settings(new, allow_hipaa_change=True)
'''


def test_self_committing_detector_has_teeth():
    assert_pin_has_teeth(_self_committing_in_flip_scope, _BAD_SAME_SCOPE, _GOOD)


_GOOD_PEER_FN_USES_SET_SETTING = '''
def other_handler():
    """/config/save — legitimately own-commits; it is not a HIPAA flip."""
    set_setting(db, KEY, new)

def handler():
    def _work():
        record_system_hipaa_flip(db, settings_key=KEY, new_runtime=new,
                                 direction="off")
        return new
    new = db_call(_work)
    _apply_runtime_settings(new, allow_hipaa_change=True)
'''


def test_self_committing_detector_ignores_a_peer_function_in_the_same_file():
    """PRECISION BOUNDARY (the false positive that MODULE-scope union caused,
    caught on the first green run): ``admin.py`` holds both the HIPAA off-ramp
    and ``/config/save``, and the latter's own-commit ``set_setting`` is
    correct. A pin that flags it is a pin someone allow-lists away."""
    assert not _self_committing_in_flip_scope(
        parse_source(_GOOD_PEER_FN_USES_SET_SETTING)
    ), "the detector flagged a peer function's legitimate own-commit write"


def test_self_committing_detector_sees_the_hoisted_shape():
    """The ancestor-scope union is load-bearing, not decoration: moving the
    own-commit call OUT of the nested closure is the first thing a refactor
    does, and an innermost-scope-only pin reads green on it."""
    assert _self_committing_in_flip_scope(parse_source(_BAD_HOISTED_ONE_LEVEL_OUT)), (
        "the detector missed a self-committing writer hoisted into the "
        "handler body one scope out from the flip token"
    )


def test_funnel_route_detector_has_teeth():
    assert_pin_has_teeth(
        _flip_scope_missing_funnel,
        # A flip site with NO durable-write route at all — the shape that
        # satisfies the "no own-commit writer" arm by deleting the audit row.
        "def handler():\n"
        "    _apply_runtime_settings(new, allow_hipaa_change=True)\n",
        _GOOD,
    )


def test_boundary_chain_insert_detector_has_teeth():
    assert_pin_has_teeth(
        _boundary_chain_inserts,
        'def w(conn):\n'
        '    _chain_insert(conn, "hipaa_boundary_events", {"ts": now})\n',
        'def w(conn):\n'
        '    _chain_insert(conn, "access_log", {"ts": now})\n',
    )
