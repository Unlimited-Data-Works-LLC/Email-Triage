"""Punch 854 structural pin — a backfill_capped chip clear must prove coverage.

The ``backfill_capped`` chip is a LOSS RECORD (``web/_backfill_chip.py``): it
says mail in a gap was never enumerated. Census wf_e4854b61 (2026-11-04) found
the IMAP poll path cleared it after the next successful ``poll_once`` and the
IDLE watcher after the next connect. Neither walk recovers the gap, so the
only notice of un-triaged mail lasted one poll interval. The N-198 pin this
file replaces ("every file that marks must also clear") defended that clear.

Property, over every ``clear_backfill_capped`` call in src, direct or handed to
an off-loop dispatcher (``db_call(clear_backfill_capped, ...)``, via the shared
``hop_target`` resolver):

  * UNSCOPED (``source_mailbox=None`` or omitted) only inside a function, at any
    nesting depth, decorated by a router verb: the operator's dismiss; or
  * SCOPED with a literal ``walk_kind=`` that is in ``FULL_WALK_KINDS`` (a
    recovery walk that enumerated the whole mailbox).

No allow-list. The SSOT refuses any other scoped clear at run time too, so this
pin keeps the call sites honest and the function keeps the rule fail-closed.

A second property keeps the kinds closed: every ``mark_backfill_capped`` call
names a literal ``kind=`` in ``BACKFILL_KINDS`` (``FULL_WALK_KINDS`` is a subset),
so a misspelled kind cannot silently fall outside the full-walk set.

A third property keeps the proof honest: a full-walk clear sits in a function
that took its ids from ``probe_resync_walk``, which follows ``@odata.nextLink``.
A single short page with more pending is not the whole mailbox.
"""
from __future__ import annotations

import ast

from _pin_harness import (
    SRC_ROOT,
    assert_pin_has_teeth,
    call_args_of,
    call_name,
    enclosing_callable,
    iter_src_files,
    parse_module,
    relpath,
)

from email_triage.web._backfill_chip import BACKFILL_KINDS, FULL_WALK_KINDS

_CLEAR_FN = "clear_backfill_capped"
_MARK_FN = "mark_backfill_capped"
_SSOT_REL = "web/_backfill_chip.py"
_PROBE_FN = "probe_resync_walk"
# No "get": a read must never clear the record of a gap (db-sme NOTE, gap B).
_ROUTER_VERBS = frozenset({"post", "put", "patch", "delete"})


def _clear_keywords(node: ast.AST) -> tuple | None:
    """The keywords a ``clear_backfill_capped`` call receives, or None when
    ``node`` is not one (direct call or dispatcher hop)."""
    got = call_args_of(node, _CLEAR_FN)
    return None if got is None else got[1]


def _kw(keywords: tuple, name: str) -> ast.expr | None:
    for kw in keywords:
        if kw.arg == name:
            return kw.value
    return None


def _in_router_handler(node: ast.AST) -> bool:
    """True when any enclosing scope, at any depth, is a router-verb handler."""
    scope = enclosing_callable(node)
    while scope is not None:
        for dec in getattr(scope, "decorator_list", ()):
            if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                    and dec.func.attr in _ROUTER_VERBS):
                return True
        scope = enclosing_callable(scope)
    return False


def _violations(tree: ast.AST) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        keywords = _clear_keywords(node)
        if keywords is None:
            continue
        scope = _kw(keywords, "source_mailbox")
        unscoped = scope is None or (
            isinstance(scope, ast.Constant) and scope.value is None)
        if unscoped:
            if not _in_router_handler(node):
                found.append((node.lineno, "unscoped clear outside an operator endpoint"))
            continue
        walk = _kw(keywords, "walk_kind")
        if not (isinstance(walk, ast.Constant) and walk.value in FULL_WALK_KINDS):
            found.append((node.lineno, "scoped clear without a literal FULL_WALK_KINDS walk_kind"))
    return found


def _outermost_function(node: ast.AST) -> ast.AST | None:
    scope = enclosing_callable(node)
    outer = scope
    while scope is not None:
        outer = scope
        scope = enclosing_callable(scope)
    return outer


def _probe_violations(tree: ast.AST) -> list[tuple[int, str]]:
    """A full-walk clear runs in a function whose walk came from the one probe
    that follows ``@odata.nextLink`` (a single short page is not a full walk)."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        keywords = _clear_keywords(node)
        if keywords is None:
            continue
        walk = _kw(keywords, "walk_kind")
        if not (isinstance(walk, ast.Constant) and walk.value in FULL_WALK_KINDS):
            continue
        fn = _outermost_function(node)
        if fn is None or not any(
                isinstance(n, ast.Call) and call_name(n) == _PROBE_FN
                for n in ast.walk(fn)):
            found.append((node.lineno, f"full-walk clear without {_PROBE_FN} in its function"))
    return found


def _full_walk_clears(tree: ast.AST) -> int:
    count = 0
    for node in ast.walk(tree):
        keywords = _clear_keywords(node)
        walk = _kw(keywords, "walk_kind") if keywords is not None else None
        if isinstance(walk, ast.Constant) and walk.value in FULL_WALK_KINDS:
            count += 1
    return count


def _clear_calls(tree: ast.AST) -> int:
    return sum(1 for node in ast.walk(tree) if _clear_keywords(node) is not None)


def _dismiss_clears(tree: ast.AST) -> int:
    """Unscoped clears inside a router-verb handler: the operator's dismiss."""
    count = 0
    for node in ast.walk(tree):
        keywords = _clear_keywords(node)
        if keywords is None:
            continue
        scope = _kw(keywords, "source_mailbox")
        if (scope is None or (isinstance(scope, ast.Constant) and scope.value is None)) \
                and _in_router_handler(node):
            count += 1
    return count


def _mark_keywords(node: ast.AST) -> tuple | None:
    """The keywords a ``mark_backfill_capped`` call receives (direct or hop)."""
    got = call_args_of(node, _MARK_FN)
    return None if got is None else got[1]


def _kind_violations(tree: ast.AST) -> list[tuple[int, str]]:
    """Every mark names a literal ``kind=`` in the closed BACKFILL_KINDS set, so
    a misspelled kind cannot silently miss FULL_WALK_KINDS."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        keywords = _mark_keywords(node)
        if keywords is None:
            continue
        kind = _kw(keywords, "kind")
        if not (isinstance(kind, ast.Constant) and kind.value in BACKFILL_KINDS):
            found.append((node.lineno, "mark without a literal BACKFILL_KINDS kind"))
    return found


def test_every_chip_clear_proves_coverage():
    offenders: list[str] = []
    calls = 0
    dismisses = 0
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        calls += _clear_calls(tree)
        dismisses += _dismiss_clears(tree)
        offenders += [f"  {rel}:{line}  {why}" for line, why in _violations(tree)]
    # Non-vacuous: clears exist, and one of them is the operator's dismiss. Without
    # the dismiss edge a record could only clear by a full walk (DA S4).
    assert calls, f"no {_CLEAR_FN} call found under {SRC_ROOT}; the scan is blind"
    assert dismisses, (
        f"no unscoped {_CLEAR_FN} inside a router-verb handler: the operator's "
        "dismiss edge is gone, or the handler shape moved past _in_router_handler")
    assert not offenders, (
        "Punch 854: a backfill_capped chip is a loss record. Clear it only from "
        "the operator's dismiss endpoint (source_mailbox=None) or after a walk "
        "that enumerated the whole mailbox (walk_kind= a literal in "
        "FULL_WALK_KINDS). A routine poll, connect or window-bounded walk "
        "recovers none of the gap.\n\n" + "\n".join(offenders)
    )


def test_every_chip_mark_names_a_known_kind():
    assert FULL_WALK_KINDS <= BACKFILL_KINDS
    offenders: list[str] = []
    marks = 0
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        marks += sum(1 for n in ast.walk(tree) if _mark_keywords(n) is not None)
        offenders += [f"  {rel}:{line}  {why}" for line, why in _kind_violations(tree)]
    assert marks, f"no {_MARK_FN} call found under {SRC_ROOT}; the scan is blind"
    assert not offenders, (
        "Punch 854: name the chip kind as a literal from BACKFILL_KINDS.\n\n"
        + "\n".join(offenders)
    )


def test_kind_pin_has_teeth():
    assert_pin_has_teeth(_kind_violations, (
        "async def push(db, aid):\n"
        "    await db_call(mark_backfill_capped, db, aid, kind='gmail_histroy',\n"
        "                  window='last 7 days', recovered=200)\n"
    ), (
        "async def push(db, aid):\n"
        "    await db_call(mark_backfill_capped, db, aid, kind='gmail_history',\n"
        "                  window='last 7 days', recovered=200)\n"
    ))


def test_pin_has_teeth():
    good = (
        "async def recover(db, aid):\n"
        "    await db_call(clear_backfill_capped, db, aid,\n"
        "                  source_mailbox='INBOX', walk_kind='o365_resync')\n"
        "@router.post('/accounts/{aid}/backfill-capped/dismiss')\n"
        "async def dismiss(db, aid):\n"
        "    def _work():\n"
        "        clear_backfill_capped(db, aid, source_mailbox=None)\n"
        "    await db_call(_work)\n"
    )
    # A routine scoped clear through the dispatcher seam (the 854 shape).
    assert_pin_has_teeth(_violations, (
        "async def poll(db, aid, mb):\n"
        "    await db_call(clear_backfill_capped, db, aid, source_mailbox=mb)\n"
    ), good)
    # A scoped clear naming a walk that does not cover the gap.
    assert_pin_has_teeth(_violations, (
        "def push(db, aid):\n"
        "    clear_backfill_capped(db, aid, source_mailbox='INBOX',\n"
        "                          walk_kind='gmail_history')\n"
    ))
    # An unscoped clear outside an operator endpoint.
    assert_pin_has_teeth(_violations, (
        "async def connect(db, aid):\n"
        "    await db_call(clear_backfill_capped, db, aid, source_mailbox=None)\n"
    ))
    # A walk_kind that is a variable, not a literal, proves nothing.
    assert_pin_has_teeth(_violations, (
        "def resync(db, aid, kind):\n"
        "    clear_backfill_capped(db, aid, source_mailbox='INBOX', walk_kind=kind)\n"
    ))


def test_every_full_walk_clear_follows_the_probe():
    offenders: list[str] = []
    clears = 0
    for path in iter_src_files():
        rel = relpath(path)
        if rel == _SSOT_REL:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        clears += _full_walk_clears(tree)
        offenders += [f"  {rel}:{line}  {why}" for line, why in _probe_violations(tree)]
    assert clears, f"no full-walk {_CLEAR_FN} call found under {SRC_ROOT}; the scan is blind"
    assert not offenders, (
        f"Punch 854: a full-walk clear proves coverage only with ids from "
        f"{_PROBE_FN}, which follows nextLink.\n\n" + "\n".join(offenders)
    )


def test_probe_pin_has_teeth():
    assert_pin_has_teeth(_probe_violations, (
        "async def resync(db, aid, provider):\n"
        "    ids = await provider.search('ALL', limit=201)\n"
        "    await db_call(clear_backfill_capped, db, aid,\n"
        "                  source_mailbox='INBOX', walk_kind='o365_resync')\n"
    ), (
        "async def resync(db, aid, provider):\n"
        "    ids, saturated = await probe_resync_walk(provider)\n"
        "    await db_call(clear_backfill_capped, db, aid,\n"
        "                  source_mailbox='INBOX', walk_kind='o365_resync')\n"
    ))
