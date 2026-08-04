"""Prevention pin: no cross-loop drain of the fire-and-forget audit tasks
(census run15 testinfra — the flake class that bit test_audit_strict_mode AND
test_request_id under CI/xdist load; it RECURRED, so it gets a pin).

The access-audit middleware fire-and-forgets its audit write via
``asyncio.create_task`` on the loop the request runs on (tracked on
``app.state._audit_pending``; the ``audit_failures`` bump AND the ``access_log``
INSERT both happen INSIDE that task). A test that drains those tasks by creating
a SECOND ``asyncio.new_event_loop()`` (or ``asyncio.run``) and ``gather``-ing
them is the CROSS-LOOP-DRAIN anti-pattern: a task bound to loop A cannot be
driven by loop B, so under CI load the fire-and-forget side-effect has not
happened when the test asserts -> flaky (counter 0 / row missing).

INVARIANT: no test FUNCTION references BOTH ``asyncio.new_event_loop()`` /
``asyncio.run(`` AND ``_audit_pending``. The two CORRECT drains do not:
  - async + ``httpx.ASGITransport`` (same loop; ``await asyncio.gather(*_audit_pending)``
    on the RUNNING loop) — test_audit_strict_mode / test_request_id;
  - poll-until-done (``all(t.done() for t in pending)`` + ``time.sleep`` + a
    bounded timeout; the persistent sync-TestClient portal loop drives the task)
    — test_web/test_access_audit.py.
A self-contained ``new_event_loop`` that runs its OWN coroutines (and never
touches ``_audit_pending``) is fine (e.g. test_290_phase0) and is NOT flagged.

This walks the tests/ tree (not src/email_triage), so it is allow-listed in
``test_pin_harness_adoption.py`` rather than using the src-rooted harness.
"""
from __future__ import annotations

import ast
import pathlib

from _pin_harness import iter_files, parse_module, relpath  # N-350 R31, N-382 R32

_TESTS_ROOT = pathlib.Path(__file__).resolve().parent


def _fn_has_cross_loop_audit_drain(node: ast.AST) -> bool:
    """True if the function both spins a NEW event loop and references the
    fire-and-forget audit-task set ``_audit_pending`` — the cross-loop drain."""
    has_new_loop = False
    has_pending = False
    for n in ast.walk(node):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            if n.func.attr == "new_event_loop":
                has_new_loop = True
            elif (
                n.func.attr == "run"
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == "asyncio"
            ):
                has_new_loop = True
        elif isinstance(n, ast.Attribute) and n.attr == "_audit_pending":
            has_pending = True
        elif isinstance(n, ast.Name) and n.id == "_audit_pending":
            has_pending = True
    return has_new_loop and has_pending


def test_no_cross_loop_audit_pending_drain():
    offenders = []
    # N-382 R32: route the tests/ walk + relpath through the shared
    # harness (`iter_files` + `relpath`) instead of a hand-rolled
    # rglob + `__pycache__` skip + `.replace("\\", "/")` pair.
    for path in iter_files(_TESTS_ROOT, "*.py"):
        try:
            tree = parse_module(path); assert tree is not None  # N-350 R31
        except SyntaxError:  # pragma: no cover
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if _fn_has_cross_loop_audit_drain(node):
                    rel = relpath(path, _TESTS_ROOT)
                    offenders.append(f"{rel}::{node.name}:{node.lineno}")
    assert not offenders, (
        "a test drains the fire-and-forget audit tasks (app.state._audit_pending) "
        "via a NEW event loop (asyncio.new_event_loop() / asyncio.run) — the "
        f"cross-loop-drain flake class (census run15 testinfra): {offenders}. A "
        "task bound to loop A can't be driven by loop B, so it races under CI "
        "load. Use the SAME-loop drain: `async def` + httpx.ASGITransport with "
        "`await asyncio.gather(*_audit_pending)` on the running loop (like "
        "test_audit_strict_mode / test_request_id), or the poll-until-done drain "
        "in tests/test_web/test_access_audit.py."
    )


def test_pin_has_teeth():
    # The cross-loop drain (new_event_loop + _audit_pending in one fn) is caught.
    bad = ast.parse(
        "import asyncio\n"
        "def t(app):\n"
        "    pending = app.state._audit_pending\n"
        "    loop = asyncio.new_event_loop()\n"
        "    loop.run_until_complete(asyncio.gather(*pending))\n"
    )
    fn = next(n for n in ast.walk(bad) if isinstance(n, ast.FunctionDef))
    assert _fn_has_cross_loop_audit_drain(fn)
    # The correct same-loop drain (no new_event_loop) is NOT flagged.
    ok = ast.parse(
        "async def t(app):\n"
        "    pending = app.state._audit_pending\n"
        "    await asyncio.gather(*pending)\n"
    )
    fn2 = next(n for n in ast.walk(ok) if isinstance(n, ast.AsyncFunctionDef))
    assert not _fn_has_cross_loop_audit_drain(fn2)
    # A self-contained new_event_loop (no _audit_pending) is NOT flagged.
    ok2 = ast.parse(
        "import asyncio\n"
        "def t():\n"
        "    loop = asyncio.new_event_loop()\n"
        "    loop.run_until_complete(_my_coro())\n"
    )
    fn3 = next(n for n in ast.walk(ok2) if isinstance(n, ast.FunctionDef))
    assert not _fn_has_cross_loop_audit_drain(fn3)
