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
    bounded timeout; the sync-TestClient portal loop drives the task; a client used without
    `with` gets a per-request portal, so a test that drains across requests pins one portal, punch 577)
    — test_web/test_access_audit.py.
A self-contained ``new_event_loop`` that runs its OWN coroutines (and never
touches ``_audit_pending``) is fine (e.g. test_290_phase0) and is NOT flagged.

INVARIANT 2 (punch 577, DA F577-2) — the UNHELD-LOOP wait: a sync TestClient
used without ``with`` runs each request on its own portal loop, which closes as
the response returns and CANCELS the audit task if its INSERT has not yet
dispatched; the wait then times out (or a ``done()`` check passes on the
cancel). So no SYNC function may both wait on the fire-and-forget audit write
(call a ``*drain_audit*`` helper, or reference ``_audit_pending``) AND send a
``*client.<verb>(`` request outside ``with _one_portal_loop(`` (tests/_portal_loop.py).
``async def`` functions are exempt by construction — they await on their own
running loop (the ASGITransport drains in test_audit_strict_mode /
test_request_id). A test that reads an access_log row a route writes
SYNCHRONOUSLY (no wait) is not this seam and is not flagged.

RESIDUALS the INVARIANT-2 arm CANNOT see (DA fold-check, F577-4) — review by hand:
  - requests NOT sent as a bare ``<name>client.<verb>(``: ``self.client``, an
    aliased client (``c = client``), or a request issued inside a helper;
  - waits NOT shaped as a ``*drain_audit*`` Name call or ``_audit_pending``: an
    attribute-form drain (``helpers.drain_audit(...)``) or a custom poll loop on
    a row count;
  - fire-and-forget producers OTHER than the access-audit middleware (the
    backup ``_runner``, punch 569's ``_run``, ``triage_runner_bulk``): the same
    per-request-loop cancel applies to them, but neither arm looks for them.

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


_REQUEST_VERBS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "request"}
)


def _is_client_request(n: ast.AST) -> bool:
    return (
        isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in _REQUEST_VERBS
        and isinstance(n.func.value, ast.Name)
        and n.func.value.id.endswith("client")
    )


def _is_one_portal_loop_with(n: ast.AST) -> bool:
    return isinstance(n, ast.With) and any(
        isinstance(i.context_expr, ast.Call)
        and isinstance(i.context_expr.func, ast.Name)
        and i.context_expr.func.id == "_one_portal_loop"
        for i in n.items
    )


def _waits_on_audit_write(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if (
            isinstance(n, ast.Call)
            and isinstance(n.func, ast.Name)
            and "drain_audit" in n.func.id
        ):
            return True
        if isinstance(n, ast.Attribute) and n.attr == "_audit_pending":
            return True
        if isinstance(n, ast.Constant) and n.value == "_audit_pending":
            return True
    return False


def _fn_has_unheld_loop_audit_wait(node: ast.AST) -> bool:
    """True if a SYNC function waits on the fire-and-forget audit write AND
    sends a TestClient request outside ``with _one_portal_loop(`` — the
    per-request-portal cancel seam (INVARIANT 2)."""
    if not isinstance(node, ast.FunctionDef) or not _waits_on_audit_write(node):
        return False
    held = {
        id(m)
        for w in ast.walk(node) if _is_one_portal_loop_with(w)
        for m in ast.walk(w)
    }
    return any(
        _is_client_request(n) and id(n) not in held for n in ast.walk(node)
    )


def _offenders(predicate) -> list[str]:
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
                if predicate(node):
                    rel = relpath(path, _TESTS_ROOT)
                    offenders.append(f"{rel}::{node.name}:{node.lineno}")
    return offenders


def test_no_cross_loop_audit_pending_drain():
    offenders = _offenders(_fn_has_cross_loop_audit_drain)
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


def test_no_unheld_loop_audit_wait():
    offenders = _offenders(_fn_has_unheld_loop_audit_wait)
    assert not offenders, (
        "a sync test waits on the fire-and-forget audit write (a *drain_audit* "
        "call or _audit_pending) after a TestClient request sent OUTSIDE "
        f"`with _one_portal_loop(client):` (punch 577): {offenders}. Without "
        "`with client:` each request runs on its own portal loop, which closes "
        "as the response returns and cancels the audit task before its INSERT "
        "-> the drain times out, or a done() check passes on the cancel. Wrap "
        "the request(s) AND the wait in `_one_portal_loop` (tests/_portal_loop.py)."
    )


def _first_fn(src: str) -> ast.AST:
    return next(
        n for n in ast.walk(ast.parse(src))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    )


def test_unheld_loop_arm_has_teeth():
    # The pre-577 shape (request, then a drain, no held loop) is caught —
    # both the helper-drain form and the _audit_pending done()-check form.
    assert _fn_has_unheld_loop_audit_wait(_first_fn(
        "def t(client, app, db):\n"
        "    client.post('/x', json={})\n"
        "    _drain_audit(app)\n"
    ))
    assert _fn_has_unheld_loop_audit_wait(_first_fn(
        "def t(client, app):\n"
        "    client.get('/classify')\n"
        "    assert all(t.done() for t in app.state._audit_pending)\n"
    ))
    # One request inside the held loop does not excuse another outside it.
    assert _fn_has_unheld_loop_audit_wait(_first_fn(
        "def t(client, app, db):\n"
        "    client.get('/a')\n"
        "    with _one_portal_loop(client):\n"
        "        client.get('/b')\n"
        "        _drain_audit_writes(app, db=db, before=0)\n"
    ))
    # The request and the wait inside the held loop are NOT flagged.
    assert not _fn_has_unheld_loop_audit_wait(_first_fn(
        "def t(client, app, db):\n"
        "    with _one_portal_loop(client):\n"
        "        client.get('/classify')\n"
        "        _drain_audit_writes(app, db=db, before=0)\n"
    ))
    # async def awaits on its own running loop (the ASGITransport drains).
    assert not _fn_has_unheld_loop_audit_wait(_first_fn(
        "async def t(client, app):\n"
        "    await client.get('/classify')\n"
        "    await asyncio.gather(*getattr(app.state, '_audit_pending'))\n"
    ))
    # A synchronous-row read with no wait is not this seam.
    assert not _fn_has_unheld_loop_audit_wait(_first_fn(
        "def t(client, db):\n"
        "    client.post('/dismiss')\n"
        "    assert list_access_events(db, limit=1)\n"
    ))
