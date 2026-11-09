"""the backlog  recurrence-4 pin — CancelledError stash + counter gate.

db-sme F1 + DA F1 convergent fold: without a class-named test, the
BaseException broaden + done-callback design has no regression net for
recurrence #5.

Behavioural invariants:

* When ``safe_audit_write`` / ``safe_audit_write_async`` catches an
  ``asyncio.CancelledError`` (or any BaseException-not-Exception),
  it (a) stashes on ``_LAST_AUDIT_EXC`` FIRST, (b) does NOT bump
  the /health drift counter, (c) does NOT emit at WARNING (DEBUG
  only — the counter is reserved for genuine audit-write failures,
  not routine test-teardown/graceful-shutdown cancellations), and
  (d) re-raises.

* When either wrapper catches an ``Exception`` subclass (the pre-
  existing shape), it stashes, bumps the counter, WARNING-logs,
  and returns None (backwards compat).

* ``attach_audit_done_callback`` stashes ``task.exception()`` when
  present OR a synthesized ``_AsyncCancelledMarker`` when
  ``task.cancelled()`` is True. Closes the pre-await-cancel hole
  where the inner ``except BaseException`` never runs because the
  loop cancelled the coroutine BEFORE it hit ``await awrite()``.

Structural invariants (interprocedural pin — db-sme F2):

* Both ``safe_audit_write`` bodies contain an ``except BaseException``
  clause whose body contains (a) a ``_stash_last_audit_exc`` call
  AND (b) an ``if not isinstance(exc, Exception): ... raise`` shape
  OR an equivalent branch that ``raise``s in the not-Exception path.
  Prevents a future "cleanup" from dropping the re-raise + silently
  breaking cancel propagation.
"""
from __future__ import annotations

import ast
import asyncio

import pytest

from _pin_harness import SRC_ROOT, parse_module


# ---------------------------------------------------------------------------
# Behavioural tests — the stash / counter / re-raise contract
# ---------------------------------------------------------------------------


def test_sync_stash_no_counter_bump_on_cancellederror(monkeypatch):
    """PD#8 fail-CLOSED: stash carries the class name for the drain
    pin; counter stays untouched so shutdown noise doesn't drown real
    failures."""
    from email_triage.web import _audit

    bumps = {"n": 0}
    monkeypatch.setattr(_audit, "_bump_failure_counter",
                        lambda: bumps.__setitem__("n", bumps["n"] + 1))

    def _write():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        _audit.safe_audit_write(_write, description="test-cancel-sync")
    stashed = _audit.get_last_audit_exc()
    assert stashed is not None
    exc, description, _ts = stashed
    assert isinstance(exc, asyncio.CancelledError)
    assert description == "test-cancel-sync"
    assert bumps["n"] == 0, (
        "Counter bumped on CancelledError — would flood /health drift "
        "on routine test-teardown / graceful-shutdown noise."
    )


@pytest.mark.audit_failure_expected(
    match='test-exception-sync',
    count=1,
)
def test_sync_stash_and_counter_on_regular_exception(monkeypatch):
    """Backwards-compat: Exception subclass keeps the old shape."""
    from email_triage.web import _audit

    bumps = {"n": 0}
    monkeypatch.setattr(_audit, "_bump_failure_counter",
                        lambda: bumps.__setitem__("n", bumps["n"] + 1))

    def _write():
        raise ValueError("real audit-write failure")

    result = _audit.safe_audit_write(_write, description="test-exception-sync")
    assert result is None
    stashed = _audit.get_last_audit_exc()
    assert stashed is not None
    exc, description, _ts = stashed
    assert isinstance(exc, ValueError)
    assert description == "test-exception-sync"
    assert bumps["n"] == 1


@pytest.mark.asyncio
async def test_async_stash_no_counter_bump_on_cancellederror(monkeypatch):
    from email_triage.web import _audit

    bumps = {"n": 0}
    monkeypatch.setattr(_audit, "_bump_failure_counter",
                        lambda: bumps.__setitem__("n", bumps["n"] + 1))

    async def _awrite():
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await _audit.safe_audit_write_async(
            _awrite, description="test-cancel-async"
        )
    stashed = _audit.get_last_audit_exc()
    assert stashed is not None
    exc, description, _ts = stashed
    assert isinstance(exc, asyncio.CancelledError)
    assert description == "test-cancel-async"
    assert bumps["n"] == 0


@pytest.mark.asyncio
@pytest.mark.audit_failure_expected(
    match='test-signal-exception',
    count=1,
)
async def test_done_callback_fires_signal_on_exception(monkeypatch):
    """the backlog  F3 (DA fold) — signal.set() fires on the
    exception terminal mode. Prevents a silent rename regression on
    the signaling wire."""
    import threading
    from email_triage.web import _audit

    signal = threading.Event()

    async def _raises():
        raise ValueError("audit-write drift")

    task = asyncio.create_task(_audit.safe_audit_write_async(
        _raises, description="test-signal-exception",
    ))
    _audit.attach_audit_done_callback(task, "test-signal-exception", signal=signal)
    await task
    # Done-callback runs on the event loop after task completion;
    # signal should have fired.
    assert signal.is_set(), (
        "attach_audit_done_callback did not fire signal on exception "
        "terminal — drain-helper wake wire regressed."
    )


@pytest.mark.asyncio
async def test_done_callback_fires_signal_on_cancel(monkeypatch):
    """the backlog  F3 (DA fold) — signal.set() fires on the
    cancellation terminal mode. Same regression net as the exception
    variant; different task-end path."""
    import threading
    from email_triage.web import _audit

    signal = threading.Event()

    async def _slow():
        await asyncio.sleep(60)  # unreachable — we cancel first

    task = asyncio.create_task(_slow())
    _audit.attach_audit_done_callback(task, "test-signal-cancel", signal=signal)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert signal.is_set(), (
        "attach_audit_done_callback did not fire signal on cancel "
        "terminal — drain-helper wake wire regressed."
    )


@pytest.mark.asyncio
async def test_done_callback_stashes_task_cancelled(monkeypatch):
    """attach_audit_done_callback closes the pre-await-cancel hole:
    if the loop cancels the coroutine BEFORE it hits ``await
    awrite()``, the ``except BaseException`` never runs — but the
    done-callback stashes _AsyncCancelledMarker so the drain pin
    still names a class."""
    from email_triage.web import _audit

    # Bypass the coroutine body entirely — simulate a cancel BEFORE
    # the inner try/except ran, by cancelling the task before the loop
    # ever schedules it past the create_task boundary.
    async def _slow():
        await asyncio.sleep(60)  # unreachable — we cancel first

    task = asyncio.create_task(_slow())
    _audit.attach_audit_done_callback(task, "test-precancel")
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    stashed = _audit.get_last_audit_exc()
    assert stashed is not None
    exc, description, _ts = stashed
    # Marker shape: _AsyncCancelledMarker OR CancelledError — both are
    # acceptable BaseException-not-Exception classes; drain pin can
    # name either.
    assert not isinstance(exc, Exception)
    assert "test-precancel" in description or "test-precancel" in str(exc)


# ---------------------------------------------------------------------------
# Structural pin — interprocedural over both safe_audit_write bodies
# ---------------------------------------------------------------------------


_AUDIT_PY = SRC_ROOT / "web" / "_audit.py"
_TARGETS = frozenset({"safe_audit_write", "safe_audit_write_async"})


def _find_target_fns(tree):
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name in _TARGETS:
                out.append(node)
    return out


def _handler_is_baseexception(handler):
    t = handler.type
    if isinstance(t, ast.Name) and t.id == "BaseException":
        return True
    if isinstance(t, ast.Attribute) and t.attr == "BaseException":
        return True
    return False


def _body_calls_stash(handler_body):
    for sub in ast.walk(ast.Module(body=list(handler_body), type_ignores=[])):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        if isinstance(f, ast.Name) and f.id == "_stash_last_audit_exc":
            return True
        if isinstance(f, ast.Attribute) and f.attr == "_stash_last_audit_exc":
            return True
    return False


def _body_has_isinstance_exception_raise(handler_body):
    """Look for either:
    * ``if isinstance(exc, Exception): <return None>`` followed by a
      ``raise`` in the else / fall-through branch.
    * ``if not isinstance(exc, Exception): raise`` (older shape).

    Both are acceptable; the pin's job is to prevent a future edit
    that drops the raise for BaseException-not-Exception.
    """
    module = ast.Module(body=list(handler_body), type_ignores=[])
    for sub in ast.walk(module):
        if not isinstance(sub, ast.If):
            continue
        test = sub.test
        # Positive form: `if isinstance(exc, Exception):`
        is_pos = (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Name)
            and test.func.id == "isinstance"
        )
        # Negative form: `if not isinstance(exc, Exception):`
        is_neg = (
            isinstance(test, ast.UnaryOp)
            and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Call)
            and isinstance(test.operand.func, ast.Name)
            and test.operand.func.id == "isinstance"
        )
        if not (is_pos or is_neg):
            continue
        # Whichever branch corresponds to the not-Exception path must
        # contain a bare ``raise`` (re-raise the caught exc).
        module_local = ast.Module(
            body=list(sub.body) if is_neg else list(sub.orelse),
            type_ignores=[],
        )
        for inner in ast.walk(module_local):
            if isinstance(inner, ast.Raise):
                return True
        # For positive form: also accept an implicit fall-through raise
        # AFTER the if-block (final statement in the handler body).
        if is_pos:
            for stmt in handler_body:
                if isinstance(stmt, ast.Raise):
                    return True
    return False


def test_safe_audit_write_async_uses_asyncio_shield():
    """Recurrence-10 pin (2026-07-16): ``safe_audit_write_async`` MUST wrap
    the inner ``awrite()`` in :func:`asyncio.shield` so cancellation of the
    fire-and-forget wrapper task does NOT cancel the in-flight ``db_call``
    INSERT once it has been scheduled onto the threadpool. Without shield,
    a mid-flight cancel drops the HIPAA access-event row silently — the
    exact class that recurred 10× under CI xdist load
    (test_web/test_access_audit.py::test_middleware_logs_authenticated_
    phi_request drain-race). Removing shield would restore the compliance
    gap (§164.312(b) audit-integrity).
    """
    tree = parse_module(_AUDIT_PY)
    async_fn = next(
        (fn for fn in _find_target_fns(tree) if fn.name == "safe_audit_write_async"),
        None,
    )
    assert async_fn is not None, "safe_audit_write_async not found"
    found_shield = False
    for node in ast.walk(async_fn):
        if not isinstance(node, ast.Try):
            continue
        try_body_module = ast.Module(body=list(node.body), type_ignores=[])
        for sub in ast.walk(try_body_module):
            if not isinstance(sub, ast.Call):
                continue
            f = sub.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "shield"
                and isinstance(f.value, ast.Name)
                and f.value.id == "asyncio"
            ):
                found_shield = True
                break
            if isinstance(f, ast.Name) and f.id == "shield":
                found_shield = True
                break
        if found_shield:
            break
    assert found_shield, (
        "safe_audit_write_async MUST wrap the inner `awrite()` call in "
        "`asyncio.shield(...)` inside its try clause. Under the recurrence-10 "
        "fix (2026-07-16), removing shield silently restores the drain-race "
        "class where mid-flight cancel drops the HIPAA access-event row "
        "(§164.312(b) audit-integrity gap). See test_web/test_access_audit.py "
        "for the behavioural regression net."
    )


def test_both_safe_audit_write_variants_have_baseexception_stash_reraise():
    """Interprocedural pin: both wrappers preserve stash-then-reraise
    contract for cooperative-cancel classes."""
    tree = parse_module(_AUDIT_PY)
    fns = _find_target_fns(tree)
    assert len(fns) == 2, (
        f"Expected {sorted(_TARGETS)}, found {[f.name for f in fns]}"
    )
    missing_baseexc = []
    missing_stash = []
    missing_reraise = []
    for fn in fns:
        found_baseexc = False
        for node in ast.walk(fn):
            if not isinstance(node, ast.Try):
                continue
            for handler in node.handlers:
                if not _handler_is_baseexception(handler):
                    continue
                found_baseexc = True
                if not _body_calls_stash(handler.body):
                    missing_stash.append(fn.name)
                if not _body_has_isinstance_exception_raise(handler.body):
                    missing_reraise.append(fn.name)
        if not found_baseexc:
            missing_baseexc.append(fn.name)
    assert not missing_baseexc, (
        "safe_audit_write* variant(s) MUST catch BaseException (Python "
        "3.8+ asyncio.CancelledError inherits BaseException, not "
        "Exception — the whole #99 recurrence-4 root-cause):\n"
        + "\n".join(f"  - {n}" for n in missing_baseexc)
    )
    assert not missing_stash, (
        "The BaseException handler MUST call _stash_last_audit_exc so "
        "the drain-race pin can name the class:\n"
        + "\n".join(f"  - {n}" for n in missing_stash)
    )
    assert not missing_reraise, (
        "The BaseException handler MUST re-raise cooperative-cancel "
        "classes (isinstance(exc, Exception) OR not) — dropping this "
        "silently breaks task cancellation / interpreter shutdown:\n"
        + "\n".join(f"  - {n}" for n in missing_reraise)
    )
