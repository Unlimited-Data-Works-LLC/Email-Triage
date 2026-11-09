"""Pin: a background task that FAILS during a test fails that test (punch 629 fold, panel F2a r2 item 4, r3 items 1-3).

Why this exists. The app tracks its fire-and-forget tasks in registries and drops each
one when it finishes (``task.add_done_callback(pending.discard)``):
``app.state._audit_pending`` (web/access_audit.py), ``app.state._fire_and_forget_pending``
(web/app.py, web/routers/ui/embedding_install.py) and the module-level
``_BACKUP_BG_TASKS`` of the PHI-backup router (web/routers/backup.py). The web
conftest's teardown drains read only ``task.done()``, never ``task.exception()``, so a
task that raised was already out of its registry when they looked: a failed background
task could not fail any test. A false PASS. An audit write converts its own failure into
the ``_audit._LAST_AUDIT_EXC`` stash instead, which the next test's setup cleared unread.

The root conftest's ``_a_failed_background_task_fails_the_test`` now installs a recording
registry wherever one is CREATED (any Starlette ``State``, so every app a test builds;
the backup module's set) and fails the test on a recorded failure or a non-empty audit
stash. These teeth plant tasks through the same registration shape the app uses.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from starlette.datastructures import State


def _register(registry, task) -> None:
    registry.add(task)
    task.add_done_callback(registry.discard)


def _run_to_completion(registry, *named) -> None:
    async def main() -> None:
        tasks = [asyncio.create_task(coro, name=name) for coro, name in named]
        for task in tasks:
            _register(registry, task)
        for task in tasks:
            if task.get_name() == "hang":
                task.cancel()  # cancellation is cleanup, not a failure
        await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.sleep(0)  # let the discard callbacks run

    asyncio.run(main())


async def _boom() -> None:
    raise RuntimeError("planted failure")


async def _fine() -> None:
    return None


async def _hang() -> None:
    await asyncio.sleep(30)


def test_every_app_and_state_a_test_builds_adopts_a_recorder(_a_failed_background_task_fails_the_test):
    """The registry is installed where the app creates it, so an app the test builds
    itself gets one too, and the app's ``getattr(..., None)`` reads it."""
    recorders = dict(_a_failed_background_task_fails_the_test)
    app = FastAPI()
    for name in ("_audit_pending", "_fire_and_forget_pending"):
        registry = getattr(app.state, name, None)
        assert registry is not None and type(registry).__name__ == "_FailureRecordingSet", name
        assert getattr(app.state, name) is registry, "the same recorder on every read"
        assert getattr(State(), name, None) is not registry, "each State gets its own"
    assert getattr(app.state, "some_other_attribute", None) is None, "only the registries"
    from email_triage.web.routers import backup

    assert backup._BACKUP_BG_TASKS is recorders["backup._BACKUP_BG_TASKS"]


def test_an_assigned_registry_opts_out(_a_failed_background_task_fails_the_test):
    app = FastAPI()
    own: set = set()
    app.state._fire_and_forget_pending = own
    assert app.state._fire_and_forget_pending is own


def test_a_failed_app_task_is_recorded_and_others_are_not(_a_failed_background_task_fails_the_test):
    app = FastAPI()
    registry = app.state._fire_and_forget_pending
    _run_to_completion(registry, (_boom(), "boom"), (_fine(), "fine"), (_hang(), "hang"))
    try:
        assert registry.failures() == ["boom: RuntimeError: planted failure"]
        assert not registry, "every finished task left the registry"
    finally:
        registry.failed.clear()  # the planted failure must not fail THIS test


def test_a_failed_backup_task_is_recorded(_a_failed_background_task_fails_the_test):
    """The PHI-backup path (panel F2a r3 item 1): registered the way backup.py does."""
    from email_triage.web.routers import backup

    _run_to_completion(backup._BACKUP_BG_TASKS, (_boom(), "backup-runner"))
    try:
        assert backup._BACKUP_BG_TASKS.failures() == ["backup-runner: RuntimeError: planted failure"]
    finally:
        backup._BACKUP_BG_TASKS.failed.clear()


def test_a_finished_task_whose_discard_has_not_run_is_still_read(_a_failed_background_task_fails_the_test):
    """``done()`` turns true before the loop runs the discard callback, so a drain can
    return with the failed task still registered. ``failures()`` reads it there too."""
    registry = FastAPI().state._fire_and_forget_pending

    async def main():
        task = asyncio.create_task(_boom(), name="late")
        await asyncio.gather(task, return_exceptions=True)
        return task

    task = asyncio.run(main())
    registry.add(task)  # registered; its discard callback never ran
    try:
        assert registry.failures() == ["late: RuntimeError: planted failure"]
    finally:
        registry.discard(task)
        registry.failed.clear()


def test_a_failure_followed_by_a_cancellation_is_still_seen(_a_failed_background_task_fails_the_test):
    """``_LAST_AUDIT_EXC`` keeps the last exception only, so a cancellation stashed after
    a failure would hide it (panel F2a r3 db scope note). The wrapped setter records both."""
    from email_triage.web import _audit

    stash = _audit._stash_last_audit_exc
    stash(RuntimeError("planted audit failure"), "pin:first")
    stash(asyncio.CancelledError(), "pin:second")
    try:
        assert isinstance(_audit.get_last_audit_exc()[0], asyncio.CancelledError)
        assert stash.failures() == ["_audit stash (pin:first): RuntimeError: planted audit failure"]
    finally:
        stash.stashed.clear()  # the planted failure must not fail THIS test
        _audit.clear_last_audit_exc()


def test_a_direct_assignment_to_the_stash_is_still_seen(_a_failed_background_task_fails_the_test, monkeypatch):
    """A write that bypasses the setter still lands on ``_LAST_AUDIT_EXC``, and is read there."""
    from email_triage.web import _audit

    monkeypatch.setattr(_audit, "_LAST_AUDIT_EXC", (RuntimeError("direct"), "pin:direct", 0.0))
    try:
        assert _audit._stash_last_audit_exc.failures() == [
            "_audit._LAST_AUDIT_EXC (pin:direct): RuntimeError: direct"]
    finally:
        _audit.clear_last_audit_exc()


def test_a_marker_excuses_only_its_matching_writes(_a_failed_background_task_fails_the_test):
    """``audit_failure_expected`` is keyed (panel F2a r4: db F2, devils-advocate): an
    expected failure plus an UNEXPECTED one still fails; ``count`` binds the number;
    a marker with no ``match`` excuses nothing."""
    from email_triage.web import _audit

    stash = _audit._stash_last_audit_exc
    stash(RuntimeError("expected"), "pin:expected")
    stash(RuntimeError("unexpected"), "pin:other")
    try:
        assert stash.failures(pytest.mark.audit_failure_expected(match="pin:expected").mark) == [
            "_audit stash (pin:other): RuntimeError: unexpected"]
        assert stash.failures(pytest.mark.audit_failure_expected(
            match=("pin:expected", "pin:other"), count=2).mark) == []
        assert stash.failures(pytest.mark.audit_failure_expected(
            match=("pin:expected", "pin:other"), count=1).mark) == [
            "`audit_failure_expected(count=1)` matched 2 stash(es): ['pin:expected', 'pin:other']"]
        bare = stash.failures(pytest.mark.audit_failure_expected(reason="no key").mark)
        assert len(bare) == 1 and "needs match=" in bare[0]
    finally:
        stash.stashed.clear()
        _audit.clear_last_audit_exc()


def test_a_lagging_failure_is_read_at_the_next_setup(_a_failed_background_task_fails_the_test):
    """A task that fails AFTER its test's teardown lands in a recorder nobody reads
    again (panel F2a r4 db F1). The next setup reads the prior recorders past the
    count their teardown already read."""
    from email_triage.web import _audit

    registry = FastAPI().state._fire_and_forget_pending
    late = _audit._stash_last_audit_exc.late_failures
    assert late([("prior", registry, 0)]) == []
    _run_to_completion(registry, (_boom(), "lagging"))
    try:
        assert late([("prior", registry, 0)]) == ["prior: lagging: RuntimeError: planted failure"]
        assert late([("prior", registry, 1)]) == []  # already read by its own teardown
    finally:
        registry.failed.clear()


def test_a_lagging_failure_after_the_last_test_fails_the_session(
        request, _a_failed_background_task_fails_the_test):
    """No next test reads the LAST test's late failures (devils-advocate r5 (4)), so a
    session-scoped fixture does, in the last test's teardown."""
    from email_triage.web import _audit

    assert "_a_lagging_background_failure_fails_the_session" in request.fixturenames
    registry = FastAPI().state._fire_and_forget_pending
    _run_to_completion(registry, (_boom(), "after-last"))
    try:
        with pytest.raises(pytest.fail.Exception, match="after-last"):
            _audit._stash_last_audit_exc.session_end_check([("last", registry, 0)], ())
    finally:
        registry.failed.clear()


def test_a_lagged_write_named_by_the_prior_marker_is_excused(_a_failed_background_task_fails_the_test):
    """The prior test's EXPECTED write may land after its teardown; its own marker
    excuses it at the next setup, so an innocent test does not go red on timing."""
    from email_triage.web import _audit

    late = _audit._stash_last_audit_exc.late_failures
    last = (RuntimeError("lagged"), "pin:expected-write", 0.0)
    assert late([], last) == ["_audit._LAST_AUDIT_EXC (pin:expected-write): RuntimeError: lagged"]
    assert late([], last, ("pin:expected-write",)) == []
    assert late([], last, ("pin:other",)) != []


def test_a_stash_between_tests_lands_in_the_session_list(_a_failed_background_task_fails_the_test):
    """R-a (punch 636, panel F2a r6 devils-advocate): the setter restored at this
    test's teardown is the SESSION's recorder, so a stash between tests is recorded
    in the session list, not only kept as the last one."""
    from email_triage.web import _audit

    stash = _audit._stash_last_audit_exc
    exc = RuntimeError("between tests")
    stash.between_tests(exc, "pin:gap")
    try:
        assert any(e is exc for e, _ in stash.session_stashes), (
            "the setter in place between tests does not record the stash")
    finally:
        stash.session_stashes[:] = [(e, w) for e, w in stash.session_stashes if e is not exc]
        _audit.clear_last_audit_exc()


def test_an_unexpected_lagged_failure_is_not_hidden_by_an_expected_one(_a_failed_background_task_fails_the_test):
    """R-a: an unexpected lagged failure, then the prior test's EXPECTED one. The
    last-only stash keeps the expected one, which the prior marker excuses; the
    between-tests list still names the unexpected one."""
    from email_triage.web import _audit

    late = _audit._stash_last_audit_exc.late_failures
    unexpected = RuntimeError("unexpected")
    expected = RuntimeError("expected")
    last = (expected, "pin:expected-write", 0.0)
    gap = [(unexpected, "pin:unexpected-write"), (expected, "pin:expected-write")]
    assert late([], last, ("pin:expected-write",), gap) == [
        "_audit stash between tests (pin:unexpected-write): RuntimeError: unexpected"]
    assert late([], last, ("pin:expected-write",), gap[1:]) == []
    assert late([], None, (), [(asyncio.CancelledError(), "pin:cancelled")]) == []


def test_an_unfinished_task_at_session_end_fails_the_session(_a_failed_background_task_fails_the_test):
    """R-b (punch 636): a registered task still pending after the LAST test never
    ended, so neither its write nor its loss record happened. The session check
    names it as unfinished at session end."""
    from email_triage.web import _audit

    registry = FastAPI().state._fire_and_forget_pending
    loop = asyncio.new_event_loop()
    task = loop.create_task(_hang(), name="still-running")
    try:
        loop.run_until_complete(asyncio.sleep(0))  # started, still pending
        registry.add(task)
        assert registry.unfinished() == ["still-running"]
        with pytest.raises(pytest.fail.Exception, match="unfinished at session end"):
            _audit._stash_last_audit_exc.session_end_check([("last", registry, 0)], (), [])
    finally:
        registry.discard(task)
        task.cancel()
        loop.run_until_complete(asyncio.gather(task, return_exceptions=True))
        loop.close()
    assert registry.unfinished() == []
    _audit._stash_last_audit_exc.session_end_check([("last", registry, 0)], (), [])


@pytest.mark.audit_failure_expected(
    match='pin:opt-out',
    count=1,
)
def test_a_marked_test_may_leave_the_audit_stash():
    """The opt-out: a deliberate audit-write failure, marked, passes at teardown."""
    from email_triage.web import _audit

    _audit._stash_last_audit_exc(RuntimeError("planted audit failure"), "pin:opt-out")
    assert _audit.get_last_audit_exc() is not None
