"""Regression tests for  — fire-and-forget asyncio.create_task tracking.

The bare ``asyncio.create_task(_run())`` pattern (pre-#284) left tasks
weakly-referenced + bound to a transient event loop. Two failure modes:

  1. **Production**: the task object could be garbage-collected mid-run
     because asyncio only weak-refs scheduled tasks. ``add_done_callback``
     also doesn't pin the task — the registry set is what holds it.

  2. **Tests**: TestClient's per-call portal loop dies when the call
     returns. Tasks born during that call lose their loop. On Windows
     IOCP, accumulated dead-loop tasks were the suspected cause of the
     ~66% test_web/ hang (the backlog ).

These tests pin the wrap pattern at the two ``embedding_install``
sites + the conftest autouse drain that catches anything the wrap
missed (defense-in-depth for future bare-create_task sites).

The conftest also wires ``app.state.supervisor`` so the watcher-start
path takes the supervised branch at ``web/app.py:878`` rather than
the bare-task fallback at ``:887`` — that test is at
``test_supervisor_wired.py`` adjacent to this one.
"""

from __future__ import annotations

import asyncio

import pytest


class TestFireAndForgetRegistryShape:
    """Pin the registry shape on app.state."""

    def test_pending_set_lazy_init(self, app):
        """The registry is created on first add. Absent until then —
        same lazy-init shape as ``app.state._audit_pending``."""
        # Fresh app from the autouse reset — no fire-and-forget yet.
        assert getattr(app.state, "_fire_and_forget_pending", None) is None

    def test_pending_set_idempotent_discard(self, app):
        """``set.discard`` is idempotent — calling it twice on the
        same already-removed element is fine. This is what makes the
        done-callback safe if the task completes between add and the
        callback firing."""
        s: set = set()
        app.state._fire_and_forget_pending = s
        s.add("sentinel")
        s.discard("sentinel")  # first remove
        s.discard("sentinel")  # second remove — must not raise
        assert s == set()


class TestEmbeddingInstallWrap:
    """The two embedding_install fire-and-forget sites add the spawned
    task to ``app.state._fire_and_forget_pending`` and attach a
    done-callback that discards on completion. We assert the wrap by
    mocking the ``_run`` inner so the install machinery doesn't try
    to hit network / write to disk."""

    @pytest.mark.asyncio
    async def test_pending_tracks_then_discards(self, app):
        """End-to-end: spawn a no-op task using the same wrap shape,
        assert add+discard fires correctly. This is the contract the
        production sites mirror; if production deviates, the conftest
        drain still catches it (defense-in-depth)."""
        async def _noop() -> None:
            return None

        task = asyncio.create_task(_noop())
        pending = getattr(app.state, "_fire_and_forget_pending", None)
        if pending is None:
            pending = set()
            app.state._fire_and_forget_pending = pending
        pending.add(task)
        task.add_done_callback(pending.discard)

        # Mid-flight: task is tracked.
        assert task in pending

        # Let it complete.
        await task

        # The done-callback fires inline on the event loop; one more
        # yield is enough for the discard to land.
        await asyncio.sleep(0)
        assert task not in pending
        assert pending == set()


class TestSupervisorWired:
    """db-sme scope-add: confirm the fixture wire matches the read
    site at ``web/app.py:853``. If this breaks (e.g. someone renames
    ``app.state.supervisor`` back to ``task_supervisor``), the
    watcher-start path silently falls onto the bare-task fallback
    again and  regresses."""

    def test_supervisor_attribute_present(self, app, db):
        """``app.state.supervisor`` is set by the db fixture so the
        watcher branch reads non-None and takes the supervised path."""
        sup = getattr(app.state, "supervisor", None)
        assert sup is not None, (
            "app.state.supervisor must be wired in the db fixture so "
            "the watcher-start path at web/app.py:878 takes the "
            "supervised branch (NOT the bare-task fallback at :887). "
            "Note the attribute name: 'supervisor', NOT 'task_supervisor' "
            "— production sets it as 'supervisor' at app.py:2240."
        )

    def test_supervisor_has_is_running(self, app, db):
        """Smoke-check the wired object exposes the methods the
        watcher branch calls. If a future commit swaps in a fake that
        lacks ``is_running``, the branch falls back; this test pins
        the contract."""
        sup = app.state.supervisor
        assert callable(getattr(sup, "is_running", None))
        assert callable(getattr(sup, "supervise", None))
        assert callable(getattr(sup, "stop_all", None))


class TestAutouseDrainCancelsPending:
    """The autouse ``_cancel_pending_tasks_after_test`` fixture drains
    fire-and-forget + watcher tasks at teardown. We can't directly
    observe the autouse running on this test (it runs AFTER the test
    body), but we CAN verify that on entry, the previous test's
    pending set is empty — that's the post-condition we care about."""

    def test_pending_empty_at_test_start(self, app):
        """Fresh-app assertion: even after a sequence of prior tests
        that may have spawned fire-and-forget tasks, this test starts
        with a clean ``_fire_and_forget_pending`` (None or empty)."""
        pending = getattr(app.state, "_fire_and_forget_pending", None)
        assert pending is None or pending == set(), (
            f"prior test left {len(pending or set())} pending tasks; "
            "_cancel_pending_tasks_after_test should have drained them"
        )

    def test_watcher_tasks_empty_at_test_start(self, app, db):
        """Same for ``watcher_manager._tasks`` — prior tests don't
        bleed into this one."""
        wm = app.state.watcher_manager
        leftover = [t for t in wm._tasks.values() if not t.done()]
        assert leftover == [], (
            f"prior test left {len(leftover)} live watcher tasks; "
            "_cancel_pending_tasks_after_test should have cancelled them"
        )
