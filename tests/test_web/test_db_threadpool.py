"""Tests for ``email_triage.web.db_threadpool``.

Verifies the thin wrapper over ``asyncio.to_thread``:
- runs the sync helper on a thread pool (not the event loop)
- forwards args + kwargs unchanged
- propagates return values
- propagates exceptions
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from email_triage.web.db_threadpool import db_call


class TestDbCall:
    @pytest.mark.asyncio
    async def test_runs_off_event_loop(self):
        """The wrapped function runs on a non-main thread."""
        main_thread_id = threading.get_ident()

        def _which_thread() -> int:
            return threading.get_ident()

        worker_id = await db_call(_which_thread)
        assert worker_id != main_thread_id

    @pytest.mark.asyncio
    async def test_forwards_positional_args(self):
        def _add(a: int, b: int) -> int:
            return a + b

        assert await db_call(_add, 2, 3) == 5

    @pytest.mark.asyncio
    async def test_forwards_kwargs(self):
        def _join(a: str, *, sep: str = "-", b: str = "y") -> str:
            return a + sep + b

        assert await db_call(_join, "x", sep="|", b="z") == "x|z"

    @pytest.mark.asyncio
    async def test_propagates_return_value(self):
        def _build() -> dict:
            return {"k": "v", "n": 1}

        result = await db_call(_build)
        assert result == {"k": "v", "n": 1}

    @pytest.mark.asyncio
    async def test_propagates_exception(self):
        def _boom():
            raise ValueError("from worker")

        with pytest.raises(ValueError, match="from worker"):
            await db_call(_boom)

    @pytest.mark.asyncio
    async def test_concurrent_calls_serialise(self):
        """ — concurrent ``db_call`` invocations must NOT overlap.

        The app keeps ONE shared ``sqlite3.Connection``; the Python
        ``sqlite3`` driver rejects two threads using it concurrently
        even for reads. ``db_call`` therefore serialises every
        dispatched call through the process-wide DB lock. This test
        proves the serialisation structurally: each worker records
        whether any other worker was inside its critical section at
        the same time. With the  lock that overlap count is
        always 0; if ``db_call`` regressed to lock-free dispatch it
        would be non-zero.
        """
        in_flight = 0
        max_overlap = 0
        guard = threading.Lock()

        def _worker(n: int) -> int:
            nonlocal in_flight, max_overlap
            with guard:
                in_flight += 1
                max_overlap = max(max_overlap, in_flight)
            # Hold the section briefly so a genuine overlap would show.
            import time

            time.sleep(0.02)
            with guard:
                in_flight -= 1
            return n

        results = await asyncio.gather(*(
            db_call(_worker, n) for n in range(3)
        ))
        # gather preserves input order — also confirms arg routing.
        assert results == [0, 1, 2]
        assert max_overlap == 1, (
            f"db_call must serialise — saw {max_overlap} "
            "workers inside the shared-connection section at once"
        )

    @pytest.mark.asyncio
    async def test_db_write_helper_inside_db_call_does_not_deadlock(self):
        """ — a ``@db_write`` helper called *inside* a ``db_call``
        re-acquires the same lock instead of self-deadlocking.

        ``db_call`` now takes ``get_write_lock()`` for the dispatched
        call; ``@db_write`` takes the very same ``RLock``. Because it
        is reentrant, a decorated helper invoked from within a
        ``db_call`` body acquires the lock a second time on the same
        thread and returns normally. A plain ``Lock`` (or two distinct
        locks) would hang here until the 5s timeout trips.
        """
        from email_triage.web.db_writelock import db_write

        @db_write
        def _inner_write(x: int) -> int:
            return x * 2

        def _outer(x: int) -> int:
            # Runs under db_call's lock; calls a @db_write helper that
            # re-acquires the same RLock.
            return _inner_write(x) + 1

        result = await asyncio.wait_for(db_call(_outer, 21), timeout=5.0)
        assert result == 43
