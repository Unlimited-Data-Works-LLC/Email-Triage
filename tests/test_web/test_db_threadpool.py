"""Tests for ``email_triage.web.db_threadpool`` (#135).

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
    async def test_concurrent_calls_overlap(self):
        """Two slow helpers running through db_call should overlap on
        the threadpool — total wall time roughly max(t1, t2), not sum."""
        import time

        def _slow(secs: float) -> float:
            time.sleep(secs)
            return secs

        start = time.monotonic()
        results = await asyncio.gather(
            db_call(_slow, 0.1),
            db_call(_slow, 0.1),
            db_call(_slow, 0.1),
        )
        elapsed = time.monotonic() - start
        assert results == [0.1, 0.1, 0.1]
        # If they serialised the elapsed would be ~0.3s. With overlap
        # we expect ~0.1s; allow generous slack for CI scheduling.
        assert elapsed < 0.25, (
            f"db_call calls did not overlap (elapsed={elapsed:.3f}s)"
        )

    @pytest.mark.asyncio
    async def test_five_way_concurrency(self):
        """Five concurrent slow workers should all overlap on the pool.

        Phase 2 spec: "spawn 5 concurrent requests against a converted
        handler; assert no serialisation beyond what the underlying
        read forces". The threadpool default is min(32, os.cpu_count()
        + 4) — well above 5, so 5 calls should fan out fully.
        """
        import time

        def _slow(secs: float) -> float:
            time.sleep(secs)
            return secs

        start = time.monotonic()
        results = await asyncio.gather(*(
            db_call(_slow, 0.1) for _ in range(5)
        ))
        elapsed = time.monotonic() - start
        assert results == [0.1] * 5
        # Five serialised would be ~0.5s. With overlap we expect ~0.1s.
        assert elapsed < 0.25, (
            f"5 db_call calls did not overlap (elapsed={elapsed:.3f}s); "
            f"likely a regression to a global lock or pool=1."
        )
