""" Phase 3 — verification tests for the singleton ``lock_conn`` +
defensive ROLLBACK + fallback warning log.

What this file pins
-------------------
1. ``single_flight.init_lock_conn`` is idempotent (a second call with
   the same path returns the cached connection; no second open).
2. ``acquire_db_lock`` + ``renew_db_lock`` use the singleton on a
   file-backed DB and DO NOT open a fresh connection per call (the
   pre-#288 hazard that produced the SQLITE_MISUSE startup-burst
   cascade on the test container).
3. The process-wide ``_LOCK_CONN_RLOCK`` serialises N concurrent
   threadpool workers through the singleton without raising — the
   ``threading.Barrier(N)`` pattern from
   ``pattern_barrier_concurrency_test``.
4. The ``@db_write`` decorator's Step-2 defensive ``ROLLBACK`` clears
   stuck transaction state from a contention-aborted prior helper —
   a second ``@db_write`` after a failing one does NOT raise
   ``OperationalError: cannot start a transaction within a
   transaction``.
5. The ``_open_lock_conn`` fallback warning fires (caplog at ERROR)
   when the singleton open fails — Deliverable 4 of the Phase 3
   dispatch. The warning is the bypass-visibility signal.

These tests are designed to FAIL on the pre-#288 tree (revert the
Phase 3 patches in ``single_flight.py`` / ``db_writelock.py`` and at
least the singleton-idempotence and barrier-serialisation cases
flip — confirming the patches are load-bearing).
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from email_triage.single_flight import (
    _LOCK_CONN_RLOCK,
    _open_lock_conn,
    _reset_lock_conn_for_tests,
    acquire_db_lock,
    init_lock_conn,
    renew_db_lock,
)
from email_triage.web import db_writelock
from email_triage.web.db_writelock import db_write, get_write_lock


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singleton():
    """Per-test clean slate. The singleton is process-wide so a stale
    open from a prior test would point at a stale ``tmp_path`` DB."""
    _reset_lock_conn_for_tests()
    yield
    _reset_lock_conn_for_tests()


@pytest.fixture
def file_db_path(tmp_path: Path) -> str:
    """A file-backed test DB. ``init_lock_conn`` resolves to a real
    path, mirroring the production shape (in-memory bypasses the
    singleton entirely)."""
    db_path = tmp_path / "phase3.db"
    # Touch the file so ``sqlite3.connect`` opens cleanly. The schema
    # for ``single_flight_locks`` is created by ``init_lock_conn``.
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.close()
    return str(db_path)


@pytest.fixture
def shared_conn(file_db_path: str) -> sqlite3.Connection:
    """A shared ``app.state.db``-shaped connection. Used by tests that
    need to pass a real connection into ``acquire_db_lock`` (which
    extracts the DB path from it to find the singleton)."""
    conn = sqlite3.connect(
        file_db_path, timeout=30.0, check_same_thread=False,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Deliverable 1 — singleton lock_conn
# ---------------------------------------------------------------------------

class TestSingletonLockConn:
    """The process-wide singleton replaces the pre-#288 per-call open
    pattern. These tests pin: idempotence, reuse across acquire/renew,
    and that a fresh ``sqlite3.connect`` is NOT called per lease op.
    """

    def test_init_lock_conn_returns_same_instance_on_second_call(
        self, file_db_path: str,
    ):
        a = init_lock_conn(file_db_path)
        b = init_lock_conn(file_db_path)
        assert a is b, (
            "init_lock_conn must be idempotent — a second call should "
            "return the cached connection, not open a new one"
        )

    def test_init_lock_conn_creates_schema_at_startup(
        self, file_db_path: str,
    ):
        """The lock table is created at init, not lazily per acquire.
        Pre-#288 every acquire ran CREATE TABLE IF NOT EXISTS — cheap
        but compounded the startup-burst writer-connection storm."""
        lc = init_lock_conn(file_db_path)
        rows = lc.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name='single_flight_locks'"
        ).fetchall()
        assert len(rows) == 1

    def test_open_lock_conn_returns_singleton_for_file_db(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
    ):
        """File-backed conn: ``_open_lock_conn`` returns the singleton
        with ``owns_it=False`` (caller MUST NOT close the singleton).
        Pre-#288 it returned a fresh per-call connection with
        ``owns_it=True``."""
        singleton = init_lock_conn(file_db_path)
        lock_conn, owns_it = _open_lock_conn(shared_conn)
        assert lock_conn is singleton, (
            "_open_lock_conn must return the singleton on file-backed "
            "DBs (no per-call open)"
        )
        assert owns_it is False, (
            "Caller does NOT own the singleton — closing it would "
            "break every subsequent lease op"
        )

    def test_acquire_db_lock_reuses_singleton_across_calls(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
    ):
        """Two sequential ``acquire_db_lock`` calls must reuse the
        singleton — a fresh ``sqlite3.connect`` per call is the
        startup-burst antipattern Phase 3 eliminates.

        We patch ``sqlite3.connect`` AFTER the singleton is set up so
        the count starts at zero and only counts re-opens. If the
        Phase 3 code path is correct, no extra ``connect`` calls
        happen for file-backed lease ops.
        """
        init_lock_conn(file_db_path)
        with patch("sqlite3.connect") as mock_connect:
            with acquire_db_lock(shared_conn, "test-lock-A", holder="h1"):
                pass
            with acquire_db_lock(shared_conn, "test-lock-B", holder="h2"):
                pass
            assert mock_connect.call_count == 0, (
                f"Expected zero new sqlite3.connect calls during two "
                f"sequential lease acquires (singleton reuses), got "
                f"{mock_connect.call_count}. Phase 3 fix is broken."
            )

    def test_renew_db_lock_also_reuses_singleton(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
    ):
        """``renew_db_lock`` follows the same singleton-reuse contract
        as ``acquire_db_lock``."""
        init_lock_conn(file_db_path)
        with patch("sqlite3.connect") as mock_connect:
            with acquire_db_lock(
                shared_conn, "test-renew", holder="h1",
            ) as h:
                renew_db_lock(shared_conn, "test-renew", h)
                renew_db_lock(shared_conn, "test-renew", h)
            assert mock_connect.call_count == 0


# ---------------------------------------------------------------------------
# Deliverable 1 (concurrency) — barrier-synced N-way singleton stress
# ---------------------------------------------------------------------------

class TestSingletonConcurrency:
    """The singleton is shared by all threadpool workers. The
    ``_LOCK_CONN_RLOCK`` must serialise concurrent acquires so the
    driver never sees two threads touching the singleton's pending-
    statement state at once.
    """

    def test_n_concurrent_acquires_through_singleton_succeed(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
    ):
        """N=5 threads each acquire a UNIQUE lock name via the
        singleton; barrier-synced so all N are inside the
        ``_LOCK_CONN_RLOCK.acquire()`` rendezvous at the same instant.
        With the RLock present they serialise cleanly — every acquire
        succeeds, every release writes back. Without the RLock the
        sqlite3 driver would raise SQLITE_MISUSE on the singleton's
        shared cursor state.

        Per ``pattern_barrier_concurrency_test``: structural overlap
        proof via ``threading.Barrier`` (no wall-clock timing).
        """
        init_lock_conn(file_db_path)

        N = 5
        barrier = threading.Barrier(N, timeout=10.0)
        errors: list[BaseException] = []
        errors_lock = threading.Lock()
        results: list[int] = []
        results_lock = threading.Lock()

        def _worker(idx: int) -> None:
            try:
                barrier.wait()
                with acquire_db_lock(
                    shared_conn, f"barrier-lock-{idx}", holder=f"h{idx}",
                ) as h:
                    with results_lock:
                        results.append(idx)
                    # Tiny work hold; RLock keeps it serialised.
                    pass
            except BaseException as exc:
                with errors_lock:
                    errors.append(exc)

        threads = [
            threading.Thread(target=_worker, args=(i,))
            for i in range(N)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, (
            f"Concurrent acquires through singleton raised: "
            f"{[(type(e).__name__, str(e)) for e in errors]}. The "
            f"_LOCK_CONN_RLOCK is not serialising threadpool workers."
        )
        assert sorted(results) == list(range(N)), (
            f"Expected all {N} workers to record their idx; got "
            f"{sorted(results)}"
        )


# ---------------------------------------------------------------------------
# Deliverable 2 — defensive ROLLBACK in db_write.wrapper
# ---------------------------------------------------------------------------

class TestDefensiveRollback:
    """Step-2 ``conn.execute('ROLLBACK')`` clears stuck transaction
    state that the high-level ``in_transaction`` flag misses. A
    second ``@db_write`` after a failing one must NOT raise
    "cannot start a transaction within a transaction".
    """

    def test_second_db_write_after_failing_one_succeeds(
        self, file_db_path: str,
    ):
        """Simulate the cursor-corruption-cascade head: a `@db_write`
        helper that issues an explicit ``BEGIN`` then raises before
        ``COMMIT``. Pre-#288 the wrapper's ``conn.in_transaction`` was
        already False at that point (the driver had auto-rolled the
        BEGIN on the raise, but a stepped-but-unfinalised statement
        could still hold pending state). Step-2 ROLLBACK clears it.

        Verification: a SECOND ``@db_write`` call on the same
        connection after the failing one must succeed cleanly.
        """
        conn = sqlite3.connect(file_db_path, isolation_level=None)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS t288_phase3 "
            "(id INTEGER PRIMARY KEY, v TEXT NOT NULL)"
        )

        @db_write
        def _failing(conn: sqlite3.Connection) -> None:
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO t288_phase3 (v) VALUES ('a')"
            )
            # Raise BEFORE COMMIT, leaving the connection mid-tx.
            raise RuntimeError("simulated mid-tx failure")

        @db_write
        def _follow(conn: sqlite3.Connection) -> int:
            conn.execute("BEGIN")
            cur = conn.execute(
                "INSERT INTO t288_phase3 (v) VALUES ('b')"
            )
            conn.execute("COMMIT")
            return cur.lastrowid

        with pytest.raises(RuntimeError, match="simulated"):
            _failing(conn)

        # The decisive assertion: the follow-up @db_write call must
        # not raise "cannot start a transaction within a transaction".
        # Step-2 ROLLBACK cleared the pending state.
        rowid = _follow(conn)
        assert rowid is not None and rowid > 0

        # And the successful write actually landed.
        rows = conn.execute(
            "SELECT v FROM t288_phase3 ORDER BY id"
        ).fetchall()
        assert [r[0] for r in rows] == ["b"], (
            "Step-2 ROLLBACK should have cleared the failing BEGIN's "
            "pending INSERT, leaving only the successful follow-up."
        )

        conn.close()

    def test_step2_rollback_swallows_no_active_tx_error(
        self, file_db_path: str,
    ):
        """On a CLEAN connection (no pending tx), an explicit
        ``ROLLBACK`` raises ``OperationalError: cannot rollback - no
        transaction is active``. The Step-2 code must swallow that
        specific class — it's the success case, not a real error.

        Test shape: a ``@db_write`` helper that raises on the FIRST
        statement (before any BEGIN). The wrapper's Step-1 sees
        ``in_transaction=False``, the Step-2 ROLLBACK fires against
        a clean connection, swallows the "no transaction" error, and
        the original RuntimeError propagates intact.
        """
        conn = sqlite3.connect(file_db_path)

        @db_write
        def _raise_before_any_write(conn: sqlite3.Connection) -> None:
            raise RuntimeError("simulated early failure")

        with pytest.raises(RuntimeError, match="simulated early"):
            _raise_before_any_write(conn)
        # If Step-2's OperationalError-swallow regressed, the
        # ``raise`` above would be replaced by an
        # OperationalError("no transaction is active"). The fact
        # that the original RuntimeError reached us proves the
        # swallow is correct.
        conn.close()


# ---------------------------------------------------------------------------
# Deliverable 4 — _open_lock_conn fallback warning log
# ---------------------------------------------------------------------------

class TestOpenLockConnFallbackWarning:
    """When the singleton init fails — silently dropping into the
    shared-connection fallback path is the bypass class Phase 2
    couldn't see. Deliverable 4 makes it visible: an ERROR-level log
    line names the fallback so operators can grep for it.
    """

    def test_fallback_emits_error_log_when_singleton_init_raises(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
        caplog: pytest.LogCaptureFixture,
    ):
        """Simulate a singleton-init failure (FD pressure, permissions,
        SHM corruption) and assert the ERROR log fires with the
        actionable payload.
        """
        # No singleton initialised yet — _open_lock_conn will try the
        # lazy init path. Patch ``init_lock_conn`` to raise so we hit
        # the fallback.
        with caplog.at_level(
            logging.ERROR, logger="email_triage.single_flight",
        ):
            with patch(
                "email_triage.single_flight.init_lock_conn",
                side_effect=OSError("simulated FD exhaustion"),
            ):
                lock_conn, owns_it = _open_lock_conn(shared_conn)
        # Fallback path: returns the shared conn, owns_it False.
        assert lock_conn is shared_conn
        assert owns_it is False
        # And the warning log fired with the expected marker phrase.
        assert any(
            "_open_lock_conn fell back" in rec.message
            for rec in caplog.records
        ), (
            f"Expected the Deliverable 4 fallback ERROR log, got "
            f"{[r.message for r in caplog.records]}"
        )

    def test_singleton_open_success_emits_no_warning(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
        caplog: pytest.LogCaptureFixture,
    ):
        """The happy path — singleton init succeeds — must NOT emit
        the fallback warning. False-positive coverage."""
        with caplog.at_level(
            logging.ERROR, logger="email_triage.single_flight",
        ):
            lock_conn, owns_it = _open_lock_conn(shared_conn)
        assert lock_conn is not None
        assert not any(
            "_open_lock_conn fell back" in rec.message
            for rec in caplog.records
        )


# ---------------------------------------------------------------------------
#  HOTFIX — RLock cross-thread release regression
# ---------------------------------------------------------------------------

class TestCrossThreadReleaseRegression:
    """The original Phase 3 shape held the ``_LOCK_CONN_RLOCK`` across
    ``acquire_db_lock``'s ``yield``. Under
    ``acquire_db_lock_async`` that wraps the sync generator via
    ``cm.__enter__`` + ``cm.__exit__`` each dispatched through
    ``asyncio.to_thread``, ``__enter__`` and ``__exit__`` can land
    on different threadpool workers — and ``threading.RLock`` is
    THREAD-OWNED, so the release on thread B raised
    ``RuntimeError: cannot release un-acquired lock``.

    The hotfix splits the acquire-row and release-row into two
    self-contained helpers (``_acquire_lock_row`` /
    ``_release_lock_row``), each scoping its own
    ``with _LOCK_CONN_RLOCK:`` block. Each helper's acquire+release
    runs on ONE thread (whichever thread the helper itself runs on),
    so RLock thread-ownership is satisfied regardless of which
    worker dispatches ``__enter__`` vs ``__exit__``.

    This test reproduces the bug by forcing cross-thread dispatch
    (multi-worker executor + multiple parallel async acquires) and
    asserts NO ``RuntimeError: cannot release`` errors fire.
    """

    @pytest.mark.asyncio
    async def test_async_acquire_release_across_threads_no_release_bug(
        self, file_db_path: str, shared_conn: sqlite3.Connection,
    ):
        from concurrent.futures import ThreadPoolExecutor
        from email_triage.single_flight import acquire_db_lock_async

        init_lock_conn(file_db_path)

        # Force a multi-worker executor so __enter__ + __exit__ are
        # likely to land on different threads. The default executor
        # has at least 5 workers; pinning to 4 here keeps the test
        # deterministic.
        loop = asyncio.get_running_loop()
        loop.set_default_executor(
            ThreadPoolExecutor(max_workers=4),
        )

        errors: list[tuple[str, str, str]] = []
        errors_lock = threading.Lock()

        async def _one(name: str) -> None:
            try:
                async with acquire_db_lock_async(
                    shared_conn, name, holder=f"h-{name}",
                ):
                    # Yield so the executor has every chance to land
                    # __exit__ on a different worker than __enter__.
                    await asyncio.sleep(0.02)
            except BaseException as exc:
                with errors_lock:
                    errors.append((
                        name, type(exc).__name__, str(exc),
                    ))

        # 8 parallel acquires with unique names — no two should
        # contend on the lease row, so every acquire SHOULD succeed
        # and every release SHOULD complete cleanly.
        await asyncio.gather(*(
            _one(f"async-test-{i}") for i in range(8)
        ))

        # The specific bug class: RuntimeError "cannot release
        # un-acquired lock" from RLock thread-ownership violation.
        release_bugs = [
            (n, t, m) for n, t, m in errors
            if t == "RuntimeError" and "cannot release" in m
        ]
        assert not release_bugs, (
            f" HOTFIX regression: cross-thread RLock release "
            f"bug fired in {len(release_bugs)}/{len(errors)} workers: "
            f"{release_bugs[:3]}"
        )
        # Stronger assertion: no errors AT ALL (clean run).
        # If errors fire for other reasons (FK, connection, etc.),
        # surface them so investigators know the test isn't silently
        # masking a different fault.
        assert not errors, (
            f"Unexpected errors in cross-thread acquire/release: "
            f"{errors[:5]}"
        )


# ---------------------------------------------------------------------------
#  HOTFIX-3 — Shape B first-tick startup jitter
# ---------------------------------------------------------------------------

class TestStartupJitter:
    """The ``supervised_interval_loop`` kwarg ``startup_jitter_secs``
    spreads the first-tick wave across ``[0, N)`` seconds. Phase 3
    closed the cursor-corruption cascade but the residual ``database
    is locked`` storm — ~14 background loops all firing first-tick
    ``@db_write`` writes within the same 5-10s post-warmup window —
    is the SQLite single-writer-wall behavior. Jitter spreads the
    queue so its depth never exceeds the 30s busy_timeout.

    These are mechanism-level tests: assert ``random.uniform(0, N)``
    is called and its result is the first ``asyncio.sleep`` argument.
    Wall-clock-spread tests are timing-flake-prone (per
    ``pattern_barrier_concurrency_test`` rationale).
    """

    @pytest.mark.asyncio
    async def test_startup_jitter_calls_random_uniform(self):
        from email_triage.web import task_supervisor as ts

        async def _quick_tick() -> None:
            raise asyncio.CancelledError()

        sleep_calls: list[float] = []
        uniform_calls: list[tuple[float, float]] = []
        original_uniform = ts.random.uniform

        async def _capture_sleep(secs: float) -> None:
            sleep_calls.append(secs)
            return None

        def _capture_uniform(a: float, b: float) -> float:
            uniform_calls.append((a, b))
            return original_uniform(a, b)

        with patch.object(asyncio, "sleep", _capture_sleep), \
                patch.object(ts.random, "uniform", _capture_uniform):
            try:
                await ts.supervised_interval_loop(
                    "test-jitter",
                    60,
                    _quick_tick,
                    warmup_secs=5.0,
                    startup_jitter_secs=30.0,
                )
            except asyncio.CancelledError:
                pass

        assert any(
            a == 0 and b == 30.0 for a, b in uniform_calls
        ), (
            f"Expected ``random.uniform(0, 30.0)`` call, "
            f"got {uniform_calls}"
        )
        assert len(sleep_calls) >= 2, sleep_calls
        # First sleep is the jitter draw in [0, 30); second is the
        # 5.0s warmup.
        assert 0 <= sleep_calls[0] < 30.0, sleep_calls[0]
        assert sleep_calls[1] == 5.0, sleep_calls[1]

    @pytest.mark.asyncio
    async def test_startup_jitter_zero_skips_uniform(self):
        """Default ``startup_jitter_secs=0.0`` MUST NOT call
        ``random.uniform`` — backward-compat for callers that
        don't opt in."""
        from email_triage.web import task_supervisor as ts

        async def _quick_tick() -> None:
            raise asyncio.CancelledError()

        uniform_calls: list[tuple[float, float]] = []
        original_uniform = ts.random.uniform

        def _capture_uniform(a: float, b: float) -> float:
            uniform_calls.append((a, b))
            return original_uniform(a, b)

        async def _noop_sleep(secs: float) -> None:
            return None

        with patch.object(asyncio, "sleep", _noop_sleep), \
                patch.object(ts.random, "uniform", _capture_uniform):
            try:
                await ts.supervised_interval_loop(
                    "test-no-jitter",
                    60,
                    _quick_tick,
                    warmup_secs=5.0,
                )
            except asyncio.CancelledError:
                pass

        assert uniform_calls == [], (
            f"Default startup_jitter_secs=0.0 must NOT call "
            f"random.uniform. Got: {uniform_calls}"
        )
