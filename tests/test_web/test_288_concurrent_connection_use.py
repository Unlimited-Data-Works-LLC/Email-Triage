""" Phase 1 — Barrier(2) reproducer: concurrent shared-connection use.

Hypothesis under test
---------------------
``web/db_threadpool.db_call`` runs every dispatched call under the
process-wide DB write lock (``db_writelock``) — that's the 
serialisation. The lock is sufficient ONLY for sites that go through
``db_call``. The  hypothesis is that one or more async-reachable
sites still touch ``app.state.db`` directly (raw ``.execute(...)`` on
the shared connection) WITHOUT hopping through ``db_call`` first.

What actually fires (Phase 1 finding, 2026-05-25)
-------------------------------------------------
On modern CPython (3.13.13 / sqlite3 3.50.4, ``threadsafety=3``) the
docstring claim in ``db_threadpool.py`` §"SQLite + threading" —
``InterfaceError: bad parameter or other API misuse`` on two-thread
``.execute(...)`` overlap — DOES NOT REPRODUCE. The driver's internal
connection mutex serialises individual ``.execute()`` calls
transparently; a raw concurrent SELECT vs INSERT does NOT raise.

What DOES reproduce, deterministically, is **two overlapping
``BEGIN`` blocks on the shared connection**: SQLite's transaction
state is per-connection, and a ``BEGIN`` while ``in_transaction``
raises ``sqlite3.OperationalError: cannot start a transaction within
a transaction``. This matches the canonical hazard documented at
``src/email_triage/web/db_writelock.py`` lines 14-20.

So the production-class race the  architectural fix must rule
out is: **one writer inside ``db_call`` mid-``BEGIN…COMMIT`` AND one
unprotected async-reachable site issuing its own ``BEGIN`` on the
same connection**. The driver class is ``OperationalError``, not
``InterfaceError``.

What this test does
-------------------
Constructs the offending shape **deterministically** with
``threading.Barrier(2)``:

  * Thread W (writer): acquires the write lock via ``db_call`` and
    runs an explicit ``BEGIN … INSERT … `` block, rendezvouses at the
    barrier so the partner is provably inside its own ``BEGIN``, then
    ``COMMIT``s.
  * Thread B (bypasser): issues ``BEGIN`` directly on the SAME
    ``sqlite3.Connection`` — NO ``db_call``, NO write lock. This is
    the offending shape the  architectural fix must eliminate.

Both threads rendezvous at the barrier so the overlap is FORCED, not
wall-clock-inferred (see ``pattern_barrier_concurrency_test``). With
the barrier satisfied, the two threads are guaranteed to be inside
their ``BEGIN`` blocks simultaneously — the precondition for the
driver-level rejection.

Pass criterion
--------------
At least one of the two threads raises ``sqlite3.OperationalError``
(the canonical ``cannot start a transaction within a transaction``).
``sqlite3.InterfaceError`` / ``ProgrammingError`` are accepted too so
the assertion documents the rejection family — but the empirical
class on Python 3.11+ is ``OperationalError``. If neither side
errors, the hypothesis is REFUTED for this shape and the 
architectural-fix scope has to be re-walked.

Status of the offender in production code
-----------------------------------------
Phase 2 (AST audit) enumerates the actual unprotected sites. Phase 3
routes each one through ``db_call``. After Phase 3 the production
shape no longer constructs this race — but this test stays in tree as
the **mechanism** documentation: it builds the bad shape *locally*
(does not need any production code path) and proves the driver-level
class. A future change that re-introduces concurrent connection use
would not be caught by this test directly (no production path is
exercised here), but the AST guard in
``test_async_db_safety.py`` covers the static-completeness side.

See also
--------
- ``src/email_triage/web/db_threadpool.py`` — ``db_call``.
- ``src/email_triage/web/db_writelock.py`` — the write lock.
- ``pattern_barrier_concurrency_test.md`` — barrier-based concurrency
  assertion pattern (canonical reference: this test follows it).
"""

from __future__ import annotations

import asyncio
import sqlite3
import threading

import pytest

from email_triage.web.db_threadpool import db_call


def _fresh_conn() -> sqlite3.Connection:
    """Open a connection in the SAME shape ``init_db`` opens production.

    Matters for the reproducer because the driver's concurrent-use
    rejection behaviour depends on the connection flags — most notably
    ``check_same_thread=False``, which is what permits the cross-thread
    handoff in the first place (and what makes the race observable
    rather than caught earlier by the same-thread assertion).
    """
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        "CREATE TABLE t288 (id INTEGER PRIMARY KEY, val TEXT NOT NULL)"
    )
    conn.commit()
    # Switch to manual transaction control — the helpers under test
    # issue explicit BEGIN/COMMIT, which is exactly the shape that
    # exposes the per-connection transaction-state race.
    conn.isolation_level = None
    return conn


class TestConcurrentConnectionUse288:
    """ — concurrent use of one ``sqlite3.Connection`` from two
    threads (one inside ``db_call``, one outside) is rejected by the
    driver. This is the mechanism that flips ``/health`` and bleeds
    user-visible 500s when an async-reachable site bypasses
    ``db_call``.
    """

    @pytest.mark.asyncio
    async def test_locked_writer_vs_unlocked_begin_raises_driver_error(
        self,
    ):
        """Writer through ``db_call`` (locked, inside ``BEGIN`` block)
        + a bypasser issuing its own ``BEGIN`` on the same connection
        without ``db_call`` — the driver MUST reject the second
        ``BEGIN`` (``OperationalError: cannot start a transaction
        within a transaction``).

        Forced overlap via ``threading.Barrier(2)``: each thread
        crosses the barrier only after entering its ``BEGIN`` block,
        so the success path proves both transactions were
        simultaneously open on the same connection. The pre-fix
        assertion is that the driver class fires on at least one
        side.
        """
        conn = _fresh_conn()

        # Generous bound for the failure path only — success returns
        # immediately when both threads cross. 10s headroom for cold
        # threadpool spawn on a saturated host (see
        # pattern_barrier_concurrency_test §timeout reasoning).
        barrier = threading.Barrier(2, timeout=10.0)
        # A second sync point so the writer holds its transaction
        # open until the bypasser's BEGIN attempt has completed
        # (succeeded OR raised). Without this, post-barrier scheduling
        # can let the writer's COMMIT win the race, the connection
        # exits its transaction state, and the bypasser's BEGIN runs
        # fine — flaking the assertion. The Event makes the rejection
        # window deterministic.
        bypasser_done = threading.Event()

        # Capture exceptions from BOTH sides — either may be the one
        # the driver rejects, depending on which crosses the barrier
        # first and which call lands inside the driver's critical
        # section. ``list`` (not single var) so a race that errors
        # both sides is still observable.
        errors: list[BaseException] = []
        errors_lock = threading.Lock()

        def _record(exc: BaseException) -> None:
            with errors_lock:
                errors.append(exc)

        def _writer_sync(c: sqlite3.Connection) -> None:
            """Dispatched via ``db_call`` — runs under the write lock.

            Opens an explicit ``BEGIN``, writes, rendezvouses at the
            barrier (so the bypasser is provably inside its own
            ``BEGIN`` on the same connection), then ``COMMIT``s. The
            window between ``BEGIN`` and ``COMMIT`` is exactly when
            ``conn.in_transaction`` is true — the precondition for the
            ``cannot start a transaction within a transaction``
            rejection.
            """
            try:
                c.execute("BEGIN")
                c.execute("INSERT INTO t288 (val) VALUES ('W')")
                barrier.wait()
                # Hold the transaction open until the bypasser has
                # finished its BEGIN attempt — that is when the
                # driver's rejection fires (or does not). 5s upper
                # bound is generous; the bypasser is a 3-statement
                # block in-process. Without this wait the writer's
                # COMMIT can win the post-barrier race, the
                # transaction closes, and the bypasser's BEGIN
                # spuriously succeeds.
                bypasser_done.wait(timeout=5.0)
                c.execute("COMMIT")
            except BaseException as exc:
                _record(exc)
                # Re-raise so ``db_call`` propagates and the gather
                # ``return_exceptions=True`` surfaces it.
                raise

        def _bypasser_unlocked(c: sqlite3.Connection) -> None:
            """The offending shape: a direct ``BEGIN`` on the shared
            connection, NO ``db_call`` hop, NO write lock.

            Mirror of an async-reachable site that bypasses
            ``db_call`` (any helper that issues its own
            ``BEGIN``/``COMMIT`` block on ``app.state.db`` outside a
            ``db_call`` worker is the production form of this
            shape). Rendezvouses at the barrier first so the
            transaction-state overlap is provable; then issues
            ``BEGIN`` on the same connection the writer's transaction
            is still open on.
            """
            try:
                barrier.wait()
                try:
                    c.execute("BEGIN")
                    # If the driver let the BEGIN through (it must
                    # not), write + commit so the test does not
                    # leave a dangling transaction for the writer's
                    # COMMIT.
                    c.execute("INSERT INTO t288 (val) VALUES ('B')")
                    c.execute("COMMIT")
                finally:
                    # Signal the writer regardless of outcome — the
                    # writer's transaction must be released so the
                    # gather completes (otherwise the writer would
                    # block on the Event until the 5s timeout).
                    bypasser_done.set()
            except BaseException as exc:
                _record(exc)
                raise

        # Run both sides concurrently. The writer goes through
        # ``db_call`` (takes the lock); the reader bypasses it (no
        # lock). ``return_exceptions=True`` so a raise on either side
        # does not cancel the partner mid-rendezvous — we want both
        # sides' outcomes captured.
        loop = asyncio.get_running_loop()
        await asyncio.gather(
            db_call(_writer_sync, conn),
            loop.run_in_executor(None, _bypasser_unlocked, conn),
            return_exceptions=True,
        )

        # The hypothesis is REPRODUCED if the driver class fires on
        # at least one side. The exact class varies by which call
        # lands inside the driver's critical section first — list all
        # three so the assertion documents the rejection family.
        driver_classes = (
            sqlite3.InterfaceError,
            sqlite3.OperationalError,
            sqlite3.ProgrammingError,
        )
        assert any(isinstance(e, driver_classes) for e in errors), (
            " hypothesis NOT reproduced: expected a driver-level "
            "rejection (sqlite3.InterfaceError / OperationalError / "
            "ProgrammingError) on at least one side, got "
            f"{[type(e).__name__ for e in errors]}. If the test is "
            "green on a pre-fix tree the concurrent-connection-use "
            "mechanism may be false — re-walk the Phase 2 audit."
        )

    @pytest.mark.asyncio
    async def test_both_through_db_call_is_safe(self):
        """Control: TWO writers BOTH through ``db_call`` is safe.

        Same shape as the failing test above, except both sides take
        the write lock via ``db_call``. The lock serialises them —
        the driver never sees concurrent use, the driver class never
        fires. Establishes that the rejection above is genuinely the
        unprotected-side's fault, not a property of the shape itself.

        The barrier here would DEADLOCK under the lock (only one
        thread can be inside a ``db_call`` body at a time), so this
        control uses a small wall-clock sleep instead — it is the
        absence of the driver error class that is being asserted, not
        overlap.
        """
        conn = _fresh_conn()
        errors: list[BaseException] = []

        def _safe_writer(c: sqlite3.Connection, tag: str) -> None:
            try:
                c.execute("BEGIN")
                c.execute("INSERT INTO t288 (val) VALUES (?)", (tag,))
                # Tiny sleep so the partner has a chance to try
                # entering its db_call — proves it queues behind the
                # lock rather than colliding.
                import time
                time.sleep(0.01)
                c.execute("COMMIT")
            except BaseException as exc:
                errors.append(exc)
                raise

        await asyncio.gather(
            db_call(_safe_writer, conn, "A"),
            db_call(_safe_writer, conn, "B"),
            return_exceptions=True,
        )

        driver_classes = (
            sqlite3.InterfaceError,
            sqlite3.OperationalError,
            sqlite3.ProgrammingError,
        )
        assert not any(isinstance(e, driver_classes) for e in errors), (
            "Control failed: two ``db_call``-wrapped writers on the "
            "same connection raised a driver class — the lock is not "
            "serialising them. Investigate ``db_writelock`` before "
            "trusting the Phase 1 reproducer."
        )
        # Both writes should have landed.
        rows = conn.execute(
            "SELECT val FROM t288 ORDER BY id"
        ).fetchall()
        assert sorted(r["val"] for r in rows) == ["A", "B"]
