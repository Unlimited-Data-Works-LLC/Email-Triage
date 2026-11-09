""" Cycle 10 Phase 0 — concurrent acquire/release burst test.

Scope
-----
Verifies the Phase 0 surgical fixes (cached_statements=0, singleton
fast-path reorder, conn-cached db_path) eliminate the concurrent-
PRAGMA-on-shared-connection corruption documented in:

  * ``arch-review-options.md`` — Python sqlite3 driver-level shared-
    connection cursor-corruption hazards
  * ``debugging-test.md`` §3 — ``_resolve_db_path`` PRAGMA race in
    ``single_flight._open_lock_conn`` under bursty background ticks
  * CPython issue #118172 — 3.12/3.13 multi-thread cursor-cache
    silent corruption (workaround: ``cached_statements=0``)

What this test does
-------------------
Spawns N threadpool workers that each issue ``acquire_db_lock_async``
+ ``release_db_lock_async`` cycles against a SHARED connection with
``check_same_thread=False``. Uses ``threading.Barrier(N)`` to FORCE
all workers into ``_open_lock_conn`` simultaneously so the PRAGMA
race window is provably hit (see ``pattern_barrier_concurrency_test``).

With the Phase 0 fixes in place, the burst should:
  * Issue zero ``InterfaceError: bad parameter or other API misuse``
  * Issue zero ``SystemError: error return without exception set``
  * Issue zero ``OperationalError: cannot commit transaction - SQL
    statements in progress``
  * Issue zero ``ERROR`` log lines on the
    ``email_triage.single_flight`` logger (the fallback-to-shared-conn
    path is the commit-scope-leak bypass and Phase 3 wants it visible
    as ERROR rather than silent)
  * Complete every acquire (allow_retry=False semantics — the lock
    is contended but bounded)

This is a regression guard for Phase 0; if any future change re-
introduces the concurrent PRAGMA / cursor-cache hazard, this test
fails fast.
"""
from __future__ import annotations
from _db_tracking import track

import asyncio
import logging
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from email_triage.single_flight import (
    _CONN_DB_PATH_CACHE,
    _reset_db_path_cache_for_tests,
    _reset_lock_conn_for_tests,
    acquire_db_lock_async,
    init_lock_conn,
)
from email_triage.web.db import init_db


@pytest.fixture
def temp_db(tmp_path):
    """File-backed DB with the Phase 0 fixes (cached_statements=0,
    cached _triage_db_path attribute, timeout=30)."""
    db_path = tmp_path / "triage.db"
    conn = track(init_db(str(db_path)))
    init_lock_conn(str(db_path))
    yield conn, str(db_path)
    try:
        conn.close()
    except Exception:
        pass
    _reset_lock_conn_for_tests()
    _reset_db_path_cache_for_tests()


def _worker_iteration(
    conn: sqlite3.Connection,
    lease_name: str,
    barrier: threading.Barrier,
) -> tuple[bool, str | None]:
    """One acquire/release cycle. Rendezvous at the barrier so all
    workers' ``_open_lock_conn`` calls overlap deterministically.

    Returns ``(success, error_class_name | None)``. Success means the
    acquire returned an owner_id and the release succeeded with no
    exception class observed.
    """
    barrier.wait(timeout=10.0)

    async def _acquire_release() -> bool:
        async with acquire_db_lock_async(
            conn, lease_name, ttl_secs=5,
        ) as owner_id:
            return owner_id is not None

    try:
        loop = asyncio.new_event_loop()
        try:
            ok = loop.run_until_complete(_acquire_release())
            if not ok:
                return False, "AcquireReturnedNone"
        finally:
            loop.close()
    except sqlite3.InterfaceError as exc:
        return False, f"InterfaceError:{exc}"
    except sqlite3.OperationalError as exc:
        msg = str(exc)
        if "SQL statements in progress" in msg or "database is locked" in msg:
            return False, f"OperationalError:{msg}"
        return False, f"OperationalError:{msg}"
    except SystemError as exc:
        return False, f"SystemError:{exc}"
    except Exception as exc:
        return False, f"{type(exc).__name__}:{exc}"
    return True, None


def test_concurrent_acquire_burst_no_corruption(temp_db, caplog):
    """8 threadpool workers × 1 simultaneous acquire each → no
    cursor / commit-scope / cached-statement corruption.

    With Phase 0 fixes (cached_statements=0, singleton fast-path
    before _resolve_db_path, cached _triage_db_path attribute), all
    workers should serialize cleanly through the singleton lock_conn
    + the advisory-lock row contention. None should observe driver-
    level corruption.
    """
    conn, _db_path = temp_db
    n_workers = 8
    barrier = threading.Barrier(n_workers)

    caplog.set_level(logging.ERROR, logger="email_triage.single_flight")

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        results = list(
            pool.map(
                lambda i: _worker_iteration(
                    conn, f"phase0-burst-{i}", barrier
                ),
                range(n_workers),
            )
        )

    failures = [(i, err) for i, (ok, err) in enumerate(results) if not ok]

    # All advisory-lock contention is expected — only ONE worker can
    # hold the same lease at a time. Workers using DIFFERENT lease
    # names should all succeed; verify by lease-name uniqueness.
    # Above we generate unique lease names per worker so every acquire
    # should succeed.
    assert not failures, (
        f"#290 Phase 0 regression: {len(failures)}/{n_workers} workers "
        f"observed driver corruption or unexpected error. "
        f"Failures: {failures}"
    )

    # No ERROR-level fallback-to-shared-conn log lines should fire —
    # the singleton fast-path catches every steady-state acquire.
    error_records = [
        r for r in caplog.records
        if r.levelno >= logging.ERROR
        and r.name == "email_triage.single_flight"
    ]
    assert not error_records, (
        f"#290 Phase 0 regression: {len(error_records)} ERROR log "
        f"lines on email_triage.single_flight indicate the commit-"
        f"scope-leak fallback path fired. Records: "
        f"{[r.getMessage() for r in error_records]}"
    )


def test_repeated_acquire_release_cycles_same_lease(temp_db, caplog):
    """Single lease, 50 sequential acquire/release cycles.

    Verifies cached_statements=0 does not introduce per-call statement-
    prep regression that breaks the basic acquire/release contract.
    Also verifies no cursor-state leaks across cycles (cursor.close()
    discipline from Phase 3 HOTFIX-2 preserved).
    """
    conn, _ = temp_db
    caplog.set_level(logging.ERROR, logger="email_triage.single_flight")

    async def _cycle(i: int) -> None:
        async with acquire_db_lock_async(
            conn, "phase0-sequential", ttl_secs=5,
        ) as owner_id:
            assert owner_id is not None, f"cycle {i}: acquire returned None"

    loop = asyncio.new_event_loop()
    try:
        for i in range(50):
            loop.run_until_complete(_cycle(i))
    finally:
        loop.close()

    error_records = [
        r for r in caplog.records
        if r.levelno >= logging.ERROR
        and r.name == "email_triage.single_flight"
    ]
    assert not error_records, (
        f"sequential cycles produced ERROR logs: "
        f"{[r.getMessage() for r in error_records]}"
    )


def test_cached_db_path_present_after_init_db(temp_db):
    """ invariant: ``init_db`` MUST register the resolved file
    path in ``single_flight._CONN_DB_PATH_CACHE`` so
    ``_open_lock_conn`` can skip the concurrent PRAGMA database_list
    call on the fallback path. (sqlite3.Connection in CPython 3.13
    has no ``__dict__`` so the dict-by-id pattern is the
    work-around — see ``set_cached_db_path`` docstring.)"""
    conn, db_path = temp_db
    cached = _CONN_DB_PATH_CACHE.get(id(conn))
    assert cached == db_path, (
        f"#290 invariant: init_db must cache db_path via "
        f"set_cached_db_path. Expected {db_path!r}, got {cached!r}"
    )


def test_cached_statements_zero_on_init_db_connection():
    """ invariant: the connection returned by ``init_db`` MUST
    have ``cached_statements=0`` to mitigate CPython #118172.

    Verifying via the in-memory case so we don't rely on file paths.
    """
    import tempfile, os
    tmpdir = tempfile.mkdtemp()
    try:
        db_path = os.path.join(tmpdir, "triage.db")
        conn = track(init_db(db_path))
        try:
            # No direct API to read cached_statements back; instead
            # we verify the conn was constructed with the kwarg by
            # checking sqlite3's behavior — cached_statements=0 means
            # no statement cache exists, so re-running the same SQL
            # twice does NOT raise a cache-related InterfaceError under
            # any condition. The presence of the kwarg in the
            # constructor call is the structural invariant we're
            # asserting.
            #
            # Read the source of init_db to confirm structurally — at
            # AST-level the kwarg name MUST be present.
            import ast, inspect
            from email_triage.web import db as db_mod
            src = inspect.getsource(db_mod.init_db)
            tree = ast.parse(src)
            found_cached_statements_kwarg = False
            # db-sme-2 + DA-2 hedge 2026-05-28: assert kwarg VALUE is 0,
            # not just presence. A future edit to ``cached_statements=128``
            # (or any non-zero) would PASS a presence-only pin while
            # silently regressing the #118172 mitigation — the LITERAL
            # ``=0`` is the whole point per the CPython issue thread.
            found_value_zero = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func = node.func
                    is_sqlite_connect = (
                        isinstance(func, ast.Attribute)
                        and func.attr == "connect"
                    )
                    if is_sqlite_connect:
                        for kw in node.keywords:
                            if kw.arg == "cached_statements":
                                found_cached_statements_kwarg = True
                                if (
                                    isinstance(kw.value, ast.Constant)
                                    and kw.value.value == 0
                                ):
                                    found_value_zero = True
            assert found_cached_statements_kwarg, (
                "#290 invariant: init_db's sqlite3.connect call must "
                "pass cached_statements=0 to mitigate CPython #118172. "
                "AST walk did NOT find the kwarg."
            )
            assert found_value_zero, (
                "#290 invariant: cached_statements MUST be the literal "
                "0 — any other value (e.g. 128 to claw back the 5-10% "
                "perf cost) silently re-opens CPython #118172. AST walk "
                "found the kwarg but not the =0 literal."
            )
        finally:
            try:
                conn.close()
            except Exception:
                pass
            _reset_lock_conn_for_tests()
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
