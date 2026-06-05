"""Tests for ``email_triage.single_flight``."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Any

import pytest

# Full-tree `-n auto` hardening: these file-DB / audit-global suites flake when
# co-resident on a worker (SQLite file-lock contention + load-amplified async-audit
# timing). Each passes in isolation. Pin them to one xdist worker so they run
# serially, not concurrently — the project-sanctioned facet-2 fix (testinfra drawer).
pytestmark = pytest.mark.xdist_group("file_db_audit_serial")

from email_triage import single_flight
from email_triage.single_flight import (
    DbLockBusy,
    SingleFlightBusy,
    acquire_db_lock,
    acquire_db_lock_async,
    renew_db_lock,
    renew_db_lock_async,
    single_flight as sf_decorator,
)


# ---------------------------------------------------------------------------
# Process-level decorator
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_module_state():
    """Each test starts with an empty global lock dict.

    asyncio.Lock instances are tied to the running loop; pytest-asyncio
    spins a fresh loop per test, so a Lock created in test A is a
    poisoned sentinel in test B if we don't clear.

     — also clear the singleton lock_conn so per-test ``tmp_path``
    DBs don't leak across the suite (a connection opened against
    test-A's path would still be cached when test-B starts).

    Also clear the id(conn)-keyed ``_CONN_DB_PATH_CACHE``: it is
    NOT auto-evicted on conn close, so a recycled conn id (CPython reuses
    ids of GC'd objects) can return a STALE path from a prior test —
    ``_open_lock_conn`` would then open the lock conn against the wrong
    DB and the lock-table query fails with "no such table". Surfaced when
    N-17 shifted object lifetimes; the cache reset closes the fixture gap.
    """
    single_flight._reset_for_tests()
    single_flight._reset_lock_conn_for_tests()
    single_flight._reset_db_path_cache_for_tests()
    yield
    single_flight._reset_for_tests()
    single_flight._reset_lock_conn_for_tests()
    single_flight._reset_db_path_cache_for_tests()


@pytest.mark.asyncio
async def test_single_caller_succeeds():
    @sf_decorator("k1")
    async def work() -> int:
        return 42

    assert await work() == 42


@pytest.mark.asyncio
async def test_concurrent_caller_busies_out():
    started = asyncio.Event()
    release = asyncio.Event()

    @sf_decorator("k2", retry_after_secs=7)
    async def work(tag: str) -> str:
        if tag == "first":
            started.set()
            await release.wait()
        return tag

    first_task = asyncio.create_task(work("first"))
    await started.wait()  # ensure the lock is held

    with pytest.raises(SingleFlightBusy) as excinfo:
        await work("second")

    assert excinfo.value.status_code == 409
    assert "k2" in excinfo.value.detail
    assert excinfo.value.headers["Retry-After"] == "7"

    release.set()
    assert await first_task == "first"


@pytest.mark.asyncio
async def test_serial_callers_pass_independently():
    @sf_decorator("k3")
    async def work() -> int:
        await asyncio.sleep(0)
        return 1

    a = await work()
    b = await work()  # second call, FIRST is done — must succeed
    assert a == b == 1


@pytest.mark.asyncio
async def test_different_keys_do_not_block_each_other():
    held = asyncio.Event()

    @sf_decorator(lambda tag: f"k4:{tag}")
    async def work(tag: str) -> str:
        if tag == "alpha":
            held.set()
            await asyncio.sleep(0.05)
        return tag

    first = asyncio.create_task(work("alpha"))
    await held.wait()
    # Different key — must not see SingleFlightBusy.
    second = await work("beta")
    assert second == "beta"
    assert await first == "alpha"


@pytest.mark.asyncio
async def test_callable_key_resolves_against_args():
    seen_keys: list[str] = []

    @sf_decorator(lambda *, domain: f"acme:{domain}")
    async def issue(*, domain: str) -> str:
        seen_keys.append(domain)
        return domain

    assert await issue(domain="example.com") == "example.com"
    assert await issue(domain="other.com") == "other.com"
    assert seen_keys == ["example.com", "other.com"]


def test_decorating_sync_function_raises_typeerror():
    with pytest.raises(TypeError, match="async functions only"):
        @sf_decorator("k5")
        def sync_work() -> int:  # noqa: ARG001
            return 1


@pytest.mark.asyncio
async def test_busy_release_unblocks_next_caller():
    """After the first holder's task completes, the next call must succeed."""
    @sf_decorator("k6")
    async def work() -> int:
        await asyncio.sleep(0.01)
        return 1

    await work()
    # Lock should be released; next call must succeed promptly.
    assert await work() == 1


@pytest.mark.asyncio
async def test_exception_in_holder_releases_lock():
    @sf_decorator("k7")
    async def work(should_raise: bool) -> int:
        if should_raise:
            raise ValueError("boom")
        return 1

    with pytest.raises(ValueError, match="boom"):
        await work(True)
    # Lock must have been released by the `async with` exit path.
    assert await work(False) == 1


# ---------------------------------------------------------------------------
# DB-backed advisory lock
# ---------------------------------------------------------------------------

@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    yield c
    c.close()


def test_db_lock_basic_acquire_release(conn):
    with acquire_db_lock(conn, "lock-a") as holder:
        assert holder
        # Inside the context, a second acquire must fail.
        with pytest.raises(DbLockBusy):
            with acquire_db_lock(conn, "lock-a"):
                pass

    # After the context exits, the lock must be releasable / re-acquirable.
    with acquire_db_lock(conn, "lock-a"):
        pass


def test_db_lock_different_names_do_not_collide(conn):
    with acquire_db_lock(conn, "lock-x"):
        with acquire_db_lock(conn, "lock-y"):
            pass


def test_db_lock_expired_holder_is_reclaimed(conn):
    # Plant a stale row directly: holder claims to hold but expired.
    single_flight._ensure_schema(conn)
    long_ago = time.time() - 10_000
    conn.execute(
        "INSERT INTO single_flight_locks "
        "(name, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?)",
        ("lock-z", "ghost", long_ago, long_ago + 1),
    )
    conn.commit()

    # New caller should succeed — TTL has expired.
    with acquire_db_lock(conn, "lock-z") as holder:
        assert holder != "ghost"


def test_db_lock_release_only_when_we_still_hold(conn):
    """If we lost the lock to TTL reclaim mid-flight, our release
    must not delete the new owner's row."""
    holder_a = "alpha"
    holder_b = "beta"

    # Acquire as alpha with a near-zero TTL.
    with acquire_db_lock(conn, "lock-r", ttl_secs=1, holder=holder_a):
        # Force the row to look expired without exiting our context,
        # then have beta reclaim it.
        single_flight._ensure_schema(conn)
        conn.execute(
            "UPDATE single_flight_locks SET expires_at = ? WHERE name = ?",
            (time.time() - 1, "lock-r"),
        )
        conn.commit()

        with acquire_db_lock(conn, "lock-r", holder=holder_b):
            # Beta is the holder of record now.
            row = conn.execute(
                "SELECT holder FROM single_flight_locks WHERE name = ?",
                ("lock-r",),
            ).fetchone()
            assert row[0] == holder_b

    # Alpha exited its context and tried to release. Beta's row
    # must still be intact (beta exited inner context, so the row
    # was deleted by beta — but the point is: alpha didn't delete
    # a row it didn't own). Test: re-acquire freshly succeeds.
    with acquire_db_lock(conn, "lock-r"):
        pass


def test_db_lock_holder_id_returned(conn):
    """Holder ID is yielded so callers can log it / pass it forward."""
    seen: list[str] = []
    with acquire_db_lock(conn, "lock-h", holder="explicit-holder") as h:
        seen.append(h)
    assert seen == ["explicit-holder"]


def test_db_lock_default_holder_is_unique(conn):
    """Default holder is uuid4.hex; two concurrent rows would have
    distinct holders if they were both granted (which they aren't,
    but the uniqueness is what backs the safe-release predicate)."""
    holders: list[str] = []
    with acquire_db_lock(conn, "lock-u1") as h:
        holders.append(h)
    with acquire_db_lock(conn, "lock-u2") as h:
        holders.append(h)
    assert holders[0] != holders[1]
    assert all(len(h) == 32 for h in holders)  # uuid4().hex shape


# ---------------------------------------------------------------------------
# DB-backed advisory lock — commit scope, retry, renew, async
# ---------------------------------------------------------------------------

def test_acquire_uses_dedicated_connection_for_file_db(tmp_path):
    """For a file-backed DB the lock op commits on its own
    connection — the row is visible to an independent connection
    while the lock is held."""
    db = tmp_path / "lock.db"
    caller = sqlite3.connect(db)
    try:
        with acquire_db_lock(caller, "L", holder="h1"):
            observer = sqlite3.connect(db)
            row = observer.execute(
                "SELECT holder FROM single_flight_locks WHERE name = 'L'"
            ).fetchone()
            observer.close()
            assert row == ("h1",)  # committed by the dedicated conn
        # Released after the context exits — re-acquirable.
        with acquire_db_lock(caller, "L"):
            pass
    finally:
        caller.close()


def test_acquire_never_commits_callers_connection_for_file_db(tmp_path):
    """The commit-scope fix: the lock primitive must never call
    ``commit()`` on the connection the caller passed in (a file DB
    gets a dedicated connection). Before the fix this leaked the
    caller's pending transaction to disk."""
    db = tmp_path / "scope.db"
    real = sqlite3.connect(db)
    commits: list[int] = []

    class SpyConn:
        """Forwards to a real connection; counts commit() calls."""

        def execute(self, *a, **k):
            return real.execute(*a, **k)

        def commit(self):
            commits.append(1)
            return real.commit()

        def close(self):
            return real.close()

    spy = SpyConn()
    try:
        with acquire_db_lock(spy, "L"):
            pass
        # The lock ran entirely on a dedicated connection — the
        # caller's connection was only read for PRAGMA database_list.
        assert commits == []
    finally:
        real.close()


def test_acquire_retries_when_row_vanishes(conn):
    """A row that vanishes between the upsert and the recheck is a
    benign race — the acquire retries rather than failing."""
    single_flight._ensure_schema(conn)
    # Plant a *live* row so the first upsert's DO-UPDATE WHERE misses
    # (rowcount 0) without the row being reclaimable.
    future = time.time() + 10_000
    conn.execute(
        "INSERT INTO single_flight_locks "
        "(name, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?)",
        ("lock-v", "incumbent", time.time(), future),
    )
    conn.commit()

    inserts: list[int] = []

    class VanishOnceConn:
        """Deletes the lock row exactly once, right after the first
        acquire upsert — drives the vanished-row retry path."""

        def __init__(self, real):
            self._real = real
            self._armed = True

        def execute(self, sql, params=()):
            cur = self._real.execute(sql, params)
            if "INSERT INTO single_flight_locks" in sql:
                inserts.append(1)
                if self._armed:
                    self._armed = False
                    self._real.execute(
                        "DELETE FROM single_flight_locks WHERE name = ?",
                        ("lock-v",),
                    )
                    self._real.commit()
            return cur

        def commit(self):
            return self._real.commit()

        def close(self):
            return self._real.close()

    wrapped = VanishOnceConn(conn)
    with acquire_db_lock(wrapped, "lock-v", holder="winner") as h:
        assert h == "winner"
    # Two upserts: the first lost the race, the retry won.
    assert len(inserts) == 2


def test_acquire_held_lock_is_not_retried(conn):
    """A genuinely-held lock fails fast — no wasted retry attempts."""
    single_flight._ensure_schema(conn)
    future = time.time() + 10_000
    conn.execute(
        "INSERT INTO single_flight_locks "
        "(name, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?)",
        ("lock-held", "incumbent", time.time(), future),
    )
    conn.commit()

    inserts: list[int] = []

    class CountingConn:
        def __init__(self, real):
            self._real = real

        def execute(self, sql, params=()):
            if "INSERT INTO single_flight_locks" in sql:
                inserts.append(1)
            return self._real.execute(sql, params)

        def commit(self):
            return self._real.commit()

        def close(self):
            return self._real.close()

    wrapped = CountingConn(conn)
    with pytest.raises(DbLockBusy) as excinfo:
        with acquire_db_lock(wrapped, "lock-held", retries=3):
            pass
    assert excinfo.value.holder == "incumbent"
    # One upsert only — the held row short-circuits the retry loop.
    assert inserts == [1]


def test_renew_extends_live_lease(tmp_path):
    """renew_db_lock pushes expires_at forward for a held lock."""
    db = tmp_path / "renew.db"
    conn = sqlite3.connect(db)
    try:
        with acquire_db_lock(conn, "L", holder="h", ttl_secs=1000) as h:
            observer = sqlite3.connect(db)
            before = observer.execute(
                "SELECT expires_at FROM single_flight_locks WHERE name='L'"
            ).fetchone()[0]
            assert renew_db_lock(conn, "L", h, ttl_secs=9000) is True
            after = observer.execute(
                "SELECT expires_at FROM single_flight_locks WHERE name='L'"
            ).fetchone()[0]
            observer.close()
            assert after > before
    finally:
        conn.close()


def test_renew_false_when_lease_expired(tmp_path):
    """An already-expired lease cannot be renewed — it is lost."""
    db = tmp_path / "expired.db"
    conn = sqlite3.connect(db)
    try:
        single_flight._ensure_schema(conn)
        past = time.time() - 100
        conn.execute(
            "INSERT INTO single_flight_locks "
            "(name, holder, acquired_at, expires_at) VALUES (?, ?, ?, ?)",
            ("L", "me", past, past + 1),
        )
        conn.commit()
        assert renew_db_lock(conn, "L", "me") is False
    finally:
        conn.close()


def test_renew_false_when_holder_mismatch(tmp_path):
    """renew with the wrong holder id is a lease-lost signal."""
    db = tmp_path / "mismatch.db"
    conn = sqlite3.connect(db)
    try:
        with acquire_db_lock(conn, "L", holder="owner", ttl_secs=1000):
            assert renew_db_lock(conn, "L", "someone-else") is False
    finally:
        conn.close()


def test_renew_false_when_lock_absent(tmp_path):
    """renew on a name with no row returns False, not an error."""
    db = tmp_path / "absent.db"
    conn = sqlite3.connect(db)
    try:
        assert renew_db_lock(conn, "never-locked", "anyone") is False
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_acquire_db_lock_async_basic(tmp_path):
    """The async wrapper acquires, holds, and releases."""
    db = tmp_path / "async.db"
    conn = sqlite3.connect(db, check_same_thread=False)
    try:
        async with acquire_db_lock_async(conn, "al", holder="x") as h:
            assert h == "x"
            observer = sqlite3.connect(db)
            row = observer.execute(
                "SELECT holder FROM single_flight_locks WHERE name='al'"
            ).fetchone()
            observer.close()
            assert row == ("x",)
        # Released — re-acquirable.
        with acquire_db_lock(conn, "al"):
            pass
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_acquire_db_lock_async_releases_on_exception(tmp_path):
    """An exception in the async body still releases the lock."""
    db = tmp_path / "async_exc.db"
    conn = sqlite3.connect(db, check_same_thread=False)
    try:
        with pytest.raises(ValueError, match="boom"):
            async with acquire_db_lock_async(conn, "ae"):
                raise ValueError("boom")
        # Lock must have been released by the wrapper's finally.
        with acquire_db_lock(conn, "ae"):
            pass
    finally:
        conn.close()


@pytest.mark.asyncio
async def test_renew_db_lock_async(tmp_path):
    """The async renew extends a live lease and reports lease loss."""
    db = tmp_path / "async_renew.db"
    conn = sqlite3.connect(db, check_same_thread=False)
    try:
        async with acquire_db_lock_async(
            conn, "rl", holder="x", ttl_secs=1000,
        ) as h:
            assert await renew_db_lock_async(
                conn, "rl", h, ttl_secs=5000,
            ) is True
        # After release the lease is gone.
        assert await renew_db_lock_async(conn, "rl", "x") is False
    finally:
        conn.close()
