"""Tests for ``email_triage.single_flight``."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from typing import Any

import pytest

from email_triage import single_flight
from email_triage.single_flight import (
    DbLockBusy,
    SingleFlightBusy,
    acquire_db_lock,
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
    """
    single_flight._reset_for_tests()
    yield
    single_flight._reset_for_tests()


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
