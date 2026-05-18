"""Single-flight primitives — process-level + cross-process advisory locks.

Two surfaces, one module:

1. ``@single_flight(key)`` decorator. Process-level mutex via an
   ``asyncio.Lock`` per key. The second concurrent caller for the
   same key gets ``SingleFlightBusy`` (subclass of
   ``HTTPException(409)``) — explicit failure, **not** silent
   serialisation. An operator who clicks "Issue Now" while the 24h
   ACME tick is mid-flight gets a clean "issuance already in
   progress" toast, not a silently-queued second issuance that
   double-orders against Let's Encrypt three minutes later.

2. ``acquire_db_lock(conn, name, ttl_secs)`` context manager.
   SQLite-backed advisory lock keyed by name. TTL defends against
   crashed holders (lock auto-expires); released cleanly in the
   ``__exit__`` path. Survives a process restart, which the
   process-level lock cannot. Used by callers that touch external
   resources where a mid-flight crash + restart must not let a
   second instance double-act (ACME issuance is the canonical
   case — DNS provider credentials can't be replayed safely).

Design: the in-process decorator is the default — fast, no DB
round trip. The DB-backed lock is opt-in for the few call sites
that need restart safety. ``ratelimit.TokenBucket`` already uses
the same in-process Lock + dict-of-keys pattern; this module
generalises it.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Awaitable, Callable, Iterator, TypeVar

from fastapi import HTTPException


# ---------------------------------------------------------------------------
# Process-level single-flight
# ---------------------------------------------------------------------------

class SingleFlightBusy(HTTPException):
    """Raised when a second concurrent caller hits a single-flight key.

    Subclasses ``HTTPException(409)`` so FastAPI surfaces it directly
    to the UI without extra boilerplate. Carries ``Retry-After`` so a
    well-behaved client knows roughly how long to wait. The header
    value is a hint, not a guarantee — actual completion time depends
    on whatever the holder is doing (ACME issuance can take minutes).
    """

    def __init__(self, key: str, *, retry_after_secs: int = 30) -> None:
        super().__init__(
            status_code=409,
            detail=f"single_flight_busy: {key}",
            headers={"Retry-After": str(max(1, int(retry_after_secs)))},
        )
        self.single_flight_key = key


# Module-level dict of asyncio.Locks. One lock per key.
_locks: dict[str, asyncio.Lock] = {}
# Guards mutation of `_locks` itself (not the per-key locks).
_locks_dict_lock = asyncio.Lock()


async def _get_or_create_lock(key: str) -> asyncio.Lock:
    """Atomic get-or-create for the key's lock."""
    async with _locks_dict_lock:
        lock = _locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _locks[key] = lock
        return lock


F = TypeVar("F", bound=Callable[..., Awaitable[Any]])


def single_flight(
    key: str | Callable[..., str],
    *,
    retry_after_secs: int = 30,
) -> Callable[[F], F]:
    """Decorator: refuse a second concurrent call for the same key.

    ``key`` may be a literal string (one global key for the wrapped
    function) or a callable that receives the same args/kwargs as
    the wrapped function and returns the key string. The latter is
    the "per-domain ACME" shape — ``key=lambda self, **kw: f"acme:{kw['directory_url']}"``.

    Usage::

        @single_flight("acme_issue")
        async def issue_now(...): ...

        @single_flight(lambda self, **kw: f"acme:{self.cfg.domains[0]}")
        async def issue_now(self, ...): ...

    Wrapping a sync function is a deliberate type error — single-flight
    only makes sense around awaitable units of work. Sync callers
    should restructure (typically: wrap their blocking call in
    ``asyncio.to_thread`` and put the decorator on the async wrapper).
    """

    def decorator(func: F) -> F:
        if not inspect.iscoroutinefunction(func):
            raise TypeError(
                f"@single_flight wraps async functions only; "
                f"{func.__qualname__} is sync"
            )

        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            resolved_key = key(*args, **kwargs) if callable(key) else key
            lock = await _get_or_create_lock(resolved_key)
            if lock.locked():
                # Second concurrent caller — fail fast rather than
                # await. Caller (UI, scheduler) decides whether to
                # retry; we don't queue.
                raise SingleFlightBusy(
                    resolved_key, retry_after_secs=retry_after_secs,
                )
            async with lock:
                return await func(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def _reset_for_tests() -> None:
    """Clear the module-level lock dict.

    Tests spawn many short-lived asyncio loops; per-loop Lock
    instances become invalid when the loop closes. Tests call this
    in a fixture teardown to keep the global dict from carrying
    stale Locks from a prior loop.
    """
    _locks.clear()


# ---------------------------------------------------------------------------
# DB-backed advisory lock
# ---------------------------------------------------------------------------

# Schema is created on first use rather than via init_db so this
# module stays usable independent of the web layer (CLI / tests can
# import it without booting init_db). The CREATE is idempotent.
_DB_LOCK_DDL = """
CREATE TABLE IF NOT EXISTS single_flight_locks (
    name        TEXT PRIMARY KEY,
    holder      TEXT NOT NULL,
    acquired_at REAL NOT NULL,
    expires_at  REAL NOT NULL
)
"""


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.execute(_DB_LOCK_DDL)
    conn.commit()


class DbLockBusy(Exception):
    """Raised when ``acquire_db_lock`` cannot get the lock.

    Distinct from ``SingleFlightBusy`` because DB-backed locks are
    used by both HTTP handlers (where 409 is right) and background
    tasks (where a 409 makes no sense — the task just logs and
    skips this tick). Caller wraps in the right shape.
    """

    def __init__(self, name: str, holder: str, expires_at: float) -> None:
        super().__init__(
            f"db lock {name!r} held by {holder!r} until {expires_at}"
        )
        self.name = name
        self.holder = holder
        self.expires_at = expires_at


@contextmanager
def acquire_db_lock(
    conn: sqlite3.Connection,
    name: str,
    *,
    ttl_secs: int = 1800,
    holder: str | None = None,
) -> Iterator[str]:
    """Acquire a SQLite-backed advisory lock named ``name``.

    Yields the holder ID (UUID4 hex by default; can be passed in for
    deterministic tests / logs). Releases on context exit even if the
    body raises. If a prior holder crashed without releasing, the
    TTL-expiry check below treats the row as reclaimable.

    Atomicity: the acquire path is an INSERT ... ON CONFLICT DO
    UPDATE that only updates when the existing row's expires_at is
    in the past. SQLite's per-statement atomicity guarantees no
    other process will see a half-written row.

    Use this when a process restart must not allow a second instance
    to double-act. Cross-process safety; in-process safety is also
    covered (since the same row blocks every caller).
    """
    holder_id = holder or uuid.uuid4().hex
    _ensure_schema(conn)

    now = time.time()
    expires = now + max(1, int(ttl_secs))

    # Single-statement acquire: insert if absent, OR update only when
    # the prior row is past its TTL. The ``WHERE`` on the DO UPDATE
    # is the key — it keeps a live holder from being silently bumped
    # by a fresh caller.
    cur = conn.execute(
        """
        INSERT INTO single_flight_locks (name, holder, acquired_at, expires_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            holder      = excluded.holder,
            acquired_at = excluded.acquired_at,
            expires_at  = excluded.expires_at
        WHERE single_flight_locks.expires_at < ?
        """,
        (name, holder_id, now, expires, now),
    )
    conn.commit()

    if cur.rowcount == 0:
        # Either insert-on-conflict skipped (row exists, still live)
        # or the update predicate didn't match. Either way, we don't
        # hold it.
        row = conn.execute(
            "SELECT holder, expires_at FROM single_flight_locks WHERE name = ?",
            (name,),
        ).fetchone()
        if row is not None:
            existing_holder, existing_expires = row[0], row[1]
            raise DbLockBusy(name, existing_holder, existing_expires)
        # Theoretical race: row vanished between our INSERT failing
        # and our SELECT. Retry once; if that also fails the caller
        # gets the exception.
        raise DbLockBusy(name, "<vanished>", now)

    try:
        yield holder_id
    finally:
        # Release only if we still hold it. A holder whose TTL
        # expired and was reclaimed by someone else must not delete
        # the new owner's row.
        try:
            conn.execute(
                "DELETE FROM single_flight_locks "
                "WHERE name = ? AND holder = ?",
                (name, holder_id),
            )
            conn.commit()
        except Exception:
            # Release failures don't break the caller — the TTL
            # will reclaim the row eventually. Log via caller's
            # exception handler if they care.
            pass
