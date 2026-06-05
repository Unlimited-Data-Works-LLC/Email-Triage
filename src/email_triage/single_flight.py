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

2. ``acquire_db_lock(conn, name, ttl_secs)`` context manager —
   SQLite-backed advisory lock / lease keyed by name. The TTL
   defends against crashed holders (the lock auto-expires and the
   next caller reclaims it); a clean context exit releases it.
   Survives a process restart, which the process-level lock cannot.

   Long-running holders extend their lease with ``renew_db_lock``;
   a renew that returns ``False`` is a first-class "lease lost"
   signal. ``acquire_db_lock_async`` / ``renew_db_lock_async`` are
   threadpool-wrapped forms so an ``async`` background loop never
   blocks the event loop on the SQLite ``commit()``. On a
   file-backed DB the lock runs on a **dedicated** connection, so
   its ``commit()`` never flushes unrelated work pending on the
   shared app connection.

   Used where a mid-flight crash + restart must not let a second
   instance double-act — ACME issuance is the canonical case (DNS
   provider credentials can't be replayed safely), and it is the
   leader-election / per-account leasing primitive the eventual
   multi-instance design leans on.

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
import logging
import sqlite3
import threading
import time
import uuid
from contextlib import asynccontextmanager, contextmanager
from typing import (
    Any,
    AsyncIterator,
    Awaitable,
    Callable,
    Iterator,
    TypeVar,
)

from fastapi import HTTPException


_log = logging.getLogger(__name__)


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

# busy_timeout for the dedicated lock connection. Pre-#288 this was
# 5000 (5s) — narrower than the contention burst at container startup
# (~12 background-loop first ticks + Gmail push consumer all firing
# in the same ~30s window).  raises it to 30000 (30s) to match
# ``init_db``'s PRAGMA; the singleton (below) means we no longer pay
# the per-tick re-open cost so a longer wait is fine. Old constant
# kept for the in-memory fallback path that still does per-call open.
_LOCK_CONN_BUSY_TIMEOUT_MS = 30000


# ---------------------------------------------------------------------------
#  — process-wide singleton lock_conn
# ---------------------------------------------------------------------------
#
# Pre-#288 every ``acquire_db_lock`` / ``renew_db_lock`` call opened a
# NEW dedicated ``sqlite3.Connection`` against ``triage.db``. With ~12
# background interval loops each leasing once per tick (plus
# Gmail-push setup writes on top), this produced dozens of fresh
# writer-connection lifecycles against the same WAL DB file in tight
# bursts, especially at container startup. The driver-level result —
# captured live on the test container during the 2026-05-25 investigation —
# is a cascade of SQLITE_MISUSE / "no transaction is active" /
# "cannot start a transaction within a transaction" / "cannot commit
# transaction - SQL statements in progress" / "another row available"
# errors on ``lock_conn``, all originating at
# ``single_flight.acquire_db_lock`` lines 324 (INSERT) and 337
# (commit).
#
# The fix: ONE dedicated lock_conn per process, opened at app
# startup via ``init_lock_conn(db_path)`` and reused by every
# lease op. A process-wide ``threading.RLock`` (mirroring
# ``db_writelock.get_write_lock()``'s shape) serialises every lease
# op so even concurrent threadpool workers can never trip the driver
# into a half-state. ``RLock`` (not plain ``Lock``) so a nested
# ``renew_db_lock`` inside an ``acquire_db_lock`` body on the same
# thread does not self-deadlock.
#
# ``init_lock_conn`` is called from the FastAPI lifespan startup
# (web/app.py) right after ``init_db`` opens the shared connection.
# Tests can call it too; ``_reset_lock_conn_for_tests`` clears the
# singleton between fixtures so a per-test ``:memory:`` DB does not
# leak across the suite.

_LOCK_CONN: sqlite3.Connection | None = None
_LOCK_CONN_RLOCK = threading.RLock()


def init_lock_conn(db_path: str) -> sqlite3.Connection:
    """Open (or return existing) the process-wide dedicated lock_conn.

    Idempotent: a second call with the same ``db_path`` returns the
    cached connection without re-opening. A call with a different
    ``db_path`` after one was already initialised is a programmer
    error and raises — the singleton's lifecycle is one connection
    per process, not per-DB.

    For ``:memory:`` / empty-string path callers, the singleton is
    NOT set — every in-memory DB requires reusing the caller's own
    connection (a second connection would be a different empty
    database). Callers should detect this case via
    :func:`_resolve_db_path` and skip ``init_lock_conn``.
    """
    global _LOCK_CONN
    with _LOCK_CONN_RLOCK:
        if _LOCK_CONN is not None:
            # Already initialised. Quiet idempotence is fine — the
            # web app may call this multiple times across reloads in
            # dev mode.
            return _LOCK_CONN
        # N-17: route through the encrypted-aware shared opener so the
        #  write-lock conn opens against an ENCRYPTED file on an
        # encrypted install. Before N-17 this did a raw plaintext
        # sqlite3.connect: on an encrypted DB the _DB_LOCK_DDL below would
        # fail, ``_open_lock_conn`` would hit its except-fallback, and the
        # process would SILENTLY lose the dedicated lock conn's
        # commit-scope isolation — worse than a crash because a
        # /health 200 won't reveal it.
        #
        # open_dedicated_conn applies the same WAL + busy_timeout=30000
        # (== _LOCK_CONN_BUSY_TIMEOUT_MS) + foreign_keys=ON + cached_
        # statements=0 this site set inline.
        # The lock conn needs NO row_factory (raw column reads only), so
        # apply_compatible_row_factory is intentionally NOT called here.
        from email_triage.db._engine import open_dedicated_conn
        lock_conn = open_dedicated_conn(db_path, check_same_thread=False)
        # Eagerly create the lock table — the prior per-call shape
        # ran CREATE TABLE IF NOT EXISTS on every acquire (cheap but
        # noisy in the burst). Doing it once at startup means every
        # subsequent acquire/release skips the schema step.
        lock_conn.execute(_DB_LOCK_DDL)
        lock_conn.commit()
        _LOCK_CONN = lock_conn
        return lock_conn


def _reset_lock_conn_for_tests() -> None:
    """Close + clear the singleton. Per-test fixture teardown only.

    Tests open per-test ``:memory:`` or per-test temp-file DBs; the
    singleton must not leak the prior test's connection across to
    the next. Mirrors ``_reset_for_tests`` for the asyncio Lock dict
    above.
    """
    global _LOCK_CONN
    with _LOCK_CONN_RLOCK:
        if _LOCK_CONN is not None:
            try:
                _LOCK_CONN.close()
            except Exception:
                pass
            _LOCK_CONN = None


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Idempotent CREATE TABLE — used only by the in-memory fallback
    path (the singleton creates the table once at ``init_lock_conn``).

    The file-backed path no longer calls this on every acquire — the
    table is created once at startup. Keeping the helper so the
    in-memory edge case (where the caller's own connection IS the
    lock_conn) still gets the schema set up lazily on first use.
    """
    conn.execute(_DB_LOCK_DDL)
    conn.commit()


#  Cycle 10 Phase 0: cache of resolved DB paths keyed by id(conn).
#
# Used by ``_open_lock_conn`` to skip the concurrent
# ``PRAGMA database_list`` call on the shared connection (the
# corruption surface documented in ``debugging-test.md`` §3).
# ``init_db`` populates this on connection-open via
# :func:`set_cached_db_path`. ``id(conn)`` is stable for the conn's
# lifetime + Python does not reuse the id while the object is alive,
# so cleanup on close is not strictly required — but tests that
# create + close many connections in a tight loop can call
# :func:`_reset_db_path_cache_for_tests`.
#
# Rationale for ``id(conn)`` keying: ``sqlite3.Connection`` in
# CPython 3.13 silently rejects ``setattr(conn, "...", ...)`` — the
# write returns but the attribute does not stick. This is documented
# at https://docs.python.org/3/library/sqlite3.html#sqlite3.Connection
# (the class does not define ``__dict__``). The dict-by-id pattern
# is the standard work-around for adding metadata to C-extension
# objects that lack ``__dict__``.
_CONN_DB_PATH_CACHE: dict[int, str] = {}


def set_cached_db_path(conn: sqlite3.Connection, db_path: str) -> None:
    """Register the resolved file path for ``conn`` so
    :func:`_open_lock_conn` can skip the ``PRAGMA database_list``
    race in :func:`_resolve_db_path`."""
    _CONN_DB_PATH_CACHE[id(conn)] = db_path


def _reset_db_path_cache_for_tests() -> None:
    """Per-test fixture teardown. Clears the id(conn)-keyed cache so
    a recycled connection id from a new sqlite3.connect() call does
    not return a stale path from a previously-closed conn."""
    _CONN_DB_PATH_CACHE.clear()


def _resolve_db_path(conn: sqlite3.Connection) -> str | None:
    """Return the file path of ``conn``'s main database.

    ``None`` means in-memory / anonymous-temp (``:memory:`` or the
    empty-string path) — there is no file a second connection could
    attach to, so the lock ops must reuse the passed connection.
    """
    try:
        for _seq, db_name, file in conn.execute("PRAGMA database_list"):
            if db_name == "main":
                return file if file and file != ":memory:" else None
    except Exception:
        return None
    return None


def _open_lock_conn(
    conn: sqlite3.Connection,
) -> tuple[sqlite3.Connection, bool]:
    """Return ``(lock_conn, owns_it)`` for DB-lock operations.

     (post): for a file-backed DB this returns the process-wide
    singleton ``_LOCK_CONN`` opened at startup via
    :func:`init_lock_conn`. ``owns_it`` is False — the lifespan owns
    the singleton, the caller must NOT close it. Pre-#288 this
    opened a fresh connection per call; that produced dozens of
    short-lived writer connections against the same WAL file at
    startup (see module-level commentary above) which the SQLite
    driver could not always serialise cleanly.

    If the singleton has not been initialised (test fixture that
    skipped startup wiring, CLI entry that doesn't boot the
    lifespan), :func:`init_lock_conn` is called now using the path
    resolved from ``conn``. This is best-effort: if the lazy init
    itself raises (permissions, FD pressure), the function falls
    back to the shared ``conn`` and logs an ERROR — that fallback IS
    a commit-scope-leak bypass and Phase 3 wants it visible in logs
    rather than silent.

    For an in-memory DB a second connection would be a *different*
    empty database, so the passed connection is reused (``owns_it``
    False — caller owns it, do not close it).

     Cycle 10 Phase 0 reorder: the singleton fast-path now runs
    BEFORE ``_resolve_db_path(conn)`` so the steady-state acquire
    skips the ``PRAGMA database_list`` call on the shared connection
    entirely. Concurrent PRAGMA execution on the same conn under
    ``check_same_thread=False`` is a documented driver-corruption
    surface (see ``debugging-test.md`` §3) — eliminating the call on
    the hot path eliminates the race. The path-resolution branch
    only runs on the fallback / lazy-init code path which is rare
    in production.

    Plus: if ``init_db`` registered the resolved path via
    :func:`set_cached_db_path`, the fallback path skips
    ``PRAGMA database_list`` entirely too. The cache uses
    ``id(conn)``-keying because ``sqlite3.Connection`` in CPython
    3.13 has no ``__dict__`` — ``setattr`` on the conn silently
    rejects.
    """
    # Fast path: singleton already initialised. Most production
    # acquires hit this branch and skip every PRAGMA / lock.
    with _LOCK_CONN_RLOCK:
        if _LOCK_CONN is not None:
            return _LOCK_CONN, False

    # Cached path on conn — set by init_db via
    # :func:`set_cached_db_path`, eliminates the PRAGMA database_list
    # race when the singleton has not been eagerly initialised (test
    # fixture / CLI entry path).
    cached_path = _CONN_DB_PATH_CACHE.get(id(conn), Ellipsis)
    if cached_path is not Ellipsis:
        db_path = cached_path
    else:
        db_path = _resolve_db_path(conn)
    if db_path is None:
        # In-memory / anonymous-temp — reuse the caller's connection.
        return conn, False

    # Lazy-init path: lifespan didn't call ``init_lock_conn`` (test
    # fixture / CLI / migration runner). Try to open one now.
    try:
        return init_lock_conn(db_path), False
    except Exception as exc:
        # Dedicated singleton init failed (permissions, FD pressure,
        # SHM corruption). Fall back to the shared connection —
        # degraded (commit-scope leak) but functional; a broken lock
        # primitive is the worse outcome. : log this so the
        # bypass is visible in container logs rather than silent.
        # Operator may need to investigate the underlying open
        # failure separately.
        _log.error(
            "_open_lock_conn fell back to shared connection — "
            "commit-scope leak active. The lock primitive "
            "will write to the shared app connection, which can "
            "interleave with @db_write operations and corrupt cursor "
            "state. Investigate the underlying open failure.",
            extra={"_extra": {
                "db_path": db_path,
                "exc_type": type(exc).__name__,
                "exc_msg": str(exc),
            }},
        )
        return conn, False


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
    retries: int = 1,
) -> Iterator[str]:
    """Acquire a SQLite-backed advisory lock named ``name``.

    Yields the holder ID (UUID4 hex by default; pass ``holder`` for a
    deterministic id in tests / logs). Releases on context exit even
    if the body raises. A prior holder that crashed without releasing
    is reclaimed once its TTL has elapsed.

    ``retries`` — if the acquire loses a benign race (the row vanished
    between the upsert and the recheck) it retries that many times. A
    row that is *genuinely held* is never retried — the caller gets
    ``DbLockBusy`` immediately.

    Commit scope: for a file-backed DB the acquire/release run on a
    **dedicated** connection, so the lock's ``commit()`` never flushes
    unrelated work pending on the shared app connection. In-memory
    DBs reuse the passed connection (a second connection would be a
    different database). See ``_open_lock_conn`` for the
    not-mid-transaction contract.

    Long-running holders should call :func:`renew_db_lock` (or
    :func:`renew_db_lock_async`) periodically — set ``ttl_secs`` to a
    small multiple of the renew interval so a crashed holder is
    reclaimed promptly rather than after a worst-case-job-length TTL.

    Use this when a process restart must not allow a second instance
    to double-act. Cross-process safe; in-process safe too (the row
    blocks every caller).
    """
    holder_id = holder or uuid.uuid4().hex
    lock_conn, owns_conn = _open_lock_conn(conn)
    try:
        #  HOTFIX — acquire-row + release-row are split into two
        # self-contained helpers, each scoping its own
        # ``with _LOCK_CONN_RLOCK:`` block. The earlier shape (one
        # ``acquire()`` before the ``yield`` + one ``release()`` in
        # the outer ``finally``) crashed with ``RuntimeError: cannot
        # release un-acquired lock`` under the async wrapper
        # ``acquire_db_lock_async``: ``threading.RLock`` is THREAD-
        # OWNED, but ``cm.__enter__`` runs on threadpool worker A
        # via ``asyncio.to_thread`` while ``cm.__exit__`` (which
        # walks the post-yield finally) runs on threadpool worker B.
        # B's ``release()`` on a lock A holds raises.
        #
        # Splitting into two helpers means each helper takes+releases
        # the RLock on its OWN thread — the contract RLock requires.
        # The lock still serialises every lease op across the
        # singleton because both helpers contend for the same RLock,
        # just no longer holding it across the yield boundary.
        _acquire_lock_row(lock_conn, name, holder_id, ttl_secs, retries)
        try:
            yield holder_id
        finally:
            _release_lock_row(lock_conn, name, holder_id)
    finally:
        # Close the per-call connection only if we opened one (the
        # in-memory edge case or the fallback path). NEVER close the
        # singleton.
        if owns_conn:
            try:
                lock_conn.close()
            except Exception:
                pass


def _acquire_lock_row(
    lock_conn: sqlite3.Connection,
    name: str,
    holder_id: str,
    ttl_secs: int,
    retries: int,
) -> None:
    """Insert (or take-over-stale) the lease row. Self-contained
    lock-acquire+release on the calling thread ( HOTFIX —
    splits the prior generator-spanning lock so RLock thread-
    ownership is satisfied).

    Raises :class:`DbLockBusy` if the lock is genuinely held by
    another holder; the caller propagates that up through the
    context-manager protocol.
    """
    # SW-1 (2026-05-31): also hold the  process-wide write lock so this
    # dedicated lease conn never holds the WAL write-lock concurrently with the
    # main conn under SQLCipher (the INCIDENT-1 cross-conn contention class).
    # Order is ALWAYS  -> _LOCK_CONN_RLOCK (the writer thread holds only
    # ; nothing takes _LOCK_CONN_RLOCK then ) -> no lock inversion.
    from email_triage.web.db_writelock import get_write_lock
    with get_write_lock(), _LOCK_CONN_RLOCK:
        # Singleton path: schema is created once at ``init_lock_conn``.
        # Only the fallback / in-memory edge case needs lazy CREATE.
        if lock_conn is not _LOCK_CONN:
            _ensure_schema(lock_conn)
        attempts = 1 + max(0, int(retries))
        last_now = time.time()
        acquired = False
        for _attempt in range(attempts):
            now = time.time()
            last_now = now
            expires = now + max(1, int(ttl_secs))
            #  HOTFIX-2 — close every cursor explicitly before
            # releasing the RLock. Python's stdlib sqlite3 keeps the
            # underlying C-level prepared statement alive while the
            # ``Cursor`` python object is alive; locals stay alive
            # until the function returns / GC runs. With the prior
            # generator-spanning RLock held across yield this didn't
            # surface; with the split-helper shape the RLock is
            # released here and a SIBLING thread's
            # ``_acquire_lock_row`` can then see "cannot commit
            # transaction - SQL statements in progress" on the
            # singleton lock_conn because OUR cursor is still
            # alive on the connection's pending-statement list.
            # Explicit ``cur.close()`` finalises the statement
            # immediately.
            cur = lock_conn.execute(
                """
                INSERT INTO single_flight_locks
                    (name, holder, acquired_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    holder      = excluded.holder,
                    acquired_at = excluded.acquired_at,
                    expires_at  = excluded.expires_at
                WHERE single_flight_locks.expires_at < ?
                """,
                (name, holder_id, now, expires, now),
            )
            rowcount = cur.rowcount
            cur.close()
            lock_conn.commit()
            if rowcount > 0:
                acquired = True
                break
            # rowcount 0 — either the row is live (genuinely held) or
            # it vanished in a race. Recheck to tell the cases apart.
            cur2 = lock_conn.execute(
                "SELECT holder, expires_at FROM single_flight_locks "
                "WHERE name = ?",
                (name,),
            )
            row = cur2.fetchone()
            cur2.close()
            if row is not None:
                raise DbLockBusy(name, row[0], row[1])
            # Row vanished between upsert + recheck — benign race;
            # loop and retry while budget remains.
        if not acquired:
            raise DbLockBusy(name, "<vanished>", last_now)


def _release_lock_row(
    lock_conn: sqlite3.Connection,
    name: str,
    holder_id: str,
) -> None:
    """Delete the lease row if we still hold it. Self-contained
    lock-acquire+release on the calling thread (paired with
    :func:`_acquire_lock_row`).

    Best-effort: a release failure (closed conn, foreign reclaim) is
    swallowed — the TTL reclaims the row eventually. The whole point
    of running this on the OWN thread is so the RLock release is
    well-defined even if the async caller's ``__exit__`` lands on a
    different threadpool worker than the ``__enter__`` did.
    """
    # SW-1: serialize with the main writer under  (see _acquire_lock_row).
    from email_triage.web.db_writelock import get_write_lock
    with get_write_lock(), _LOCK_CONN_RLOCK:
        try:
            cur = lock_conn.execute(
                "DELETE FROM single_flight_locks "
                "WHERE name = ? AND holder = ?",
                (name, holder_id),
            )
            cur.close()
            lock_conn.commit()
        except Exception:
            # Release failure isn't fatal — TTL reclaims the row.
            pass


def renew_db_lock(
    conn: sqlite3.Connection,
    name: str,
    holder: str,
    *,
    ttl_secs: int = 1800,
) -> bool:
    """Extend the TTL of a lock this caller still holds.

    Returns ``True`` if the lease was extended, ``False`` if it was
    **lost** — the row is gone, was reclaimed by another holder, or
    this caller's own lease already expired. A ``False`` return is a
    first-class "lease lost" signal: a long-running holder that sees
    it must stop work and cancel itself rather than keep acting on a
    lock it no longer owns.

    Renewal only succeeds while the lease is still live
    (``expires_at > now``). An already-expired lease is treated as
    lost even if no one has reclaimed the row yet — resurrecting it
    would race a reclaiming instance.

    Commit scope: same dedicated-connection treatment as
    :func:`acquire_db_lock`.
    """
    lock_conn, owns_conn = _open_lock_conn(conn)
    try:
        #  — same RLock + singleton-aware contract as
        # ``acquire_db_lock``'s helpers. ``with _LOCK_CONN_RLOCK:``
        # is the safer shape than manual ``acquire()``/``release()``
        # — the context manager guarantees balanced release even
        # on raise. Acquire+release run on the same thread (the
        # whole ``renew_db_lock`` body runs inside ONE
        # ``asyncio.to_thread`` call from ``renew_db_lock_async``,
        # so thread-ownership is already satisfied — using ``with``
        # mirrors the helper shape in ``acquire_db_lock`` rather
        # than relying on that invariant).
        # SW-1: serialize with the main writer under  (see _acquire_lock_row).
        from email_triage.web.db_writelock import get_write_lock
        with get_write_lock(), _LOCK_CONN_RLOCK:
            if lock_conn is not _LOCK_CONN:
                _ensure_schema(lock_conn)
            now = time.time()
            new_expires = now + max(1, int(ttl_secs))
            #  HOTFIX-2 — see ``_acquire_lock_row`` rationale:
            # explicit ``cur.close()`` finalises the prepared
            # statement before the RLock releases so a sibling
            # thread's next ``lock_conn.commit()`` doesn't see
            # "cannot commit transaction - SQL statements in
            # progress" from our stale cursor.
            cur = lock_conn.execute(
                "UPDATE single_flight_locks SET expires_at = ? "
                "WHERE name = ? AND holder = ? AND expires_at > ?",
                (new_expires, name, holder, now),
            )
            changed = cur.rowcount > 0
            cur.close()
            lock_conn.commit()
            return changed
    finally:
        if owns_conn:
            try:
                lock_conn.close()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Async wrappers
# ---------------------------------------------------------------------------
#
# The DB-lock surface is sync (sqlite3 is sync). Async background
# loops — IMAP watchers, scheduler ticks — must not block the event
# loop on commit()/disk I/O, so these run the sync work in a
# threadpool. The dedicated lock connection is opened with
# check_same_thread=False precisely because __enter__ and __exit__
# may land on different threadpool workers.


@asynccontextmanager
async def acquire_db_lock_async(
    conn: sqlite3.Connection,
    name: str,
    *,
    ttl_secs: int = 1800,
    holder: str | None = None,
    retries: int = 1,
) -> AsyncIterator[str]:
    """Async form of :func:`acquire_db_lock`.

    Runs the blocking acquire and release in ``asyncio.to_thread`` so
    an ``async`` background loop never blocks the event loop on the
    SQLite ``commit()``. Use a file-backed DB (or a connection opened
    ``check_same_thread=False``) — the connection is touched from a
    threadpool worker.
    """
    cm = acquire_db_lock(
        conn, name, ttl_secs=ttl_secs, holder=holder, retries=retries,
    )
    holder_id: str = await asyncio.to_thread(cm.__enter__)
    try:
        yield holder_id
    finally:
        # The sync CM's body is `yield` then an unconditional
        # `finally` release — __exit__(None, None, None) runs that
        # release regardless of how the async body exited.
        await asyncio.to_thread(cm.__exit__, None, None, None)


async def renew_db_lock_async(
    conn: sqlite3.Connection,
    name: str,
    holder: str,
    *,
    ttl_secs: int = 1800,
) -> bool:
    """Async form of :func:`renew_db_lock` — runs in ``asyncio.to_thread``."""
    return await asyncio.to_thread(
        renew_db_lock, conn, name, holder, ttl_secs=ttl_secs,
    )
