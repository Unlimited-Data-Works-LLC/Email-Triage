"""Async wrapper for sync DB helpers (#135 — async DB conversion).

Background
----------
~150 async handlers across ``web/routers/ui.py`` (and the access-audit
middleware) perform direct synchronous ``sqlite3`` reads/writes on the
FastAPI event loop. SQLite holds the GIL for the duration of every
call; while one handler is mid-query, every other request on the same
worker is blocked behind it. With 30s ``/health`` polls and an
operator-facing dashboard, that turns into a measurable scalability
cliff.

The fix is plumbing-only: wrap the sync helper in ``asyncio.to_thread``
so the SQLite work happens off the event loop, and other handlers can
make progress while a slow query (large folder count, long
``MAX(created_at)`` scan, etc.) runs.

Usage
-----
At the call site, change::

    acct = get_email_account(db, account_id)

to::

    acct = await db_call(get_email_account, db, account_id)

The sync helper keeps its sync signature; the wrap lives at the call
site. This was a deliberate choice — see ``feedback_root_cause_scope.md``
for the partial-conversion rationale: this commit converts the highest-
traffic handlers (``/health``, ``/health/detail``, ``/dashboard``) plus
the access-audit middleware. Other handlers are flagged with
``# TODO #135 async-DB migration`` so future passes know what's left.

Concurrency note
----------------
``asyncio.to_thread`` schedules the work on the default loop executor
(stdlib ``ThreadPoolExecutor``). The pool's max-workers default is
``min(32, os.cpu_count() + 4)`` which is plenty for our workload. Each
thread takes the GIL while it runs SQLite C code, so two threads can't
truly execute in parallel — but they CAN overlap I/O (the SQLite
journal flush, page-cache misses) and they don't block the event loop,
which is the actual win. A handler that previously serialized every
30s ``/health`` poll behind the slowest query can now interleave.

SQLite + threading
------------------
The ``sqlite3`` connection objects we hand around were created with
``check_same_thread=False`` (see ``init_db``). That's safe because
SQLite itself is thread-safe (compiled with ``--enable-threadsafe``)
and we never share a cursor across threads — every helper opens its
own cursor inside the wrapped call. WAL mode (``PRAGMA journal_mode=
WAL``) lets readers proceed while a writer holds the lock, so the
threadpool helps reads scale linearly.
"""

from __future__ import annotations

import asyncio
from typing import Any, Awaitable, Callable, TypeVar

T = TypeVar("T")


async def db_call(
    sync_fn: Callable[..., T],
    /,
    *args: Any,
    **kwargs: Any,
) -> T:
    """Run ``sync_fn(*args, **kwargs)`` in the default thread pool.

    Thin wrapper over ``asyncio.to_thread``. Exists as its own helper
    so call sites read intent-first ("this is a DB call, off the loop")
    rather than mechanism-first ("we're using a thread pool"). Future
    refactors that swap the underlying primitive (e.g. dedicated DB
    pool, ``aiosqlite``) only have to change this file.

    Parameters
    ----------
    sync_fn :
        The synchronous helper to run. Positional-only (note the ``/``)
        so passing it as a keyword to a wrapped helper is unambiguous.
    *args, **kwargs :
        Forwarded to ``sync_fn`` as-is.

    Returns
    -------
    Whatever ``sync_fn`` returns. Exceptions propagate normally —
    ``asyncio.to_thread`` re-raises in the awaiting coroutine.
    """
    return await asyncio.to_thread(sync_fn, *args, **kwargs)


__all__ = ["db_call"]
