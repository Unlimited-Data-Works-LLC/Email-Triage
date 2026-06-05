"""``WriteSession`` Protocol — connection-handle abstraction.

The migration target type for v0.1.2 single-file encryption's ``@db_write`` helpers
and ``db_call_*`` sites. Drops the hard-wired ``sqlite3.Connection``
parameter type from the 102+ helpers + 696 callsites so v0.2.0 
Postgres retrofit can swap in an ``asyncpg`` -backed adapter without
callsite changes (per ``internal documentation`` §7
forward-compat checklist).

Both ``sqlite3.Connection`` AND SQLAlchemy Core's DBAPI ``Connection``
satisfy this Protocol structurally — by virtue of implementing the
DBAPI 2.0 surface — so existing code that passes ``sqlite3.Connection``
to a ``def fn(session: WriteSession, ...)`` typed helper type-checks
without runtime change. The Protocol is the type-system seam; the
runtime swap happens at ``WriterBackend.submit_write(...)`` (Phase 2).

The minimal surface (the methods every current helper actually uses)
is captured here — adding methods is the canonical Protocol-extension
shape (presence-of-each-method, NOT exactly-N-methods per DA-2
HEDGE-4 + ``pattern_count_agnostic_structural_drift_catch.md``).
"""

from __future__ import annotations

from typing import Any, Iterable, Protocol, runtime_checkable


@runtime_checkable
class WriteSession(Protocol):
    """Minimal DBAPI 2.0 CONNECTION surface used by ``@db_write`` helpers.

    Use ``WriteSession`` as the parameter annotation on every helper
    that today takes ``conn: sqlite3.Connection``. The structural
    check is duck-typed: any object providing ``execute / executemany
    / commit / rollback`` satisfies the Protocol. ``sqlite3.Connection``,
    ``sqlcipher3.Connection``, and SA Core's DBAPI connection wrapper all
    qualify.

    Row retrieval (``fetchone`` / ``fetchall``) is intentionally NOT on
    this Protocol: it is a CURSOR-surface operation. ``execute`` returns
    a cursor and the caller fetches from THAT — the connection itself
    does not fetch. Keeping the Protocol connection-scoped is what lets a
    v0.2.0 ``asyncpg``-backed adapter satisfy it without faking
    cursor-level methods on a connection object.
    """

    def execute(self, sql: str, parameters: Iterable[Any] = ..., /) -> Any: ...

    def executemany(
        self, sql: str, parameters: Iterable[Iterable[Any]], /,
    ) -> Any: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...
