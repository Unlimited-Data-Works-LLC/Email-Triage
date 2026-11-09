"""DB-API exception classes across BOTH SQLite drivers — the one funnel.

Punch 560 / N-560. An encrypted install opens its connections through
``sqlcipher3.dbapi2`` (:func:`email_triage.db._engine._make_encrypted_conn`).
sqlcipher3 compiles its OWN copy of the pysqlite exception hierarchy, rooted
at ``Exception`` (sqlcipher3 0.6.2 ``src/module.c:481``), so
``sqlcipher3.dbapi2.OperationalError`` is NOT a subclass of
``sqlite3.OperationalError``. A handler spelled ``except
sqlite3.OperationalError`` therefore never matches an error raised on an
encrypted connection — the handler is dead and the error propagates.

Every handler that can see a main-DB connection catches one of these tuples
instead of a bare ``sqlite3.*`` class (pinned by
``tests/test_n560_dbapi_error_funnel_ssot_pin.py``).

Each tuple holds the stdlib class plus, when ``sqlcipher3`` is importable, the
driver class of the SAME name — never a wider one, so a routed site keeps
exactly the error set it caught before. The import is eager and guarded: a
sqlcipher3 exception can only exist in a process where this import succeeds,
so a process without the driver (a plaintext / Windows dev install) loses
nothing.

Boot cost, and why it differs from ``db/_engine.py``: the engine imports
sqlcipher3 lazily (a heavy binary, loaded only when an encrypted connection is
opened). This module is imported at module load by ``triage_logging``,
``version``, ``web/auth`` and others, so every process now loads the driver at
first import. The guard therefore also catches ``OSError`` (a broken install
whose shared object fails to load), so a plaintext install that never opens an
encrypted connection still boots; an encrypted install with a broken driver
still fails closed at connect time in ``_make_encrypted_conn``.

:func:`is_missing_table` is the one "table absent" predicate for handlers
whose benign case is an older schema: they catch ``DB_OPERATIONAL_ERRORS`` and
must not treat a locked, busy or I/O error as "absent".
"""

from __future__ import annotations

import sqlite3

try:
    import sqlcipher3.dbapi2 as _sqlcipher_dbapi
except (ImportError, OSError):
    # Plaintext install — the ``encryption`` extra is absent (or its shared
    # object will not load), so no sqlcipher3 connection (and no sqlcipher3
    # exception) can exist here.
    _sqlcipher_dbapi = None


def _both_drivers(name: str) -> tuple[type[BaseException], ...]:
    stdlib = getattr(sqlite3, name)
    if _sqlcipher_dbapi is None:
        return (stdlib,)
    return (stdlib, getattr(_sqlcipher_dbapi, name))


DB_ERRORS = _both_drivers("Error")
DB_DATABASE_ERRORS = _both_drivers("DatabaseError")
DB_OPERATIONAL_ERRORS = _both_drivers("OperationalError")
DB_INTEGRITY_ERRORS = _both_drivers("IntegrityError")
DB_PROGRAMMING_ERRORS = _both_drivers("ProgrammingError")

# The stdlib class name -> its funnel tuple. The pin and the rewrite both
# read this so a new class is added in ONE place.
FUNNEL_BY_CLASS: dict[str, tuple[type[BaseException], ...]] = {
    "Error": DB_ERRORS,
    "DatabaseError": DB_DATABASE_ERRORS,
    "OperationalError": DB_OPERATIONAL_ERRORS,
    "IntegrityError": DB_INTEGRITY_ERRORS,
    "ProgrammingError": DB_PROGRAMMING_ERRORS,
}

FUNNEL_NAME_BY_CLASS: dict[str, str] = {
    "Error": "DB_ERRORS",
    "DatabaseError": "DB_DATABASE_ERRORS",
    "OperationalError": "DB_OPERATIONAL_ERRORS",
    "IntegrityError": "DB_INTEGRITY_ERRORS",
    "ProgrammingError": "DB_PROGRAMMING_ERRORS",
}


def is_missing_table(exc: BaseException) -> bool:
    """True when ``exc`` is SQLite's "no such table" error.

    The message is SQLite core's, identical under both drivers. A handler that
    skips an absent table (an older schema) gates its benign branch on this, so
    "database is locked", "disk I/O error" and the like are NOT read as
    "absent" (punch 560 panel, devils-advocate F2).
    """
    return "no such table" in str(exc).lower()
