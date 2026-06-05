"""Shared cross-module DB primitives for the ``db/`` cluster modules.

Home for generic helpers that ≥2 ``db/`` modules + ``web/db.py`` legitimately
need — promoted here per the DA-3 "extract to db/_helpers.py when ≥3
consumers" trigger so a cluster module never reaches back into ``web/db.py``
for a primitive ``web/db.py`` doesn't own either (``feedback_code_reuse_
directive``).

Contents:
  * ``_rows`` / ``_row`` — ``dict(row)`` mappers. Promoted #277b (db-sme
    Ruling 1, 2026-05-29): canonical in ``web/db.py``, already duplicated
    inline in ``db/audit.py``; ``db/accounts.py`` was the
    3rd consumer. ``web/db.py`` + ``db/audit.py`` keep their existing inline
    copies AS-IS (byte-identical) — re-threading them is churn outside the
    extraction scope.
  * ``_has_table`` / ``_has_column`` — generic SQLite schema-introspection.
    Promoted #277c (db-sme SUB-1 OVERRIDE, 2026-05-29): generic utilities
    (NOT style-owned), 6 callers in ``web/db.py`` + 3 in ``routers/ui/
    profile.py`` + style-CORE consumers — same ≥3-consumer cross-module
    trigger as ``_rows``. The DEFs live here; ``web/db.py`` imports them
    back so its own call sites + public surface are unchanged.
  * ``apply_compatible_row_factory`` — set ``conn.row_factory`` to the Row
    class from the conn's OWN dbapi module (N-16). Promoted here because
    every connection-open site across the package needs it on the
    encrypted path; ``_helpers`` is the leaf module they can all import.
"""

from __future__ import annotations

import sqlite3
import sys
from typing import Any


def apply_compatible_row_factory(conn: sqlite3.Connection) -> None:
    """Set ``row_factory`` to the ``Row`` class from the conn's OWN dbapi
    module — ``sqlite3.Row`` for a stdlib connection, ``sqlcipher3.dbapi2.Row``
    for a SQLCipher-encrypted one (N-16).

    Why this is required: stdlib ``sqlite3.Row`` is a C type that
    type-rejects a foreign cursor — assigning ``conn.row_factory =
    sqlite3.Row`` on a ``sqlcipher3`` connection raises ``TypeError:
    Row() argument 1 must be sqlite3.Cursor, not sqlcipher3.dbapi2.Cursor``
    the first time a row is materialised (caught by the v0.1.2 encrypted
    boot bake at ``_bootstrap_schema`` → ``_column_exists``).

    Resolution is by module, not by import: ``type(conn).__module__`` is
    ``"sqlite3"`` for a stdlib connection and ``"sqlcipher3.dbapi2"`` for an
    encrypted one; both modules expose a ``.Row`` factory that is correct
    for cursors produced by that same connection. We resolve the module
    from ``sys.modules`` (the connection's class already forced the import)
    rather than importing ``sqlcipher3`` directly — sqlcipher3 is a
    Linux-only / optional binary dependency.
    """
    conn.row_factory = sys.modules[type(conn).__module__].Row


def row_get(row: Any, key: str, idx: int) -> Any:
    """Read a column from a row that may be a mapping-style ``Row`` (any
    dbapi: stdlib ``sqlite3.Row`` or ``sqlcipher3.dbapi2.Row``) or a plain
    positional tuple.

    Factory-agnostic by design (N-16): ``isinstance(row, sqlite3.Row)``
    silently goes ``False`` for a ``sqlcipher3`` row and steers the caller
    into the positional-tuple branch with the WRONG index. Duck-typing on
    ``keys()`` — which both Row classes expose and a bare tuple does not —
    keeps the keyed branch for ANY keyed Row and the positional branch only
    for genuine tuples.
    """
    if hasattr(row, "keys"):
        return row[key]
    return row[idx]


def _rows(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    """Map a ``fetchall()`` result to a list of plain dicts.

    The ``[dict(r) for r in rows]`` idiom appeared ~22× verbatim across
    ``web/db.py``'s read helpers; this is the single home for it.
    """
    return [dict(row) for row in rows]


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    """Map a ``fetchone()`` result to a plain dict, or ``None``.

    Standardises the ``dict(row) if row ... else None`` idiom on an
    explicit ``is None`` test — a couple of call sites used a bare
    truthiness check, which differs only for a degenerate zero-column
    Row but is worth not having two spellings of.
    """
    return None if row is None else dict(row)


def _has_table(conn: sqlite3.Connection, table_name: str) -> bool:
    """True when ``table_name`` exists in the SQLite schema."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master "
        "WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _has_column(
    conn: sqlite3.Connection, table_name: str, column_name: str,
) -> bool:
    """True when ``column_name`` exists on ``table_name``."""
    if not _has_table(conn, table_name):
        return False
    rows = conn.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()
    for r in rows:
        # PRAGMA returns (cid, name, type, notnull, dflt_value, pk)
        name = r[1] if not hasattr(r, "keys") else r["name"]
        if name == column_name:
            return True
    return False
