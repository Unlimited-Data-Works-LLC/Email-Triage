""" — count-agnostic test-fixture migration application.

Some test fixtures build a MINIMAL schema by hand, then apply a HARDCODED tuple
of migration versions that touch the table under test — e.g. ``(12, 14, 15,
32)`` for ``sent_mail_index``. When a NEW migration adds a column the real
``index_message`` (etc.) writes, that version must be hand-appended to EVERY
such tuple or unrelated tests fail silently. This exact trap bit 's
``embedding_dimension`` (v32): 8 tests were red until ``32`` was added to the
fixtures by hand.

``apply_table_migrations(conn, table)`` applies, in version order, EVERY
registered migration whose body references ``table`` — so a future migration
that alters the table is picked up automatically with no tuple to edit. It
detects "touches the table" by scanning the migration body's own source for the
table name (the migrations are small, single-purpose, and name their table by
string literal in the DDL/ALTER). This keeps such fixtures CURRENT-by-
construction instead of frozen at a hand-maintained version list.

NOTE: this is for fixtures that want the *current full* schema of a table. A
fixture that deliberately reproduces a HISTORICAL state to test migration
evolution (e.g. ``(12, 14)`` = pre-v15) should KEEP its explicit version list —
that partial state is the point of the test.
"""

from __future__ import annotations

import inspect
import sqlite3


def apply_table_migrations(conn: sqlite3.Connection, table: str) -> list[int]:
    """Apply every registered migration whose body references ``table``, in
    ascending version order. Returns the applied version list (for assertions).

    Count-agnostic: a new table-touching migration is included automatically,
    so the fixture never needs a hand-edited version tuple again.
    """
    from email_triage.web.migrations import MIGRATIONS

    applied: list[int] = []
    for m in sorted(MIGRATIONS, key=lambda x: x.version):
        try:
            body_src = inspect.getsource(m.body)
        except (OSError, TypeError):  # pragma: no cover - C-impl / lambda
            body_src = ""
        if table in body_src:
            m.body(conn)
            applied.append(m.version)
    conn.commit()
    return applied
