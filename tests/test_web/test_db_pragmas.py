"""Regression tests for connection-level PRAGMAs set at DB open.

Without ``busy_timeout`` a write that meets a held write lock fails
immediately with SQLITE_BUSY ("database is locked") instead of waiting —
and the app has many background tasks writing concurrently.
"""

from __future__ import annotations

from email_triage.web.db import init_db


def test_init_db_sets_busy_timeout(tmp_path):
    conn = init_db(tmp_path / "triage.db")
    try:
        # 30s: the 5s window was narrower than the startup
        # background-task write burst, causing `database is locked`
        # storms that flipped /health to 503 for the whole deploy window.
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 30000
    finally:
        conn.close()


def test_init_db_keeps_wal_and_foreign_keys(tmp_path):
    conn = init_db(tmp_path / "triage.db")
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        conn.close()
