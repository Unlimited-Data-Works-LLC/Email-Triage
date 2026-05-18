"""Migration v19 — wrap ``sent_folder_override`` scalar string to list.

Backfill semantics:

  * Account row with ``sent_folder_override="Sent Mail"`` (legacy
    string) → post-v19 the value is ``["Sent Mail"]``.
  * Account row with no ``sent_folder_override`` key → no change.
  * Account row with already-list value → no change (idempotency on
    re-run).
  * Empty / whitespace string collapses to ``[]``.

The migration runs as part of the standard ``run_migrations`` flow
on init_db; this test exercises the body directly against a freshly
initialised in-memory DB so we can pre-seed legacy shapes.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from email_triage.web.db import init_db
from email_triage.web.migrations import MIGRATIONS


def _find_migration(version: int):
    for m in MIGRATIONS:
        if m.version == version:
            return m
    raise AssertionError(f"migration {version} not registered")


def _insert_acct(conn: sqlite3.Connection, *, user_id: int, config: dict) -> int:
    """Insert a minimal email_accounts row carrying ``config``."""
    cur = conn.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))",
        (user_id, "test", "imap", json.dumps(config)),
    )
    return int(cur.lastrowid)


def _seed_user(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, datetime('now'))",
        ("m@test", "tester", "user"),
    )
    return int(cur.lastrowid)


def _config_after(conn: sqlite3.Connection, acct_id: int) -> dict:
    row = conn.execute(
        "SELECT config_json FROM email_accounts WHERE id = ?",
        (acct_id,),
    ).fetchone()
    raw = row["config_json"] if hasattr(row, "keys") else row[0]
    return json.loads(raw)


class TestV20Backfill:
    def test_legacy_scalar_string_wraps_to_list(self):
        conn = init_db(":memory:")
        # init_db already runs all registered migrations. Drop our
        # legacy row in, then re-run v19's body directly to simulate
        # the upgrade.
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": "Sent Mail"},
        )
        # Run v19 body again (it's idempotent; this also lets us run
        # against a row that was inserted post-init).
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert cfg["sent_folder_override"] == ["Sent Mail"]

    def test_missing_key_left_alone(self):
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"host": "mail.example.com"},
        )
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert "sent_folder_override" not in cfg

    def test_already_list_left_alone(self):
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": ["Sent", "Sent Items"]},
        )
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert cfg["sent_folder_override"] == ["Sent", "Sent Items"]

    def test_empty_string_collapses_to_empty_list(self):
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": ""},
        )
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert cfg["sent_folder_override"] == []

    def test_whitespace_string_collapses_to_empty_list(self):
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": "   "},
        )
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert cfg["sent_folder_override"] == []

    def test_idempotent_on_re_run(self):
        """Running v19 body twice in a row leaves the row identical."""
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": "Sent Mail"},
        )
        _find_migration(20).body(conn)
        cfg_first = _config_after(conn, acct_id)
        _find_migration(20).body(conn)
        cfg_second = _config_after(conn, acct_id)
        assert cfg_first == cfg_second
        assert cfg_first["sent_folder_override"] == ["Sent Mail"]

    def test_non_string_non_list_collapses_to_empty_list(self):
        """Defensive: numeric / dict / None shapes collapse to []."""
        conn = init_db(":memory:")
        user_id = _seed_user(conn)
        acct_id = _insert_acct(
            conn, user_id=user_id,
            config={"sent_folder_override": 42},
        )
        _find_migration(20).body(conn)
        cfg = _config_after(conn, acct_id)
        assert cfg["sent_folder_override"] == []
