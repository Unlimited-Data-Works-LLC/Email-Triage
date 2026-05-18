"""Tests for ``log_entries`` rotation (item #26).

Covers the combined age-plus-count prune helper and its wiring into
app startup and the background 30-minute sweep.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from email_triage.config import LoggingConfig, TriageConfig
from email_triage.web.app import _log_entries_prune_loop, create_app
from email_triage.web.db import (
    init_db,
    prune_log_entries,
    prune_log_entries_by_age_and_count,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _seed_entry(conn, *, ts: str, level: str = "INFO", message: str = "x") -> int:
    """Insert one row with an explicit ``ts`` and return the rowid."""
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (ts, level, "test", message, json.dumps({}), now),
    )
    conn.commit()
    return cur.lastrowid


def _count_entries(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]


# ---------------------------------------------------------------------------
# Helper-level tests
# ---------------------------------------------------------------------------

def test_prune_by_age_deletes_old_rows():
    """50 rows older than retention, 50 fresh — old rows go, new stay."""
    conn = init_db(":memory:")
    old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    new_ts = datetime.now(timezone.utc).isoformat()

    for _ in range(50):
        _seed_entry(conn, ts=old_ts, message="old")
    for _ in range(50):
        _seed_entry(conn, ts=new_ts, message="new")

    assert _count_entries(conn) == 100

    deleted = prune_log_entries_by_age_and_count(
        conn, retention_days=30, max_rows=50000
    )

    assert deleted == 50
    assert _count_entries(conn) == 50
    # Only "new" rows remain.
    remaining = conn.execute("SELECT DISTINCT message FROM log_entries").fetchall()
    assert [r[0] for r in remaining] == ["new"]


def test_prune_by_count_keeps_newest():
    """60k rows, cap 50k — exactly 50k remain, all the newest IDs."""
    conn = init_db(":memory:")
    ts = datetime.now(timezone.utc).isoformat()

    # Bulk insert via executemany for speed.
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [(ts, "INFO", "test", f"msg-{i}", "{}", now) for i in range(60000)],
    )
    conn.commit()
    assert _count_entries(conn) == 60000

    deleted = prune_log_entries_by_age_and_count(
        conn, retention_days=30, max_rows=50000
    )

    assert deleted == 10000
    assert _count_entries(conn) == 50000
    # Lowest remaining id should be 10001 (kept the newest 50000).
    min_id = conn.execute("SELECT MIN(id) FROM log_entries").fetchone()[0]
    assert min_id == 10001


def test_prune_by_age_and_count_combined():
    """Both axes deleting — union of old + overflow rows goes."""
    conn = init_db(":memory:")
    old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    new_ts = datetime.now(timezone.utc).isoformat()

    # 20 ancient, plus 100 fresh — cap at 50 max rows, 30-day age.
    for _ in range(20):
        _seed_entry(conn, ts=old_ts, message="ancient")
    for _ in range(100):
        _seed_entry(conn, ts=new_ts, message="fresh")

    assert _count_entries(conn) == 120

    deleted = prune_log_entries_by_age_and_count(
        conn, retention_days=30, max_rows=50
    )

    # 20 ancient + 50 overflow = 70 deleted; 50 remain.
    assert deleted == 70
    assert _count_entries(conn) == 50
    # All survivors are fresh.
    remaining = conn.execute(
        "SELECT DISTINCT message FROM log_entries"
    ).fetchall()
    assert [r[0] for r in remaining] == ["fresh"]


def test_prune_idempotent():
    """A second call right after the first deletes zero rows."""
    conn = init_db(":memory:")
    old_ts = (datetime.now(timezone.utc) - timedelta(days=45)).isoformat()
    new_ts = datetime.now(timezone.utc).isoformat()

    for _ in range(30):
        _seed_entry(conn, ts=old_ts)
    for _ in range(30):
        _seed_entry(conn, ts=new_ts)

    first = prune_log_entries_by_age_and_count(
        conn, retention_days=30, max_rows=50000
    )
    second = prune_log_entries_by_age_and_count(
        conn, retention_days=30, max_rows=50000
    )

    assert first == 30
    assert second == 0


def test_legacy_prune_log_entries_still_works():
    """Back-compat: the old count-only helper still runs."""
    conn = init_db(":memory:")
    ts = datetime.now(timezone.utc).isoformat()
    for _ in range(100):
        _seed_entry(conn, ts=ts)

    deleted = prune_log_entries(conn, keep=25)
    assert deleted == 75
    assert _count_entries(conn) == 25


# ---------------------------------------------------------------------------
# Wiring: startup + background task
# ---------------------------------------------------------------------------

def test_startup_prunes_log_entries(tmp_path):
    """App boot should call the helper — table is bounded by end of lifespan."""
    db_path = tmp_path / "triage.db"

    # Pre-populate the DB with old rows before the app boots.
    conn = init_db(str(db_path))
    old_ts = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    for _ in range(50):
        _seed_entry(conn, ts=old_ts)
    assert _count_entries(conn) == 50
    conn.close()

    config = TriageConfig()
    config.persistence.db_path = str(db_path)
    config.logging = LoggingConfig(retention_days=30, max_rows=50000)

    # Enter + exit the lifespan to trigger startup prune. The lifespan
    # imports ``bootstrap_secrets_from_config`` inside the function body,
    # so we patch the source module (``email_triage.secrets``) — a
    # minimal stub provider avoids needing a real master key.
    from fastapi.testclient import TestClient

    from email_triage import secrets as _secrets_mod

    class _StubSecrets:
        def __init__(self):
            self._s: dict[str, str] = {}
        def get(self, k): return self._s.get(k)
        def set(self, k, v): self._s[k] = v
        def list_keys(self): return list(self._s.keys())

    with patch.object(
        _secrets_mod,
        "bootstrap_secrets_from_config",
        lambda conn, cfg: _StubSecrets(),
    ):
        app = create_app(config)
        with TestClient(app):
            pass

    # After startup, the OLD pre-seeded rows are gone. The lifespan
    # itself emits a couple of INFO lines after the prune fires
    # ("Pruned log_entries on startup", "Web UI started"), which
    # land in log_entries via the SQL log handler that attaches
    # earlier in the lifespan body. Those are valid retention-
    # window-fresh rows; the contract under test is "the prune
    # cleared the old data," so check for entries at the seeded
    # ts rather than total table size.
    verify_conn = init_db(str(db_path))
    old_count = verify_conn.execute(
        "SELECT COUNT(*) FROM log_entries WHERE ts = ?", (old_ts,),
    ).fetchone()[0]
    assert old_count == 0
    verify_conn.close()


def test_background_task_prunes_periodically():
    """The 30-min loop calls the helper at least once when driven."""
    conn = init_db(":memory:")

    # Seed one clearly-prunable old row.
    old_ts = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    _seed_entry(conn, ts=old_ts)
    assert _count_entries(conn) == 1

    # Build a minimal app.state-like shim.
    class _App:
        class state:
            db = conn
            config = TriageConfig()
    _App.state.config.logging = LoggingConfig(retention_days=30, max_rows=50000)

    async def _drive():
        # Patch the two sleep points so the loop runs one sweep then
        # cancels cleanly on the second sleep.
        real_sleep = asyncio.sleep
        calls = {"n": 0}

        async def fast_sleep(_secs):
            calls["n"] += 1
            if calls["n"] == 1:
                # The initial startup delay — skip instantly.
                return
            # The post-sweep 30-min wait — cancel here to unwind the loop.
            raise asyncio.CancelledError()

        with patch("email_triage.web.app.asyncio.sleep", fast_sleep):
            try:
                await _log_entries_prune_loop(_App)
            except asyncio.CancelledError:
                pass
        # Ensure we restored the real sleep for any later awaits.
        _ = real_sleep  # noqa: F841

    asyncio.run(_drive())

    # The old row should have been pruned by the single sweep.
    assert _count_entries(conn) == 0
