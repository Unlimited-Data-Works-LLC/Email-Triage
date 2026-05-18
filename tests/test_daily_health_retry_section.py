"""Tests for the retry-deads section of the daily-health email
(#175 R-B).

Covers:
  * Threshold logic — per-account (≥3) + install-wide (≥5).
  * Silent path when neither threshold fires.
  * Breakdown shape (dead_reason counts per account).
  * HTML + text renders include the section when present, skip when
    None.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from email_triage.config import TriageConfig
from email_triage.web.daily_health import (
    RETRY_DEADS_PER_ACCOUNT_THRESHOLD,
    RETRY_DEADS_INSTALL_WIDE_THRESHOLD,
    _render_html,
    _render_text,
    gather_retry_deads_section,
)
from email_triage.web.db import init_db


def _install_ra_schema(db) -> None:
    """Install the v30 shape R-A is going to deliver."""
    try:
        db.execute("DROP TABLE IF EXISTS watcher_retry_queue")
    except Exception:
        pass
    db.execute(
        """
        CREATE TABLE watcher_retry_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            provider_type TEXT NOT NULL,
            mailbox TEXT,
            uid TEXT,
            uidvalidity TEXT,
            gmail_msg_id TEXT,
            o365_msg_id TEXT,
            error_class TEXT,
            error_msg TEXT,
            state TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at TEXT,
            dead_reason TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.commit()


def _make_account(db, *, account_id=1, name="acct1"):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        (f"u{account_id}@test.com", f"User {account_id}", "user", now),
    )
    user_id = db.execute(
        "SELECT id FROM users WHERE email = ?",
        (f"u{account_id}@test.com",),
    ).fetchone()[0]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        " created_at, updated_at) "
        "VALUES (?, ?, ?, 'imap', '{}', 0, ?, ?)",
        (account_id, user_id, name, now, now),
    )
    db.commit()


def _seed_dead(db, *, account_id, dead_reason, updated_hours_ago=2, count=1):
    for _ in range(count):
        updated = (
            datetime.now(timezone.utc) - timedelta(hours=updated_hours_ago)
        ).isoformat()
        db.execute(
            "INSERT INTO watcher_retry_queue ("
            " account_id, provider_type, error_class, error_msg, "
            " state, attempts, next_attempt_at, dead_reason, "
            " created_at, updated_at"
            ") VALUES (?, 'imap', 'ReadTimeout', '', 'dead', 3, ?, ?, ?, ?)",
            (
                account_id, updated, dead_reason,
                updated, updated,
            ),
        )
    db.commit()


# ---------------------------------------------------------------------------
# Gather logic
# ---------------------------------------------------------------------------


@pytest.fixture
def db():
    conn = init_db(":memory:")
    _install_ra_schema(conn)
    yield conn
    conn.close()


class TestGatherSilentPaths:
    def test_no_deads_returns_none(self, db):
        _make_account(db, account_id=1, name="A")
        assert gather_retry_deads_section(db) is None

    def test_below_both_thresholds_returns_none(self, db):
        _make_account(db, account_id=1, name="A")
        # 2 deads — below the per-account threshold (3) and below
        # install-wide (5).
        _seed_dead(db, account_id=1, dead_reason="auth_revoked", count=2)
        assert gather_retry_deads_section(db) is None

    def test_old_deads_excluded(self, db):
        _make_account(db, account_id=1, name="A")
        # 10 deads but all >24h ago — outside the window.
        _seed_dead(
            db, account_id=1, dead_reason="auth_revoked",
            count=10, updated_hours_ago=40,
        )
        assert gather_retry_deads_section(db) is None


class TestGatherThresholdCrossings:
    def test_per_account_threshold_fires(self, db):
        _make_account(db, account_id=1, name="Inbox A")
        # 3 deads on one account — hits the per-account threshold,
        # below install-wide.
        _seed_dead(
            db, account_id=1, dead_reason="auth_revoked",
            count=3,
        )
        section = gather_retry_deads_section(db)
        assert section is not None
        # Install-wide not crossed (3 < 5).
        assert section["install_wide"] is False
        assert section["dead_24h"] == 3
        # Per-account list has the offending account.
        assert len(section["per_account"]) == 1
        acct = section["per_account"][0]
        assert acct["account_id"] == 1
        assert acct["account_label"] == "Inbox A"
        assert acct["count"] == 3
        assert acct["breakdown"] == {"auth_revoked": 3}

    def test_install_wide_threshold_fires_without_per_account(self, db):
        _make_account(db, account_id=1, name="A")
        _make_account(db, account_id=2, name="B")
        _make_account(db, account_id=3, name="C")
        # 2 deads on each account = 6 install-wide, but NONE crosses
        # the per-account threshold.
        _seed_dead(db, account_id=1, dead_reason="auth_revoked", count=2)
        _seed_dead(db, account_id=2, dead_reason="message_gone", count=2)
        _seed_dead(db, account_id=3, dead_reason="max_attempts_exceeded", count=2)
        section = gather_retry_deads_section(db)
        assert section is not None
        assert section["install_wide"] is True
        assert section["dead_24h"] == 6
        # No per-account row crosses 3 → empty.
        assert section["per_account"] == []

    def test_both_thresholds_simultaneous(self, db):
        _make_account(db, account_id=1, name="Bad")
        _make_account(db, account_id=2, name="Worse")
        _seed_dead(db, account_id=1, dead_reason="auth_revoked", count=3)
        _seed_dead(db, account_id=2, dead_reason="message_gone", count=4)
        section = gather_retry_deads_section(db)
        assert section is not None
        assert section["install_wide"] is True
        assert section["dead_24h"] == 7
        assert len(section["per_account"]) == 2

    def test_breakdown_groups_reasons(self, db):
        _make_account(db, account_id=1, name="X")
        _seed_dead(db, account_id=1, dead_reason="auth_revoked", count=2)
        _seed_dead(db, account_id=1, dead_reason="max_attempts_exceeded", count=2)
        section = gather_retry_deads_section(db)
        # 4 deads on one account → per-account fires.
        acct = section["per_account"][0]
        assert acct["count"] == 4
        assert acct["breakdown"] == {
            "auth_revoked": 2,
            "max_attempts_exceeded": 2,
        }


# ---------------------------------------------------------------------------
# Renderer integration
# ---------------------------------------------------------------------------


def _state_with_retry_deads(rd: dict | None) -> dict:
    """Minimal state dict for the renderer. Fills in only the keys
    the renderer touches; other sections render as empty/no-op."""
    return {
        "now": datetime.now(timezone.utc),
        "hipaa_mode": False,
        "attention_reasons": [],
        "gateway_ok": True,
        "watchers": [],
        "error_count_24h": 0,
        "warning_count_24h": 0,
        "error_rows": [],
        "triage_total": 0,
        "triage_accounts": [],
        "triage_error_rate": 0.0,
        "stale_auth_accounts": [],
        "hipaa_events_count": 0,
        "hipaa_recent_actors": [],
        "api_key_events_count": 0,
        "api_key_events_recent": [],
        "baa_expirations": None,
        "update_available": None,
        "retry_deads": rd,
        "log_row_count": 0,
        "pubsub_configured": False,
        "providers": {},
        "account_states": [],
        "poll": {"registered": 0, "fresh": 0},
        "mailboxes": {"total": 0, "watching": 0},
    }


class TestRendererIntegration:
    def test_html_omits_section_when_none(self):
        config = TriageConfig()
        html = _render_html(_state_with_retry_deads(None), config)
        assert "Retry queue — abandoned messages" not in html

    def test_html_renders_section_when_present(self):
        config = TriageConfig()
        rd = {
            "install_wide": True,
            "dead_24h": 7,
            "per_account": [
                {
                    "account_id": 1,
                    "account_label": "Bad Inbox",
                    "owner": "Owner Bob",
                    "count": 5,
                    "breakdown": {"auth_revoked": 3, "message_gone": 2},
                },
            ],
        }
        html = _render_html(_state_with_retry_deads(rd), config)
        assert "Retry queue — abandoned messages" in html
        assert "7" in html  # install-wide count
        assert "Bad Inbox" in html
        assert "Owner Bob" in html
        # Breakdown text — reasons rendered with spaces.
        assert "auth revoked" in html
        assert "message gone" in html

    def test_text_omits_section_when_none(self):
        config = TriageConfig()
        text = _render_text(_state_with_retry_deads(None), config)
        assert "Retry queue — abandoned messages" not in text

    def test_text_renders_section_when_present(self):
        config = TriageConfig()
        rd = {
            "install_wide": False,
            "dead_24h": 3,
            "per_account": [
                {
                    "account_id": 7,
                    "account_label": "Acct7",
                    "owner": "",
                    "count": 3,
                    "breakdown": {"auth_revoked": 3},
                },
            ],
        }
        text = _render_text(_state_with_retry_deads(rd), config)
        assert "Retry queue — abandoned messages" in text
        assert "Acct7" in text
        assert "3 abandoned in 24h" in text


# ---------------------------------------------------------------------------
# Threshold constants — guard against accidental drift.
# ---------------------------------------------------------------------------


class TestThresholdConstants:
    def test_per_account_threshold_is_three(self):
        assert RETRY_DEADS_PER_ACCOUNT_THRESHOLD == 3

    def test_install_wide_threshold_is_five(self):
        assert RETRY_DEADS_INSTALL_WIDE_THRESHOLD == 5
