"""Tests for the ``retry_queue`` field on /health/detail (#175 R-B).

Same synthetic-schema strategy as the admin tests — R-A ships the
migration in parallel, this fixture installs the expected v30
shape so the health-field tests run against the right table.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _install_ra_schema(db) -> None:
    """Drop legacy v16 shape + install the v30 shape R-A is going
    to deliver. Idempotent."""
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


def _seed(
    db, *, state, dead_reason=None, created_hours_ago=0,
    updated_hours_ago=0,
):
    created = (
        datetime.now(timezone.utc) - timedelta(hours=created_hours_ago)
    ).isoformat()
    updated = (
        datetime.now(timezone.utc) - timedelta(hours=updated_hours_ago)
    ).isoformat()
    db.execute(
        "INSERT INTO watcher_retry_queue ("
        " account_id, provider_type, error_class, error_msg, "
        " state, attempts, next_attempt_at, dead_reason, "
        " created_at, updated_at"
        ") VALUES (1, 'imap', 'ReadTimeout', '', ?, 0, ?, ?, ?, ?)",
        (state, updated, dead_reason, created, updated),
    )
    db.commit()


class TestHealthDetailRetryQueueBlock:
    def test_empty_db_renders_zero_block(self, client, db, admin_cookies):
        _install_ra_schema(db)
        r = client.get(
            "/health/detail", cookies=admin_cookies,
        )
        assert r.status_code == 200
        body = r.json()
        assert "retry_queue" in body
        rq = body["retry_queue"]
        assert rq["pending"] == 0
        assert rq["dead_24h"] == 0
        assert rq["oldest_pending_age_sec"] is None
        # All canonical reason keys present even with no rows.
        bd = rq["dead_breakdown_24h"]
        assert bd["max_attempts_exceeded"] == 0
        assert bd["auth_revoked"] == 0
        assert bd["uidvalidity_changed"] == 0
        assert bd["message_gone"] == 0
        assert bd["operator_abandoned"] == 0

    def test_pending_and_dead_counts(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="pending", created_hours_ago=2)
        _seed(db, state="pending", created_hours_ago=4)
        _seed(db, state="dead", dead_reason="auth_revoked", updated_hours_ago=3)
        _seed(db, state="dead", dead_reason="max_attempts_exceeded", updated_hours_ago=10)
        # An older dead row (40h ago) — outside the 24h window, must
        # NOT count toward dead_24h.
        _seed(db, state="dead", dead_reason="operator_abandoned", updated_hours_ago=40)

        r = client.get("/health/detail", cookies=admin_cookies)
        body = r.json()
        rq = body["retry_queue"]
        assert rq["pending"] == 2
        assert rq["dead_24h"] == 2  # the 40h dead one is excluded
        bd = rq["dead_breakdown_24h"]
        assert bd["auth_revoked"] == 1
        assert bd["max_attempts_exceeded"] == 1
        assert bd["operator_abandoned"] == 0  # excluded by 24h window

    def test_oldest_pending_age_computed(self, client, db, admin_cookies):
        _install_ra_schema(db)
        _seed(db, state="pending", created_hours_ago=5)
        _seed(db, state="pending", created_hours_ago=1)
        # Dead rows must not influence oldest_pending_age.
        _seed(
            db, state="dead", dead_reason="auth_revoked",
            created_hours_ago=10,
        )

        r = client.get("/health/detail", cookies=admin_cookies)
        rq = r.json()["retry_queue"]
        # Oldest of the two pending rows is ~5h ago = 18000s. Allow
        # a generous window for time skew.
        assert rq["oldest_pending_age_sec"] is not None
        assert 4 * 3600 < rq["oldest_pending_age_sec"] < 6 * 3600

    def test_missing_table_returns_sentinel(self, client, db, admin_cookies):
        # Drop the table entirely — pre-migration install.
        db.execute("DROP TABLE IF EXISTS watcher_retry_queue")
        db.commit()
        r = client.get("/health/detail", cookies=admin_cookies)
        # The endpoint must still return 200 — retry_queue is one
        # failure-safe block among many.
        assert r.status_code == 200
        rq = r.json()["retry_queue"]
        assert rq.get("state") == "unknown"
        assert "error" in rq
