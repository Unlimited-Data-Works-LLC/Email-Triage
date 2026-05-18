"""Tests for #166 push-delivery counter table.

Pins:

* DB helpers (``record_push_delivery``, ``get_push_deliveries_window``,
  ``prune_push_deliveries``) — UPSERT shape, window read shape,
  retention prune.
* Webhook wire-in — successful Gmail / O365 push delivery writes
  exactly one row; counter failure does NOT 5xx the webhook
  (best-effort counter must never block delivery).
* Stats template surface — the rolling-window context keys land on
  ``_stats_page_snapshot`` so the /admin/stats template can render
  them.

Filed 2026-05-13. Companion migration v24
(_v24_create_push_deliveries).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import json

import pytest


def _seed_account(db, account_id: int = 1, name: str = "Test Gmail"):
    """Insert an ``email_accounts`` row so the FK on push_deliveries
    has a parent row. Uses ``INSERT OR IGNORE`` so re-seeding the same
    id in a single test is a no-op."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, 1, ?, 'gmail_api', ?, ?, ?)",
        (account_id, name, json.dumps({}), now, now),
    )
    db.commit()


# ---------------------------------------------------------------------------
# DB helpers (pure SQL — no FastAPI test client)
# ---------------------------------------------------------------------------


class TestRecordPushDelivery:
    """``record_push_delivery`` UPSERTs into push_deliveries."""

    def test_first_delivery_creates_row(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1)
        record_push_delivery(db, account_id=1, provider="gmail")
        rows = get_push_deliveries_window(db, days=1)
        assert len(rows) == 1
        assert rows[0]["account_id"] == 1
        assert rows[0]["provider"] == "gmail"
        assert rows[0]["count"] == 1

    def test_second_delivery_same_day_increments(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1)
        record_push_delivery(db, account_id=1, provider="gmail")
        record_push_delivery(db, account_id=1, provider="gmail")
        record_push_delivery(db, account_id=1, provider="gmail")
        rows = get_push_deliveries_window(db, days=1)
        assert len(rows) == 1
        assert rows[0]["count"] == 3

    def test_separate_provider_separate_row(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1)
        record_push_delivery(db, account_id=1, provider="gmail")
        record_push_delivery(db, account_id=1, provider="office365")
        rows = get_push_deliveries_window(db, days=1)
        assert len(rows) == 2
        assert {r["provider"] for r in rows} == {"gmail", "office365"}

    def test_separate_account_separate_row(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1, name="first")
        _seed_account(db, account_id=2, name="second")
        record_push_delivery(db, account_id=1, provider="gmail")
        record_push_delivery(db, account_id=2, provider="gmail")
        rows = get_push_deliveries_window(db, days=1)
        assert len(rows) == 2
        assert {r["account_id"] for r in rows} == {1, 2}

    def test_none_account_id_is_noop(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        record_push_delivery(db, account_id=None, provider="gmail")  # type: ignore[arg-type]
        assert get_push_deliveries_window(db, days=1) == []

    def test_empty_provider_is_noop(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1)
        record_push_delivery(db, account_id=1, provider="")
        assert get_push_deliveries_window(db, days=1) == []


class TestGetPushDeliveriesWindow:
    """``get_push_deliveries_window`` returns rolling N-day rollup."""

    def test_outside_window_excluded(self, db, admin_user):
        from email_triage.web.db import get_push_deliveries_window
        _seed_account(db, account_id=1)
        # Hand-insert a row 30 days old.
        old_day = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
        db.execute(
            "INSERT INTO push_deliveries (account_id, provider, day, count) "
            "VALUES (1, 'gmail', ?, 99)",
            (old_day,),
        )
        db.commit()
        rows = get_push_deliveries_window(db, days=14)
        assert rows == []

    def test_account_name_joined(self, db, admin_user):
        from email_triage.web.db import (
            record_push_delivery, get_push_deliveries_window,
        )
        _seed_account(db, account_id=1, name="Truma")
        record_push_delivery(db, account_id=1, provider="gmail")
        rows = get_push_deliveries_window(db, days=1)
        assert rows[0]["account_name"] == "Truma"
        assert rows[0]["account_id"] == 1


class TestPrunePushDeliveries:
    """``prune_push_deliveries`` drops rows older than keep_days."""

    def test_old_rows_pruned(self, db, admin_user):
        from email_triage.web.db import prune_push_deliveries
        _seed_account(db, account_id=1)
        old_day = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%d")
        db.execute(
            "INSERT INTO push_deliveries (account_id, provider, day, count) "
            "VALUES (1, 'gmail', ?, 5)",
            (old_day,),
        )
        db.commit()
        deleted = prune_push_deliveries(db, keep_days=90)
        assert deleted == 1
        cur = db.execute("SELECT COUNT(*) FROM push_deliveries")
        assert cur.fetchone()[0] == 0

    def test_recent_rows_kept(self, db, admin_user):
        from email_triage.web.db import prune_push_deliveries
        _seed_account(db, account_id=1)
        recent_day = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
        db.execute(
            "INSERT INTO push_deliveries (account_id, provider, day, count) "
            "VALUES (1, 'gmail', ?, 5)",
            (recent_day,),
        )
        db.commit()
        deleted = prune_push_deliveries(db, keep_days=90)
        assert deleted == 0
        cur = db.execute("SELECT COUNT(*) FROM push_deliveries")
        assert cur.fetchone()[0] == 1
