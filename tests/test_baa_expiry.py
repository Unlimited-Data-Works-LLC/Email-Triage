"""Tests for :mod:`email_triage.baa_expiry` (#169 Wave 2-α — I7).

Covers:

* Bucket math via ``classify_bucket`` — every threshold including
  the boundary days (0, 1, 7, 8, 30, 31).
* ``compute_expiry_buckets`` sorting + non-BAA rows skipping.
* ``auto_disable_expired_for_hipaa_accounts`` invariants:
    - HIPAA-flagged accounts get their FK cleared.
    - Non-HIPAA accounts keep their FK.
    - Audit row appended per disabled account.
    - Idempotent (re-running on already-cleared state is a no-op).
* ``health_status_block`` + ``build_banner_context`` shape pins.
"""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from email_triage.baa_expiry import (
    auto_disable_expired_for_hipaa_accounts,
    baa_expiry_daily_sweep,
    build_banner_context,
    classify_bucket,
    compute_expiry_buckets,
    gather_for_daily_email,
    health_status_block,
)
from email_triage.web.db import (
    create_ai_backend,
    create_email_account,
    init_db,
    set_account_style_learning_backend,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    """Fresh in-memory DB with v26 schema applied."""
    return init_db(":memory:")


@pytest.fixture
def user_id(db) -> int:
    """Insert a single admin user; return its id."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("admin@example.com", "Admin", "admin", now),
    )
    db.commit()
    return int(cur.lastrowid)


def _insert_backend(
    db,
    *,
    name: str,
    type_: str = "azure_openai",
    baa_certified: bool = True,
    baa_expires_at: str | None = None,
    enabled: bool = True,
    created_by: int | None = None,
) -> int:
    return create_ai_backend(
        db,
        name=name,
        type_=type_,
        endpoint="https://example.com/v1",
        api_key_secret_ref=None,
        model="gpt-4o-mini",
        baa_certified=baa_certified,
        baa_expires_at=baa_expires_at,
        enabled=enabled,
        created_by=created_by,
    )


def _iso_today_plus(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# classify_bucket — pure threshold math
# ---------------------------------------------------------------------------

class TestClassifyBucket:
    def test_not_baa_certified_is_fresh(self):
        bucket, days = classify_bucket(
            baa_certified=False, baa_expires_at=None,
        )
        assert bucket == "fresh"
        assert days is None

    def test_baa_certified_without_expiry_is_fresh(self):
        # Defensive — CHECK constraint should prevent this but the
        # bucket math falls back to fresh rather than crashing.
        bucket, days = classify_bucket(
            baa_certified=True, baa_expires_at=None,
        )
        assert bucket == "fresh"

    def test_far_future_is_fresh(self):
        bucket, days = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(365),
        )
        assert bucket == "fresh"
        assert days == 365

    def test_31_days_is_fresh(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(31),
        )
        assert bucket == "fresh"

    def test_30_days_is_soon(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(30),
        )
        assert bucket == "expiring_soon"

    def test_8_days_is_soon(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(8),
        )
        assert bucket == "expiring_soon"

    def test_7_days_is_urgent(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(7),
        )
        assert bucket == "expiring_urgent"

    def test_1_day_is_urgent(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(1),
        )
        assert bucket == "expiring_urgent"

    def test_today_is_urgent(self):
        # Same day = days==0 = still urgent, not yet expired.
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=date.today().isoformat(),
        )
        assert bucket == "expiring_urgent"

    def test_yesterday_is_expired(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(-1),
        )
        assert bucket == "expired"

    def test_one_year_ago_is_expired(self):
        bucket, _ = classify_bucket(
            baa_certified=True,
            baa_expires_at=_iso_today_plus(-365),
        )
        assert bucket == "expired"


# ---------------------------------------------------------------------------
# compute_expiry_buckets — DB-backed
# ---------------------------------------------------------------------------

class TestComputeBuckets:
    def test_empty_db_returns_empty_buckets(self, db):
        out = compute_expiry_buckets(db)
        for key in ("fresh", "expiring_soon", "expiring_urgent", "expired"):
            assert out[key] == []

    def test_mixed_rows_sorted_within_bucket(self, db):
        _insert_backend(
            db, name="A-soonest-urgent",
            baa_expires_at=_iso_today_plus(2),
        )
        _insert_backend(
            db, name="B-later-urgent",
            baa_expires_at=_iso_today_plus(6),
        )
        _insert_backend(
            db, name="C-soon",
            baa_expires_at=_iso_today_plus(20),
        )
        _insert_backend(
            db, name="D-fresh",
            baa_expires_at=_iso_today_plus(180),
        )
        _insert_backend(
            db, name="E-expired",
            baa_expires_at=_iso_today_plus(-10),
        )
        out = compute_expiry_buckets(db)
        assert [r.name for r in out["expiring_urgent"]] == [
            "A-soonest-urgent", "B-later-urgent",
        ]
        assert [r.name for r in out["expiring_soon"]] == ["C-soon"]
        assert [r.name for r in out["fresh"]] == ["D-fresh"]
        assert [r.name for r in out["expired"]] == ["E-expired"]

    def test_non_baa_row_lands_in_fresh(self, db):
        _insert_backend(
            db, name="Ollama-local",
            type_="ollama",
            baa_certified=False,
        )
        out = compute_expiry_buckets(db)
        assert len(out["fresh"]) == 1
        assert out["fresh"][0].name == "Ollama-local"


# ---------------------------------------------------------------------------
# auto_disable_expired_for_hipaa_accounts
# ---------------------------------------------------------------------------

class TestAutoDisable:
    def test_hipaa_account_with_expired_backend_is_cleared(
        self, db, user_id,
    ):
        bid = _insert_backend(
            db, name="ExpiredAzure",
            baa_expires_at=_iso_today_plus(-5),
        )
        # HIPAA-flagged account; FK -> the expired backend.
        aid = create_email_account(
            db, user_id, "Test", "imap", {}, hipaa=True,
        )
        set_account_style_learning_backend(db, aid, bid)

        disabled = auto_disable_expired_for_hipaa_accounts(db)
        assert len(disabled) == 1
        assert disabled[0]["account_id"] == aid
        assert disabled[0]["backend_id"] == bid

        # FK has been cleared.
        row = db.execute(
            "SELECT style_learning_backend_id FROM email_accounts "
            "WHERE id = ?",
            (aid,),
        ).fetchone()
        assert (
            row["style_learning_backend_id"]
            if hasattr(row, "keys") else row[0]
        ) is None

    def test_non_hipaa_account_with_expired_backend_is_preserved(
        self, db, user_id,
    ):
        bid = _insert_backend(
            db, name="ExpiredAzure",
            baa_expires_at=_iso_today_plus(-5),
        )
        aid = create_email_account(
            db, user_id, "Test", "imap", {}, hipaa=False,
        )
        set_account_style_learning_backend(db, aid, bid)

        disabled = auto_disable_expired_for_hipaa_accounts(db)
        assert disabled == []

        # FK still points at the expired backend.
        row = db.execute(
            "SELECT style_learning_backend_id FROM email_accounts "
            "WHERE id = ?",
            (aid,),
        ).fetchone()
        bid_after = (
            row["style_learning_backend_id"]
            if hasattr(row, "keys") else row[0]
        )
        assert bid_after == bid

    def test_idempotent_re_run_is_noop(self, db, user_id):
        bid = _insert_backend(
            db, name="ExpiredAzure",
            baa_expires_at=_iso_today_plus(-5),
        )
        aid = create_email_account(
            db, user_id, "Test", "imap", {}, hipaa=True,
        )
        set_account_style_learning_backend(db, aid, bid)
        first = auto_disable_expired_for_hipaa_accounts(db)
        second = auto_disable_expired_for_hipaa_accounts(db)
        assert len(first) == 1
        assert second == []

    def test_audit_row_appended_per_disabled_account(
        self, db, user_id,
    ):
        bid = _insert_backend(
            db, name="ExpiredAzure",
            baa_expires_at=_iso_today_plus(-3),
        )
        aid = create_email_account(
            db, user_id, "Test", "imap", {}, hipaa=True,
        )
        set_account_style_learning_backend(db, aid, bid)
        auto_disable_expired_for_hipaa_accounts(db)

        rows = db.execute(
            "SELECT operation, outcome, detail FROM hipaa_access_events "
            "WHERE account_id = ?",
            (aid,),
        ).fetchall()
        assert len(rows) >= 1
        ops = [r["operation"] for r in rows]
        assert "style_learning_backend_baa_expired" in ops

    def test_fresh_backend_not_touched(self, db, user_id):
        bid = _insert_backend(
            db, name="FreshAzure",
            baa_expires_at=_iso_today_plus(180),
        )
        aid = create_email_account(
            db, user_id, "Test", "imap", {}, hipaa=True,
        )
        set_account_style_learning_backend(db, aid, bid)
        disabled = auto_disable_expired_for_hipaa_accounts(db)
        assert disabled == []


# ---------------------------------------------------------------------------
# Surface helpers — banner + health-block + daily-email gather
# ---------------------------------------------------------------------------

class TestSurfaceHelpers:
    def test_banner_silent_on_clean_db(self, db):
        ctx = build_banner_context(db)
        assert ctx["severity"] == "silent"

    def test_banner_soft_on_only_30_day_row(self, db):
        _insert_backend(
            db, name="SoonAzure",
            baa_expires_at=_iso_today_plus(20),
        )
        ctx = build_banner_context(db)
        assert ctx["severity"] == "soft"
        assert len(ctx["expiring_soon"]) == 1

    def test_banner_loud_on_urgent_or_expired(self, db):
        _insert_backend(
            db, name="UrgentAzure",
            baa_expires_at=_iso_today_plus(3),
        )
        ctx = build_banner_context(db)
        assert ctx["severity"] == "loud"

        # Reset + try expired-only
        db2 = init_db(":memory:")
        _insert_backend(
            db2, name="ExpiredAzure",
            baa_expires_at=_iso_today_plus(-10),
        )
        ctx2 = build_banner_context(db2)
        assert ctx2["severity"] == "loud"

    def test_health_status_block_shape(self, db):
        _insert_backend(
            db, name="A", baa_expires_at=_iso_today_plus(-5),
        )
        _insert_backend(
            db, name="B", baa_expires_at=_iso_today_plus(3),
        )
        _insert_backend(
            db, name="C", baa_expires_at=_iso_today_plus(20),
        )
        block = health_status_block(db, auto_disabled_count=7)
        assert block == {
            "expiring_soon": 2,  # urgent + soon merge for Nagios.
            "expired": 1,
            "expired_hipaa_accounts_disabled": 7,
        }

    def test_gather_for_daily_email_returns_none_on_clean_day(
        self, db,
    ):
        _insert_backend(
            db, name="Fresh", baa_expires_at=_iso_today_plus(180),
        )
        assert gather_for_daily_email(db) is None

    def test_gather_for_daily_email_returns_buckets_when_in_scope(
        self, db,
    ):
        _insert_backend(
            db, name="A", baa_expires_at=_iso_today_plus(2),
        )
        out = gather_for_daily_email(db)
        assert out is not None
        assert len(out["expiring_urgent"]) == 1


# ---------------------------------------------------------------------------
# Full sweep — combine bucket + auto-disable
# ---------------------------------------------------------------------------

class TestDailySweep:
    def test_sweep_returns_summary(self, db, user_id):
        bid = _insert_backend(
            db, name="A", baa_expires_at=_iso_today_plus(-2),
        )
        aid = create_email_account(
            db, user_id, "Acc", "imap", {}, hipaa=True,
        )
        set_account_style_learning_backend(db, aid, bid)
        summary = baa_expiry_daily_sweep(db)
        assert summary["expired"] == 1
        assert summary["expiring_soon"] == 0
        assert summary["expiring_urgent"] == 0
        assert len(summary["auto_disabled"]) == 1
        assert "swept_at" in summary
