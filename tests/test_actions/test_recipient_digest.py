"""Tests for the per-recipient per-account daily digest."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from email_triage.actions.recipient_digest import (
    HIPAA_REASON_BY_SOURCE,
    HIPAA_REASON_DEFAULT,
    MIN_RESEND_INTERVAL_HOURS,
    build_custom_digest_subject,
    gather_digest_rows,
    get_last_sent,
    mark_sent,
    parse_send_at_hour,
    render_html,
    render_plain,
    should_fire,
)
from email_triage.actions.digest_configs import (
    DigestConfig, DigestFilter, DigestSchedule,
)
from email_triage.web.db import init_db, set_setting


# ---------------------------------------------------------------------------
# build_custom_digest_subject — cadence + filter-driven subject builder
# ---------------------------------------------------------------------------


def _cfg(name="", cadence="daily", categories=None) -> DigestConfig:
    return DigestConfig(
        kind="custom",
        name=name,
        schedule=DigestSchedule(cadence=cadence),
        filter=DigestFilter(categories=list(categories or [])),
    )


def _now() -> datetime:
    # Thursday, May 7, 2026 — fixed local datetime for deterministic
    # date_str output.
    return datetime(2026, 5, 7, 8, 10)


def test_subject_no_categories_falls_back_to_name():
    cfg = _cfg(name="AI Newsletters", cadence="daily")
    out = build_custom_digest_subject(cfg, _now())
    assert out == "Your Daily AI Newsletters Digest — Thursday, May 07, 2026"


def test_subject_no_categories_no_name_falls_back_to_email():
    cfg = _cfg(name="", cadence="daily")
    out = build_custom_digest_subject(cfg, _now())
    assert out == "Your Daily Email Digest — Thursday, May 07, 2026"


def test_subject_single_category_pluralizes_singular_slug():
    cfg = _cfg(cadence="daily", categories=["newsletter"])
    out = build_custom_digest_subject(cfg, _now())
    assert out == "Your Daily Newsletters Digest — Thursday, May 07, 2026"


def test_subject_single_category_already_plural_kept():
    cfg = _cfg(cadence="daily", categories=["newsletters"])
    out = build_custom_digest_subject(cfg, _now())
    assert out == "Your Daily Newsletters Digest — Thursday, May 07, 2026"


def test_subject_single_category_with_hyphen_slug_titlecased():
    cfg = _cfg(cadence="monthly", categories=["security-alerts"])
    out = build_custom_digest_subject(cfg, _now())
    # Already ends in "s" → no extra pluralize
    assert out == "Your Monthly Security Alerts Digest — Thursday, May 07, 2026"


def test_subject_multiple_categories_first_plus_count():
    cfg = _cfg(
        cadence="weekly",
        categories=["newsletter", "promotions", "alerts"],
    )
    out = build_custom_digest_subject(cfg, _now())
    assert out == "Your Weekly Newsletters +2 Digest — Thursday, May 07, 2026"


def test_subject_cadence_reflects_schedule():
    for cadence, expected_token in (
        ("daily", "Daily"),
        ("weekly", "Weekly"),
        ("monthly", "Monthly"),
    ):
        cfg = _cfg(name="X", cadence=cadence)
        out = build_custom_digest_subject(cfg, _now())
        assert f"Your {expected_token} X Digest" in out


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db():
    return init_db(":memory:")


def _seed_run(
    db,
    *,
    account_id: int,
    created_at: str,
    results: list[dict],
):
    """Insert one triage_runs row with the given results."""
    # Seed a user first to satisfy email_accounts.user_id FK.
    db.execute(
        "INSERT OR IGNORE INTO users (id, email, name, role, created_at) "
        "VALUES (1, 'u@e.com', 'U', 'user', ?)",
        (created_at,),
    )
    db.execute(
        "INSERT OR IGNORE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, 1, 'TestAcct', 'imap', '{}', ?, ?)",
        (account_id, created_at, created_at),
    )
    db.commit()
    db.execute(
        "INSERT INTO triage_runs "
        "(account_id, account_name, query, total_messages, "
        " results_json, errors_json, elapsed_secs, created_at) "
        "VALUES (?, 'TestAcct', 'is:unread', ?, ?, '[]', 0, ?)",
        (account_id, len(results), json.dumps(results), created_at),
    )
    db.commit()


def _row(
    *,
    sender="alice@example.com",
    subject="Hello world",
    category="newsletter",
    reason="Bulk send + unsubscribe link present",
    source="llm",
    status="ok",
    date=None,
):
    return {
        "message_id": "abc",
        "sender": sender,
        "subject": subject,
        "category": category,
        "reason": reason,
        "source": source,
        "status": status,
        "date": date or "2026-05-02T08:14:00+00:00",
    }


# ---------------------------------------------------------------------------
# parse_send_at_hour
# ---------------------------------------------------------------------------


class TestParseSendAtHour:
    def test_valid_hours(self):
        assert parse_send_at_hour("00:10") == 0
        assert parse_send_at_hour("08:10") == 8
        assert parse_send_at_hour("23:10") == 23

    def test_invalid_returns_none(self):
        assert parse_send_at_hour(None) is None
        assert parse_send_at_hour("") is None
        assert parse_send_at_hour("garbage") is None
        assert parse_send_at_hour("24:10") is None
        assert parse_send_at_hour("-1:10") is None


# ---------------------------------------------------------------------------
# should_fire — feature toggle, hour match, idempotence window
# ---------------------------------------------------------------------------


class TestShouldFire:
    def test_disabled_never_fires(self):
        now = datetime(2026, 5, 2, 8, 0, tzinfo=timezone.utc)
        cfg = {
            "recipient_digest_enabled": False,
            "recipient_digest_send_at": "08:10",
        }
        assert not should_fire(
            account_cfg=cfg, last_sent_iso=None, now=now,
        )

    def test_no_send_at_never_fires(self):
        now = datetime(2026, 5, 2, 8, 0, tzinfo=timezone.utc)
        cfg = {"recipient_digest_enabled": True}
        assert not should_fire(
            account_cfg=cfg, last_sent_iso=None, now=now,
        )

    def test_hour_match_fires(self):
        now = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        cfg = {
            "recipient_digest_enabled": True,
            "recipient_digest_send_at": "08:10",
        }
        assert should_fire(
            account_cfg=cfg, last_sent_iso=None, now=now,
        )

    def test_hour_mismatch_skips(self):
        now = datetime(2026, 5, 2, 9, 14, tzinfo=timezone.utc)
        cfg = {
            "recipient_digest_enabled": True,
            "recipient_digest_send_at": "08:10",
        }
        assert not should_fire(
            account_cfg=cfg, last_sent_iso=None, now=now,
        )

    def test_idempotence_window_blocks(self):
        """Even with hour match + enabled, refuse if last_sent was
        within MIN_RESEND_INTERVAL_HOURS."""
        now = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        recent = now - timedelta(hours=12)
        cfg = {
            "recipient_digest_enabled": True,
            "recipient_digest_send_at": "08:10",
        }
        assert not should_fire(
            account_cfg=cfg,
            last_sent_iso=recent.isoformat(),
            now=now,
        )

    def test_past_idempotence_window_fires(self):
        now = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        ancient = now - timedelta(hours=MIN_RESEND_INTERVAL_HOURS + 1)
        cfg = {
            "recipient_digest_enabled": True,
            "recipient_digest_send_at": "08:10",
        }
        assert should_fire(
            account_cfg=cfg,
            last_sent_iso=ancient.isoformat(),
            now=now,
        )

    def test_malformed_last_sent_does_not_block(self):
        now = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        cfg = {
            "recipient_digest_enabled": True,
            "recipient_digest_send_at": "08:10",
        }
        assert should_fire(
            account_cfg=cfg,
            last_sent_iso="not-a-date",
            now=now,
        )


# ---------------------------------------------------------------------------
# gather_digest_rows
# ---------------------------------------------------------------------------


class TestGatherDigestRows:
    def test_pulls_rows_in_window(self, db):
        now_iso = datetime.now(timezone.utc).isoformat()
        _seed_run(db, account_id=1, created_at=now_iso, results=[
            _row(sender="a@e.com", category="newsletter"),
            _row(sender="b@e.com", category="reply"),
        ])
        since = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        rows = gather_digest_rows(db, account_id=1, since_iso=since)
        assert len(rows) == 2
        assert {r["sender"] for r in rows} == {"a@e.com", "b@e.com"}

    def test_skips_non_ok_status(self, db):
        now_iso = datetime.now(timezone.utc).isoformat()
        _seed_run(db, account_id=1, created_at=now_iso, results=[
            _row(status="ok", sender="ok@e.com"),
            _row(status="skipped", sender="skip@e.com"),
            _row(status="error", sender="err@e.com"),
        ])
        since = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        rows = gather_digest_rows(db, account_id=1, since_iso=since)
        assert {r["sender"] for r in rows} == {"ok@e.com"}

    def test_skips_rows_outside_window(self, db):
        old = (
            datetime.now(timezone.utc) - timedelta(hours=48)
        ).isoformat()
        recent = datetime.now(timezone.utc).isoformat()
        _seed_run(db, account_id=1, created_at=old, results=[
            _row(sender="old@e.com"),
        ])
        # Seed a second run for the same account at a recent time.
        db.execute(
            "INSERT INTO triage_runs "
            "(account_id, account_name, query, total_messages, "
            " results_json, errors_json, elapsed_secs, created_at) "
            "VALUES (1, 'TestAcct', 'is:unread', 1, ?, '[]', 0, ?)",
            (json.dumps([_row(sender="new@e.com")]), recent),
        )
        db.commit()
        since = (
            datetime.now(timezone.utc) - timedelta(hours=24)
        ).isoformat()
        rows = gather_digest_rows(db, account_id=1, since_iso=since)
        assert {r["sender"] for r in rows} == {"new@e.com"}

    def test_empty_returns_empty(self, db):
        # No accounts, no runs.
        rows = gather_digest_rows(
            db, account_id=99,
            since_iso=datetime.now(timezone.utc).isoformat(),
        )
        assert rows == []


# ---------------------------------------------------------------------------
# Rendering — reason redaction (Option B)
# ---------------------------------------------------------------------------


class TestReasonRedaction:
    def test_standard_mode_passes_reason_verbatim(self):
        rows = [_row(reason="Patient confirmed appt", source="llm")]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=False,
        )
        assert "Patient confirmed appt" in html

    def test_hipaa_mode_redacts_reason_via_source_map(self):
        for source, expected_phrase in HIPAA_REASON_BY_SOURCE.items():
            rows = [_row(
                reason="THIS SHOULD BE REDACTED — patient PHI",
                source=source,
            )]
            html = render_html(
                rows=rows, account_name="A", account_email="x@y.com",
                hipaa=True,
            )
            assert expected_phrase in html
            assert "THIS SHOULD BE REDACTED" not in html

    def test_hipaa_mode_unknown_source_falls_back_to_default(self):
        rows = [_row(reason="raw", source="unknown_source")]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=True,
        )
        assert HIPAA_REASON_DEFAULT in html
        assert "raw" not in html

    def test_hipaa_mode_subject_and_sender_pass_through(self):
        """Subject + sender are NOT new PHI exposure — already in
        same mailbox. Only reason is redacted under Option B."""
        rows = [_row(
            sender="alice@example.com",
            subject="Confidential: Q2 numbers",
            reason="raw reason should not leak",
            source="llm",
        )]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=True,
        )
        assert "alice@example.com" in html
        assert "Confidential: Q2 numbers" in html
        assert "raw reason should not leak" not in html

    def test_standard_mode_truncates_long_reason(self):
        long = "x" * 500
        rows = [_row(reason=long, source="llm")]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=False,
        )
        # Truncated to 119 chars + ellipsis.
        assert "x" * 200 not in html
        assert "…" in html


# ---------------------------------------------------------------------------
# Rendering — HTML + plaintext shape
# ---------------------------------------------------------------------------


class TestRenderShape:
    def test_html_includes_all_columns(self):
        rows = [_row()]
        html = render_html(
            rows=rows, account_name="My Mail", account_email="x@y.com",
            hipaa=False,
        )
        # Headers
        assert "When" in html
        assert "Sender" in html
        assert "Category" in html
        assert "Subject" in html
        assert "Why" in html
        # Body data
        assert "alice@example.com" in html
        assert "Hello world" in html
        assert "newsletter" in html

    def test_plain_includes_all_columns(self):
        rows = [_row()]
        text = render_plain(
            rows=rows, account_name="My Mail", account_email="x@y.com",
            hipaa=False,
        )
        assert "alice@example.com" in text
        assert "Hello world" in text
        assert "newsletter" in text

    def test_hipaa_banner_renders(self):
        rows = [_row()]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=True,
        )
        assert "HIPAA mode" in html

    def test_html_escapes_user_content(self):
        rows = [_row(subject="<script>alert(1)</script>")]
        html = render_html(
            rows=rows, account_name="A", account_email="x@y.com",
            hipaa=False,
        )
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


# ---------------------------------------------------------------------------
# Idempotence helpers
# ---------------------------------------------------------------------------


class TestIdempotenceHelpers:
    def test_get_last_sent_none_when_unset(self, db):
        assert get_last_sent(db, 42) is None

    def test_mark_sent_then_get(self, db):
        now = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        mark_sent(db, 42, now, 17)
        assert get_last_sent(db, 42) == now.isoformat()

    def test_mark_sent_overwrites(self, db):
        a = datetime(2026, 5, 2, 8, 14, tzinfo=timezone.utc)
        b = datetime(2026, 5, 3, 8, 14, tzinfo=timezone.utc)
        mark_sent(db, 42, a, 1)
        mark_sent(db, 42, b, 5)
        assert get_last_sent(db, 42) == b.isoformat()
