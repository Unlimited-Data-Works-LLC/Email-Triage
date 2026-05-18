"""Tests for email watches storage + matcher (#100).

Covers schema CRUD, every filter dimension, scope resolution,
HIPAA exclusion from all-accounts scope, validation, payload
shaping (HIPAA redaction + body always omitted), and the audit
row writer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage.web import email_watches as W
from email_triage.web.db import init_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def db():
    conn = init_db(":memory:")
    yield conn
    conn.close()


def _make_account_row(db, *, account_id: int = 1, hipaa: bool = False):
    """Insert a minimal email_accounts row so FK-bound watches don't blow up."""
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "Operator A", "user", now),
    )
    user_id = db.execute(
        "SELECT id FROM users WHERE email='user@example.com'"
    ).fetchone()["id"]
    db.execute(
        "INSERT INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        "created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            account_id, user_id, "acct1", "imap",
            json.dumps({"host": "mail.example.com", "username": "u@example.com"}),
            1 if hipaa else 0, now, now,
        ),
    )
    db.commit()
    return account_id


def _make_watch(**overrides):
    base = dict(
        watch_id="",
        name="Test Watch",
        enabled=True,
        account_id=1,
        filter=W.WatchFilter(from_addr="boss@"),
        actions=W.WatchActions(
            escalate=W.EscalateAction(enabled=True, notify_email="ops@example.com"),
        ),
    )
    base.update(overrides)
    return W.EmailWatch(**base)


# ---------------------------------------------------------------------------
# Storage CRUD
# ---------------------------------------------------------------------------


class TestStorage:
    def test_upsert_mints_id_and_timestamps(self, db):
        _make_account_row(db)
        w = _make_watch()
        saved = W.upsert_watch(db, w)
        assert saved.watch_id.startswith("watch_")
        assert saved.created_at
        assert saved.updated_at

    def test_get_returns_round_trip(self, db):
        _make_account_row(db)
        w = _make_watch(filter=W.WatchFilter(
            from_addr="boss@",
            from_domain="example.com",
            subject_contains="urgent",
        ))
        saved = W.upsert_watch(db, w)
        loaded = W.get_watch(db, saved.watch_id)
        assert loaded is not None
        assert loaded.filter.from_addr == "boss@"
        assert loaded.filter.from_domain == "example.com"
        assert loaded.filter.subject_contains == "urgent"
        assert loaded.actions.escalate.enabled is True

    def test_delete_removes_row(self, db):
        _make_account_row(db)
        w = _make_watch()
        saved = W.upsert_watch(db, w)
        assert W.delete_watch(db, saved.watch_id) is True
        assert W.get_watch(db, saved.watch_id) is None

    def test_list_includes_all_accounts_row(self, db):
        _make_account_row(db, account_id=1)
        per_acct = W.upsert_watch(db, _make_watch(name="per-acct"))
        all_acct = W.upsert_watch(
            db,
            _make_watch(name="every", account_id=None),
        )
        rows = W.list_watches(db, account_id=1, include_all_accounts=True)
        ids = {r.watch_id for r in rows}
        assert per_acct.watch_id in ids
        assert all_acct.watch_id in ids

    def test_list_excludes_all_accounts_when_flag_off(self, db):
        _make_account_row(db, account_id=1)
        per_acct = W.upsert_watch(db, _make_watch(name="per-acct"))
        all_acct = W.upsert_watch(
            db,
            _make_watch(name="every", account_id=None),
        )
        rows = W.list_watches(db, account_id=1, include_all_accounts=False)
        ids = {r.watch_id for r in rows}
        assert per_acct.watch_id in ids
        assert all_acct.watch_id not in ids


# ---------------------------------------------------------------------------
# Matcher — every dimension
# ---------------------------------------------------------------------------


class TestMatcher:
    def test_disabled_watch_never_matches(self):
        w = _make_watch(enabled=False)
        assert not W.matches(w, sender="boss@example.com", subject="hi")

    def test_from_addr_substring(self):
        w = _make_watch(filter=W.WatchFilter(from_addr="boss@"))
        assert W.matches(w, sender="boss@example.com", subject="hi")
        assert not W.matches(w, sender="other@example.com", subject="hi")

    def test_from_addr_with_display_name(self):
        w = _make_watch(filter=W.WatchFilter(from_addr="boss@"))
        # Display-name + addr-spec form; matcher must extract the addr.
        assert W.matches(
            w, sender="Operator A <boss@example.com>", subject="hi",
        )

    def test_from_addr_case_insensitive(self):
        w = _make_watch(filter=W.WatchFilter(from_addr="BOSS@"))
        assert W.matches(w, sender="boss@example.com", subject="hi")

    def test_from_domain(self):
        w = _make_watch(filter=W.WatchFilter(from_domain="example.com"))
        assert W.matches(w, sender="x@example.com", subject="hi")
        assert not W.matches(w, sender="x@other.test", subject="hi")

    def test_from_domain_with_at_prefix(self):
        # Tolerate "@example.com" vs "example.com" interchangeably.
        w = _make_watch(filter=W.WatchFilter(from_domain="@example.com"))
        assert W.matches(w, sender="x@example.com", subject="hi")

    def test_subject_contains(self):
        w = _make_watch(filter=W.WatchFilter(subject_contains="invoice"))
        assert W.matches(w, sender="x@y.test", subject="Invoice #123")
        assert not W.matches(w, sender="x@y.test", subject="hello")

    def test_keyword_matches_subject_or_body(self):
        w = _make_watch(filter=W.WatchFilter(keyword="urgent"))
        assert W.matches(w, sender="x@y.test", subject="URGENT issue")
        assert W.matches(
            w, sender="x@y.test", subject="hi", body_text="this is urgent",
        )
        assert not W.matches(
            w, sender="x@y.test", subject="hi", body_text="quiet day",
        )

    def test_combined_filters_are_and(self):
        w = _make_watch(filter=W.WatchFilter(
            from_domain="example.com", subject_contains="invoice",
        ))
        assert W.matches(w, sender="x@example.com", subject="Invoice #1")
        # Domain ok, subject miss -> no match.
        assert not W.matches(w, sender="x@example.com", subject="hello")
        # Subject ok, domain miss -> no match.
        assert not W.matches(w, sender="x@other.test", subject="invoice 1")

    def test_advanced_only_returns_true(self):
        w = _make_watch(filter=W.WatchFilter(advanced='from:"boss@"'))
        # Matcher delegates advanced to the upstream provider; permissive.
        assert W.matches(w, sender="anyone@anywhere.test", subject="x")

    def test_empty_filter_matches_everything(self):
        w = _make_watch(filter=W.WatchFilter())
        assert W.matches(w, sender="x@y.test", subject="z")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


class TestValidate:
    def test_missing_name_errors(self):
        w = _make_watch(name="")
        errs = W.validate(w)
        assert any("name" in e.lower() for e in errs)

    def test_no_filter_errors(self):
        w = _make_watch(filter=W.WatchFilter())
        errs = W.validate(w)
        assert any("filter" in e.lower() for e in errs)

    def test_no_actions_errors(self):
        w = _make_watch(actions=W.WatchActions())
        errs = W.validate(w)
        assert any("action" in e.lower() for e in errs)

    def test_webhook_enabled_without_url_errors(self):
        w = _make_watch(actions=W.WatchActions(
            webhook=W.WebhookAction(enabled=True, url=""),
        ))
        errs = W.validate(w)
        assert any("url" in e.lower() for e in errs)

    def test_webhook_invalid_scheme_errors(self):
        w = _make_watch(actions=W.WatchActions(
            webhook=W.WebhookAction(enabled=True, url="not-a-url"),
        ))
        errs = W.validate(w)
        assert any("http" in e.lower() for e in errs)

    def test_valid_watch_no_errors(self):
        w = _make_watch()
        assert W.validate(w) == []


# ---------------------------------------------------------------------------
# Payload shaping — HIPAA redaction + body always omitted
# ---------------------------------------------------------------------------


class TestPayload:
    def test_standard_mode_keeps_subject_and_sender(self):
        w = _make_watch()
        out = W.shape_webhook_payload(
            w, sender="Operator A <a@example.com>",
            subject="Hello", body_text="Body here",
            category="newsletter",
            account_id=1, account_name="acct1",
            message_id="m1", hipaa=False,
        )
        assert out["sender"] == "Operator A <a@example.com>"
        assert out["subject"] == "Hello"
        assert out["category"] == "newsletter"
        assert out["redaction"] == "standard"
        # Body is never included regardless of mode.
        assert "body" not in out
        assert "body_text" not in out

    def test_hipaa_redacts_subject_and_sender(self):
        w = _make_watch()
        out = W.shape_webhook_payload(
            w, sender="Dr. Operator A <a@example.com>",
            subject="patient appointment 3pm",
            body_text="should not appear",
            category="action-required",
            account_id=1, account_name="acct1",
            message_id="m1", hipaa=True,
        )
        # First name + domain only.
        assert out["sender"] == "Operator @ example.com"
        assert out["subject"] == "[redacted]"
        assert out["redaction"] == "hipaa_redacted"
        assert "body" not in out
        assert "body_text" not in out


# ---------------------------------------------------------------------------
# Audit row writer
# ---------------------------------------------------------------------------


class TestAudit:
    def test_audit_row_recorded(self, db):
        _make_account_row(db)
        w = _make_watch()
        saved = W.upsert_watch(db, w)
        rid = W.write_audit_row(
            db,
            watch=saved,
            account_id=1,
            actor_user_id=None,
            message_id="m1",
            escalate_fired=True,
            webhook_fired=False,
            redaction="standard",
        )
        assert rid > 0
        row = db.execute(
            "SELECT outcome, account_id, message_id, detail "
            "FROM access_log WHERE id = ?",
            (rid,),
        ).fetchone()
        assert row["outcome"] == "watch_fired"
        assert row["account_id"] == 1
        assert row["message_id"] == "m1"
        detail = json.loads(row["detail"])
        assert detail["watch_id"] == saved.watch_id
        assert detail["escalate"] is True
        assert detail["webhook"] is False
        assert detail["redaction"] == "standard"
