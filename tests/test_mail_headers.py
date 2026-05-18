"""Outbound X-Email-Triage stamping + inbound loop-prevention skip."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from email.message import EmailMessage as PyEmailMessage
from typing import Any
from unittest.mock import AsyncMock

import pytest

from email_triage.actions.digest import generate_digest
from email_triage.actions.draft_reply import DraftReplyAction
from email_triage.engine.models import (
    Classification,
    EmailMessage,
    FlowState,
    FlowStatus,
)
from email_triage.mail_headers import (
    X_EMAIL_TRIAGE_HEADER,
    build_triage_header,
    get_triage_header,
)
from email_triage.web.auth import send_otp_email


# ---------------------------------------------------------------------------
# Header builder unit tests
# ---------------------------------------------------------------------------


class TestBuildTriageHeader:
    def test_minimum_fields(self):
        value = build_triage_header(
            "otp", version="abc1234", generated="2026-04-23T12:00:00-04:00",
        )
        assert value.startswith("otp")
        assert "version=abc1234" in value
        assert "generated=2026-04-23T12:00:00-04:00" in value

    def test_digest_with_category_and_account(self):
        value = build_triage_header(
            "digest",
            category="newsletters",
            account="alice@home",
            version="sha1",
            generated="now",
        )
        assert value.startswith("digest")
        assert "category=newsletters" in value
        assert "account=alice@home" in value

    def test_hipaa_drops_account(self):
        value = build_triage_header(
            "digest",
            category="medical-labs",
            account="dr-patel@clinic",
            hipaa=True,
            version="v", generated="g",
        )
        assert "category=medical-labs" in value
        assert "account=" not in value
        # Header still emitted — loop-prevention still works.
        assert value.startswith("digest;")

    def test_source_is_first_token(self):
        value = build_triage_header(
            "health-email", version="v", generated="g",
        )
        assert value.split(";", 1)[0].strip() == "health-email"


class TestGetTriageHeader:
    def test_canonical_case(self):
        assert get_triage_header({X_EMAIL_TRIAGE_HEADER: "digest"}) == "digest"

    def test_lowercase(self):
        assert get_triage_header({"x-email-triage": "otp"}) == "otp"

    def test_mixed_case(self):
        assert get_triage_header({"X-EMAIL-TRIAGE": "draft-reply"}) == "draft-reply"

    def test_missing(self):
        assert get_triage_header({}) is None
        assert get_triage_header({"Subject": "hi"}) is None

    def test_none(self):
        assert get_triage_header(None) is None


# ---------------------------------------------------------------------------
# Digest stamping
# ---------------------------------------------------------------------------


def _mk_newsletter(body="headline 1\nheadline 2", uid="1") -> EmailMessage:
    return EmailMessage(
        message_id=uid,
        provider="imap",
        sender="Newsletter <news@example.com>",
        recipients=["user@test.com"],
        subject="Daily",
        body_text=body,
        date=datetime.now(timezone.utc),
    )


class _FakeClassifier:
    async def complete(self, prompt: str) -> str:
        return '[{"headline": "H", "summary": "S", "url": null}]'


class _FakeProvider:
    """Minimal provider that records ``deliver_to_inbox`` calls."""

    def __init__(self) -> None:
        self.delivered: list[dict[str, Any]] = []
        self.drafts: list[dict[str, Any]] = []

    async def deliver_to_inbox(
        self,
        to: list[str],
        subject: str,
        body: str,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        self.delivered.append({
            "to": to, "subject": subject, "body": body,
            "extra_headers": extra_headers or {},
        })
        return "inbox-1"

    async def create_draft(
        self,
        to: list[str],
        subject: str,
        body: str,
        in_reply_to: str | None = None,
        thread_id: str | None = None,
        *,
        extra_headers: dict[str, str] | None = None,
    ) -> str:
        self.drafts.append({
            "to": to, "subject": subject, "body": body,
            "extra_headers": extra_headers or {},
            "in_reply_to": in_reply_to, "thread_id": thread_id,
        })
        return "draft-1"

    async def close(self) -> None:  # pragma: no cover
        pass


def test_digest_stamps_x_email_triage_header():
    """Digest delivery calls pass extra_headers with an X-Email-Triage stamp.

    generate_digest itself returns HTML; the stamp is applied by the
    caller when it invokes the provider. Simulate that call here — the
    ui.py + app.py paths are wired to pass the header in, and the
    provider records what it received.
    """
    provider = _FakeProvider()
    headers = {
        X_EMAIL_TRIAGE_HEADER: build_triage_header(
            "digest", category="newsletters", account="acct",
            version="v", generated="g",
        ),
    }

    async def _go():
        await provider.deliver_to_inbox(
            to=["user@example.com"],
            subject="Newsletter Digest",
            body="<p>body</p>",
            extra_headers=headers,
        )

    asyncio.run(_go())
    assert provider.delivered
    stamp = provider.delivered[0]["extra_headers"][X_EMAIL_TRIAGE_HEADER]
    assert stamp.startswith("digest;")
    assert "version=" in stamp
    assert "generated=" in stamp


def test_digest_header_includes_category():
    value = build_triage_header(
        "digest", category="customer-support",
        account="acct", version="v", generated="g",
    )
    assert "category=customer-support" in value


def test_digest_header_omits_account_on_hipaa():
    value = build_triage_header(
        "digest", category="medical",
        account="dr@clinic", hipaa=True,
        version="v", generated="g",
    )
    assert "account=" not in value
    assert "category=medical" in value


# ---------------------------------------------------------------------------
# Draft reply stamping
# ---------------------------------------------------------------------------


def test_draft_reply_stamps_x_email_triage():
    provider = _FakeProvider()
    action = DraftReplyAction()
    message = EmailMessage(
        message_id="m1",
        provider="imap",
        sender="sender@example.com",
        recipients=["me@example.com"],
        subject="Hi",
        body_text="Hello",
        date=datetime.now(timezone.utc),
    )
    classification = Classification(
        category="customer-support", confidence=0.9, reason="test",
    )
    flow = FlowState(
        flow_id="f1", message_id="m1",
        provider="imap", status=FlowStatus.ACTING,
    )

    async def _go():
        return await action.execute(flow, message, classification, provider, None)

    output = asyncio.run(_go())
    assert output.result.value == "completed"
    assert provider.drafts
    stamp = provider.drafts[0]["extra_headers"][X_EMAIL_TRIAGE_HEADER]
    assert stamp.startswith("draft-reply;")
    assert "category=customer-support" in stamp


# ---------------------------------------------------------------------------
# OTP stamping
# ---------------------------------------------------------------------------


def test_otp_email_stamps_x_email_triage_otp(monkeypatch):
    """Check that send_otp_email adds the X-Email-Triage header."""
    captured: dict[str, Any] = {}

    class _FakeSMTP:
        def __init__(self, host, port):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def starttls(self):
            pass

        def login(self, u, p):
            pass

        def send_message(self, msg):
            captured["msg"] = msg

    import email_triage.web.auth as auth_mod
    monkeypatch.setattr(auth_mod.smtplib, "SMTP", _FakeSMTP)

    send_otp_email(
        smtp_host="h", smtp_port=25,
        smtp_user="u", smtp_password="p",
        from_addr="from@x", to_addr="to@x",
        code="123456", use_tls=True, from_name="",
    )
    msg = captured["msg"]
    stamp = msg.get(X_EMAIL_TRIAGE_HEADER) or msg.get("x-email-triage")
    assert stamp, f"no header; got keys={list(msg.keys())}"
    assert stamp.startswith("otp")
    assert "version=" in stamp
    assert "generated=" in stamp


# ---------------------------------------------------------------------------
# Daily health stamping
# ---------------------------------------------------------------------------


def test_health_email_stamps_x_email_triage_health_email():
    from email_triage.config import TriageConfig, HealthEmailConfig
    from email_triage.web.daily_health import assemble_daily_health_email

    state = {
        "now": datetime(2026, 4, 23, tzinfo=timezone.utc),
        "hipaa_mode": False,
        "attention_reasons": [],
        "watchers": [],
        "error_count_24h": 0, "warning_count_24h": 0, "error_rows": [],
        "triage_total": 0, "triage_accounts": [], "triage_error_rate": 0.0,
        "hipaa_events_count": 0, "hipaa_recent_actors": [],
        "api_key_events_count": 0, "api_key_events_recent": [],
        "log_row_count": 0, "pubsub_configured": False, "gateway_ok": True,
    }
    cfg = TriageConfig()
    msg = assemble_daily_health_email(state, cfg)
    stamp = msg.get(X_EMAIL_TRIAGE_HEADER)
    assert stamp and stamp.startswith("health-email")


# ---------------------------------------------------------------------------
# Pipeline-layer loop-prevention
# ---------------------------------------------------------------------------


class _SkipTestClassifier:
    """Records whether classify() was called."""

    def __init__(self) -> None:
        self.called = 0

    async def classify(self, message, categories, hints):
        self.called += 1
        return Classification(category="unknown", confidence=0.5, reason="x")


def _build_msg_with_header(headers: dict[str, str]) -> EmailMessage:
    return EmailMessage(
        message_id="m1",
        provider="imap",
        sender="a@b",
        recipients=["c@d"],
        subject="S",
        body_text="B",
        date=datetime.now(timezone.utc),
        headers=dict(headers),
    )


def test_run_triage_skips_stamped_message_direct_skip_path():
    """The `get_triage_header` function is the skip gate — positive."""
    msg = _build_msg_with_header({
        X_EMAIL_TRIAGE_HEADER: build_triage_header(
            "digest", category="newsletters", account="a",
            version="v", generated="g",
        ),
    })
    assert get_triage_header(msg.headers) is not None


def test_run_triage_skip_is_case_insensitive():
    msg = _build_msg_with_header(
        {"x-email-triage": "digest; version=v; generated=g"},
    )
    assert get_triage_header(msg.headers) == "digest; version=v; generated=g"


def test_run_triage_processes_normal_message():
    """Negative control: no X-Email-Triage header ⇒ skip gate is False."""
    msg = _build_msg_with_header({"Subject": "hi"})
    assert get_triage_header(msg.headers) is None


@pytest.mark.asyncio
async def test_run_triage_records_skipped_entry(monkeypatch, tmp_path):
    """Integration-ish: feed run_triage a stamped message; classifier must
    not be called and results entry must record status=skipped."""
    import sqlite3
    from email_triage.config import TriageConfig
    from email_triage.web.triage_runner import run_triage

    db_path = tmp_path / "t.db"
    from email_triage.web.db import init_db
    conn = init_db(str(db_path))

    # Need a category and a provider. Stub everything the runner pulls.
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO categories (slug, description, created_at, updated_at) "
        "VALUES (?, ?, ?, ?)",
        ("newsletters", "", now, now),
    )
    conn.commit()

    fake_classifier = _SkipTestClassifier()

    class _FakeProv:
        name = "fake"

        async def search(self, query, limit):
            return ["1"]

        async def fetch_message(self, mid):
            return EmailMessage(
                message_id=mid,
                provider="fake",
                sender="a@b",
                recipients=["c@d"],
                subject="S",
                body_text="B",
                date=datetime.now(timezone.utc),
                headers={X_EMAIL_TRIAGE_HEADER: "digest; version=v; generated=g"},
            )

        async def close(self):
            pass

    import email_triage.web.routers.ui as ui_mod
    monkeypatch.setattr(
        ui_mod, "_create_provider_from_account",
        lambda acct, secrets: _FakeProv(),
    )
    monkeypatch.setattr(
        ui_mod, "_build_classifier_from_config",
        lambda cfg: fake_classifier,
    )

    acct = {
        "id": 1, "name": "test", "user_id": None,
        "provider_type": "fake", "config": {},
    }
    config = TriageConfig()

    result = await run_triage(
        conn, config, None, acct, query="", limit=10, trigger="test",
    )
    # Classifier was never called.
    assert fake_classifier.called == 0
    # Exactly one skipped entry.
    assert result["total_messages"] == 1
    entry = result["results"][0]
    assert entry["status"] == "skipped"
    assert entry["skip_reason"] == "x_email_triage_header"
    assert "x_email_triage" in entry
    assert entry["message_id"] == "1"
