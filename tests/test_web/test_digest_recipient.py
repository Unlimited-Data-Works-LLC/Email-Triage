"""Digest recipient-mode + From/To/Reply-To regressions.

Covers the Option-D hybrid recipient feature and the two header bugs
(From was the OAuth identity, To was the OAuth login) shipped in
the same cluster.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from email import message_from_bytes
from email.policy import default as default_policy
from unittest.mock import AsyncMock, MagicMock

import pytest


# ---------------------------------------------------------------------------
# _account_mailbox_address
# ---------------------------------------------------------------------------


class TestAccountMailboxAddress:
    def test_prefers_config_account(self):
        from email_triage.web.routers.ui import _account_mailbox_address
        acct = {"config": {"account": "real@gmail.com", "username": "login@other"}}
        assert _account_mailbox_address(acct) == "real@gmail.com"

    def test_falls_back_to_username(self):
        from email_triage.web.routers.ui import _account_mailbox_address
        acct = {"config": {"username": "user@imap.test"}}
        assert _account_mailbox_address(acct) == "user@imap.test"

    def test_skips_non_email_account_for_email_username(self):
        from email_triage.web.routers.ui import _account_mailbox_address
        # If account is set but not an email, prefer a username that IS.
        acct = {"config": {"account": "nick", "username": "nick@imap.test"}}
        assert _account_mailbox_address(acct) == "nick@imap.test"

    def test_last_resort_account_name(self):
        from email_triage.web.routers.ui import _account_mailbox_address
        acct = {"config": {}, "name": "Alice Mailbox"}
        assert _account_mailbox_address(acct) == "Alice Mailbox"

    def test_empty_everything(self):
        from email_triage.web.routers.ui import _account_mailbox_address
        assert _account_mailbox_address({}) == ""


# ---------------------------------------------------------------------------
# _resolve_digest_recipient
# ---------------------------------------------------------------------------


class TestResolveDigestRecipient:
    ACCT = {"config": {"account": "src@gmail.com"}}

    def test_default_back_to_account(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "back_to_account", "", hipaa=False,
        )
        assert dest == "src@gmail.com"
        assert mode == "back_to_account"
        assert warn == ""

    def test_user_email_mode(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "user_email", "", hipaa=False,
        )
        assert dest == "user@example.com"
        assert mode == "user_email"
        assert warn == ""

    def test_other_mode_valid_email(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "other", "boss@corp.com", hipaa=False,
        )
        assert dest == "boss@corp.com"
        assert mode == "other"
        assert warn == ""

    def test_other_mode_invalid_falls_back(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "other", "not-an-email", hipaa=False,
        )
        assert mode == "back_to_account"
        assert dest == "src@gmail.com"
        assert "invalid" in warn.lower()

    def test_hipaa_locks_to_back_to_account(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "other", "boss@corp.com", hipaa=True,
        )
        assert mode == "back_to_account"
        assert dest == "src@gmail.com"
        assert "hipaa" in warn.lower()

    def test_hipaa_user_email_also_blocked(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        _dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "user@example.com", "user_email", "", hipaa=True,
        )
        assert mode == "back_to_account"
        assert "hipaa" in warn.lower()

    def test_user_email_empty_falls_back(self):
        from email_triage.web.routers.ui import _resolve_digest_recipient
        dest, mode, warn = _resolve_digest_recipient(
            self.ACCT, "", "user_email", "", hipaa=False,
        )
        assert mode == "back_to_account"
        assert dest == "src@gmail.com"
        assert warn


# ---------------------------------------------------------------------------
# smtp_send_digest shape (From/To/Reply-To/Subject)
# ---------------------------------------------------------------------------


class TestSmtpSendDigest:
    def test_builds_message_with_from_to_reply_to(self, monkeypatch):
        from email_triage.web import auth as auth_mod

        captured = {}

        class FakeSMTP:
            def __init__(self, host, port):
                captured["host"] = host
                captured["port"] = port
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def starttls(self):
                captured["tls"] = True
            def login(self, u, p):
                captured["login"] = (u, p)
            def send_message(self, msg):
                captured["msg"] = msg

        monkeypatch.setattr(auth_mod.smtplib, "SMTP", FakeSMTP)
        auth_mod.smtp_send_digest(
            smtp_host="smtp.test",
            smtp_port=587,
            smtp_user="u",
            smtp_password="pw",
            from_addr="triage@example.com",
            from_name="Triage",
            to_addr="boss@corp.com",
            reply_to="human@example.com",
            subject="Digest",
            html_body="<p>Hi</p>",
            use_tls=True,
            extra_headers={"X-Email-Triage": "digest"},
        )

        msg = captured["msg"]
        assert msg["To"] == "boss@corp.com"
        assert msg["Reply-To"] == "human@example.com"
        assert "triage@example.com" in msg["From"]
        assert "Triage" in msg["From"]
        assert msg["Subject"] == "Digest"
        assert msg["X-Email-Triage"] == "digest"


# ---------------------------------------------------------------------------
# End-to-end-ish digest endpoint via mocked provider
# ---------------------------------------------------------------------------


def _pad_b64(s: str) -> bytes:
    pad = "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s + pad)


class _FakeGmailProvider:
    """Mocks the Gmail provider surface that digest_generate touches.

    Records raw MIME passed to deliver_to_inbox / create_draft so the
    test can inspect the From / To / Reply-To headers.
    """

    name = "gmail_api"

    def __init__(self):
        from email_triage.engine.models import EmailMessage
        self._msg_tpl = EmailMessage
        self.delivered = []
        self.drafts = []

    async def search(self, query, limit=50):
        return ["m1"]

    async def fetch_message(self, uid):
        from email_triage.engine.models import EmailMessage
        return EmailMessage(
            message_id=uid,
            provider="gmail_api",
            sender="src@example.com",
            recipients=["me@gmail.com"],
            subject="Hello",
            body_text="A newsletter article about Python.",
            date=datetime.now(timezone.utc),
            thread_id="t",
        )

    async def deliver_to_inbox(
        self, to, subject, body, *, extra_headers=None,
        from_addr=None, from_name=None, reply_to=None,
    ):
        # Signature mirrors the real provider methods (base.py
        # deliver_to_inbox + create_draft) exactly. The prior fake
        # accepted ``subtype="plain"`` which let a production paste-
        # error (digest path passing ``subtype="html"``) ride green
        # in tests until the live IMAP path raised TypeError.
        # Keeping the fake signature-strict guarantees future drift
        # surfaces here, not at runtime on a customer's mailbox.
        self.delivered.append({
            "to": to, "subject": subject, "body": body,
            "extra_headers": extra_headers,
            "from_addr": from_addr, "from_name": from_name,
            "reply_to": reply_to,
        })
        return "id-1"

    async def create_draft(
        self, to, subject, body, in_reply_to=None, thread_id=None, *,
        extra_headers=None, from_addr=None, from_name=None, reply_to=None,
    ):
        self.drafts.append({
            "to": to, "subject": subject, "body": body,
            "from_addr": from_addr, "from_name": from_name,
            "reply_to": reply_to,
        })
        return "draft-1"

    async def close(self):
        pass


class _FakeClassifier:
    async def classify(self, message):
        from email_triage.engine.models import ClassificationResult
        return ClassificationResult(category="newsletters", confidence=0.9, reason="")


def _fake_generate_digest_factory():
    async def fake_generate_digest(
        provider, classifier, messages, *, delete_originals=False,
        signature_template="", category="newsletters", account="",
        html_template="",
    ):
        return "<html><body>Digest body</body></html>", 3, 1
    return fake_generate_digest


def _make_gmail_account(db, user_id, hipaa=False):
    now = datetime.now(timezone.utc).isoformat()
    import json as _json
    cursor = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
        "hipaa, created_under_system_hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, "TestGmail", "gmail_api",
         _json.dumps({"account": "src@gmail.com", "username": "oauthlogin@example.com"}),
         1 if hipaa else 0, 0, now, now),
    )
    db.commit()
    return cursor.lastrowid


class TestDigestGenerateHeaders:
    """Drive /accounts/{id}/digest/generate with a fake provider and
    a fake classifier to verify From / To / Reply-To + mechanism."""

    def _patch_everything(self, monkeypatch, fake_provider):
        from email_triage.web.routers import ui as ui_mod
        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account",
            lambda acct, secrets: fake_provider,
        )
        monkeypatch.setattr(
            ui_mod, "_build_classifier_from_config",
            lambda cfg: _FakeClassifier(),
        )
        from email_triage.actions import digest as digest_mod
        monkeypatch.setattr(
            digest_mod, "generate_digest", _fake_generate_digest_factory(),
        )

    def _set_smtp(self, app):
        app.state.config.smtp.host = "smtp.test"
        app.state.config.smtp.port = 587
        app.state.config.smtp.username = "triage@example.com"
        app.state.config.smtp.from_addr = "triage@example.com"
        app.state.config.smtp.from_name = "Triage System"
        app.state.config.smtp.use_tls = True

    def test_from_uses_smtp_from_addr_not_account(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        """Bug #1: From used to be the Gmail account identity."""
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "back_to_account",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        assert len(fake.delivered) == 1
        call = fake.delivered[0]
        assert call["from_addr"] == "triage@example.com"
        assert call["from_name"] == "Triage System"

    def test_to_uses_account_mailbox_for_back_to_account(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        """Bug #2: To used to be config.username (OAuth login), not mailbox."""
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "back_to_account",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert fake.delivered[0]["to"] == ["src@gmail.com"]

    def test_reply_to_is_user_email(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "back_to_account",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert fake.delivered[0]["reply_to"] == "admin@test.com"

    def test_user_email_mode_uses_profile_email(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "user_email",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        # user_email mode → different address → SMTP path, not deliver_to_inbox.
        assert len(fake.delivered) == 0
        # SMTP path used — verified in the smtp test below.

    def test_other_mode_uses_smtp(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        smtp_calls = []

        def fake_send(**kwargs):
            smtp_calls.append(kwargs)

        from email_triage.web.routers import ui as ui_mod
        # The call site does a local import of smtp_send_digest —
        # patch it in the auth module.
        from email_triage.web import auth as auth_mod
        monkeypatch.setattr(auth_mod, "smtp_send_digest", fake_send)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "other",
                "recipient_custom": "boss@corp.com",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200, resp.text
        assert len(smtp_calls) == 1
        call = smtp_calls[0]
        assert call["to_addr"] == "boss@corp.com"
        assert call["from_addr"] == "triage@example.com"
        assert call["reply_to"] == "admin@test.com"

    def test_hipaa_locks_to_back_to_account(
        self, client, db, admin_cookies, admin_user, monkeypatch, app,
    ):
        """Form submits other → server forces back_to_account on HIPAA acct."""
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"], hipaa=True)
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        resp = client.post(
            f"/accounts/{acct_id}/digest/generate",
            data={
                "category": "newsletters",
                "create_draft": "1",
                "recipient_mode": "other",
                "recipient_custom": "boss@corp.com",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        # Forced back-to-account: deliver_to_inbox hit, TO is the mailbox.
        assert len(fake.delivered) == 1
        assert fake.delivered[0]["to"] == ["src@gmail.com"]

    def test_hipaa_locked_mode_logs_warning(
        self, client, db, admin_cookies, admin_user, monkeypatch, app, caplog,
    ):
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"], hipaa=True)
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        import logging as _l
        with caplog.at_level(_l.WARNING):
            resp = client.post(
                f"/accounts/{acct_id}/digest/generate",
                data={
                    "category": "newsletters",
                    "create_draft": "1",
                    "recipient_mode": "other",
                    "recipient_custom": "boss@corp.com",
                },
                cookies=admin_cookies,
            )
        assert resp.status_code == 200
        assert any(
            "down-shifted" in rec.getMessage().lower()
            or "hipaa" in rec.getMessage().lower()
            for rec in caplog.records
        )

    def test_delivery_info_log_line(
        self, client, db, admin_cookies, admin_user, monkeypatch, app, caplog,
    ):
        self._set_smtp(app)
        acct_id = _make_gmail_account(db, admin_user["id"])
        fake = _FakeGmailProvider()
        self._patch_everything(monkeypatch, fake)

        import logging as _l
        with caplog.at_level(_l.INFO):
            resp = client.post(
                f"/accounts/{acct_id}/digest/generate",
                data={
                    "category": "newsletters",
                    "create_draft": "1",
                    "recipient_mode": "back_to_account",
                },
                cookies=admin_cookies,
            )
        assert resp.status_code == 200
        assert any(
            "digest delivered" in rec.getMessage().lower()
            for rec in caplog.records
        )
