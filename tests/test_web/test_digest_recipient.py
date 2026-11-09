"""Digest recipient-mode + From/To/Reply-To regressions.

Covers the Option-D hybrid recipient feature and the two header bugs
(From was the OAuth identity, To was the OAuth login) shipped in
the same cluster.
"""

from __future__ import annotations


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
# smtp_send_digest shape (From/To/Reply-To/Subject)
# ---------------------------------------------------------------------------


class TestSmtpSendDigest:
    def test_builds_message_with_from_to_reply_to(self, monkeypatch):
        from email_triage.web import auth as auth_mod

        captured = {}

        class FakeSMTP:
            def __init__(self, host, port, timeout=None):
                captured["host"] = host
                captured["port"] = port
                captured["timeout"] = timeout
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def starttls(self, *, context=None):
                captured["tls"] = True
            def login(self, u, p):
                captured["login"] = (u, p)
            def send_message(self, msg):
                captured["msg"] = msg

        monkeypatch.setattr("email_triage.web.smtp_send.smtplib.SMTP", FakeSMTP)
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
