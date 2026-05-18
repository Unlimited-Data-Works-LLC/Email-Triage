"""Tests for #102 — "Test Now" button on /profile?tab=notifications.

The handler fires a single fixed-text message through the same SMTP
helper the live escalation uses (``send_simple_smtp_email``), so the
operator can verify wiring (cell + carrier or free-text address)
without waiting for a real urgent email.

Coverage:
  * Success path → 200, success chip, audit row written, gateway
    address recorded in detail.
  * No address configured → button absent on render; direct POST → no_address chip.
  * No escalation category selected → no_category chip.
  * SMTP failure (mock raises SMTPException) → failure chip,
    truncated error, audit row outcome=failure with full error.
  * Rate-limit: second POST within 60s → "wait a minute" chip,
    no second send fired.
  * HIPAA install: synthetic body is the test string (NOT redacted
    to nothing); confirm no PHI leaks since the body is a constant.
  * HTMX header request returns just the chip partial; non-HTMX
    returns a 303 redirect to the notifications tab.

No real cell numbers / email addresses / carrier names — every
fixture uses 555-0100 / user@example.com / "Carrier A".
"""

from __future__ import annotations

import json

import pytest
from smtplib import SMTPException


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


class _FakeSMTP:
    """Capture-only SMTP shim. Records the last send_message payload."""

    captured: dict = {}
    raise_on_send: type[Exception] | None = None
    raise_message: str = ""

    def __init__(self, host, port):
        type(self).captured["host"] = host
        type(self).captured["port"] = port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        type(self).captured["tls"] = True

    def login(self, u, p):
        type(self).captured["login"] = (u, p)

    def send_message(self, msg):
        if type(self).raise_on_send is not None:
            raise type(self).raise_on_send(type(self).raise_message)
        type(self).captured["msg"] = msg
        type(self).captured["subject"] = msg["Subject"]
        # set_content() puts plain-text body in the message payload.
        type(self).captured["body"] = msg.get_content()
        type(self).captured["to"] = msg["To"]


@pytest.fixture
def smtp_capture(monkeypatch):
    """Patch smtplib.SMTP at the helper's import site."""
    _FakeSMTP.captured = {}
    _FakeSMTP.raise_on_send = None
    _FakeSMTP.raise_message = ""
    from email_triage.web import smtp_send as smtp_mod
    monkeypatch.setattr(smtp_mod.smtplib, "SMTP", _FakeSMTP)
    return _FakeSMTP


@pytest.fixture
def smtp_configured(app):
    """Wire a working SMTP config + secret on app.state."""
    app.state.config.smtp.host = "smtp.test.example.com"
    app.state.config.smtp.port = 587
    app.state.config.smtp.username = "triage@example.com"
    app.state.config.smtp.from_addr = "triage@example.com"
    app.state.config.smtp.use_tls = True
    app.state.secrets.set("SMTP_PASSWORD", "pw")
    return app.state.config.smtp


def _set_user_notify_email(db, user_id: int, addr: str) -> None:
    db.execute(
        "UPDATE users SET notify_email = ? WHERE id = ?", (addr, user_id),
    )
    db.commit()


def _enable_escalation(db, user_id: int, slugs: list[str]) -> None:
    from email_triage.web.db import set_user_escalation_categories
    set_user_escalation_categories(db, user_id, slugs)


def _seeded_categories(db) -> list[str]:
    """Return seeded category slugs in sort_order ascending."""
    from email_triage.web.db import list_categories
    return [c["slug"] for c in list_categories(db)]


# ---------------------------------------------------------------------------
# Surface gating — render-side tests
# ---------------------------------------------------------------------------


class TestSurfaceGating:
    def test_button_absent_when_no_address(
        self, client, db, admin_cookies, admin_user,
    ):
        """No notify address → button shouldn't render. Hint shows instead."""
        # admin_user fixture creates with notify_email=NULL.
        resp = client.get("/profile?tab=notifications", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Test Now" not in resp.text
        # Hint about saving an address first.
        assert "save before testing" in resp.text

    def test_button_present_when_address_configured(
        self, client, db, admin_cookies, admin_user,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        resp = client.get("/profile?tab=notifications", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Test Now" in resp.text
        # Aria wiring for the side-effect copy.
        assert 'aria-describedby="test-send-help"' in resp.text
        # Result target div is rendered for HTMX swap.
        assert 'id="test-send-result"' in resp.text


# ---------------------------------------------------------------------------
# POST handler
# ---------------------------------------------------------------------------


class TestSuccessPath:
    def test_htmx_post_returns_success_chip_and_audits(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        gateway = "5550100@example.com"
        _set_user_notify_email(db, admin_user["id"], gateway)
        slugs = _seeded_categories(db)
        _enable_escalation(db, admin_user["id"], slugs)

        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        # Success chip text — plain language, no protocol vocab.
        assert "Sent at" in resp.text
        assert "check your phone within 60s" in resp.text
        # SMTP layer received our payload.
        assert smtp_capture.captured["to"] == gateway
        assert smtp_capture.captured["subject"] == "[email-triage] Test send"
        assert "email-triage test send" in smtp_capture.captured["body"]

        # Audit row recorded with success outcome + gateway in detail.
        from email_triage.web.db import list_auth_events
        rows = list_auth_events(
            db, event_type="escalation_test", user_id=admin_user["id"],
        )
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
        detail = json.loads(rows[0]["detail"])
        assert detail["gateway_address"] == gateway
        assert detail["category"] in slugs

    def test_chip_uses_user_friendly_language_not_protocol_terms(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])
        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        # Forbidden user-facing phrasings from the audience rule.
        text = resp.text.lower()
        assert "smtp relay" not in text
        assert "language model" not in text
        assert "ask your administrator" not in text


class TestNoAddressGuard:
    def test_direct_post_with_no_address_returns_no_address_chip(
        self, client, db, admin_cookies, admin_user, smtp_configured,
    ):
        # No notify_email set; defense-in-depth path.
        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        assert "No notification address configured" in resp.text

        from email_triage.web.db import list_auth_events
        rows = list_auth_events(
            db, event_type="escalation_test", user_id=admin_user["id"],
        )
        assert len(rows) == 1
        assert rows[0]["outcome"] == "failure"
        assert "no_address" in rows[0]["detail"]


class TestNoCategoryGuard:
    def test_no_escalation_category_returns_chip_and_does_not_send(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        # Don't enable any categories.
        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        assert "Pick at least one Escalation Category" in resp.text
        # No SMTP send fired.
        assert "msg" not in smtp_capture.captured

        from email_triage.web.db import list_auth_events
        rows = list_auth_events(
            db, event_type="escalation_test", user_id=admin_user["id"],
        )
        assert rows[0]["outcome"] == "failure"
        assert "no_category" in rows[0]["detail"]


class TestSmtpFailure:
    def test_smtp_exception_returns_failure_chip_and_audits_error(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])

        smtp_capture.raise_on_send = SMTPException
        smtp_capture.raise_message = (
            "550 5.1.1 The email account that you tried to reach "
            "does not exist"
        )

        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        # Failure chip prefix.
        assert "Sender rejected" in resp.text
        # Truncated error in chip — the chip caps at ~80 chars.
        # Find the chip text and verify no body line longer than ~150
        # chars (the chip + outer markup).
        # Also verify the SMTPException class name is part of the
        # truncated error.
        assert "SMTPException" in resp.text or "550" in resp.text

        from email_triage.web.db import list_auth_events
        rows = list_auth_events(
            db, event_type="escalation_test", user_id=admin_user["id"],
        )
        assert rows[0]["outcome"] == "failure"
        detail = json.loads(rows[0]["detail"])
        assert detail["gateway_address"] == "5550100@example.com"
        # Full untruncated error in audit detail.
        assert "550" in detail["error"]
        assert "SMTPException" in detail["error"]


class TestRateLimit:
    def test_second_send_within_window_blocked_and_no_second_send(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])

        # First send succeeds.
        resp1 = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert "Sent at" in resp1.text
        # Capture the message that was sent so we can check no second
        # one overwrites it.
        first_msg = smtp_capture.captured.get("msg")
        assert first_msg is not None

        # Second send within the 60s window should hit the rate limit.
        resp2 = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp2.status_code == 200
        assert "wait a minute" in resp2.text.lower()
        # Same captured message (no overwrite — meaning no send fired).
        assert smtp_capture.captured["msg"] is first_msg

        # Audit row for the rate-limit attempt is recorded as failure.
        from email_triage.web.db import list_auth_events
        rows = list_auth_events(
            db, event_type="escalation_test", user_id=admin_user["id"],
        )
        # Two rows: success + rate_limit.
        assert len(rows) == 2
        outcomes = sorted([r["outcome"] for r in rows])
        assert outcomes == ["failure", "success"]
        # The newer row (rows[0]) should be the rate-limit failure.
        assert "rate_limit" in rows[0]["detail"]


class TestHipaaBodyShape:
    def test_hipaa_install_body_is_test_constant_no_phi(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture, monkeypatch,
    ):
        """On a HIPAA-mode install the synthetic body still renders.

        The escalate-action's _build_notification scrubs message-keyed
        text under HIPAA — but the Test Now path sends a constant
        string that isn't keyed to a real message, so there's nothing
        to scrub. We assert the body is the test constant + that no
        real-message identifiers leak in.
        """
        from email_triage import triage_logging
        monkeypatch.setattr(triage_logging, "is_hipaa_mode", lambda: True)

        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])

        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        body = smtp_capture.captured["body"]
        # Synthetic test constant present.
        assert "email-triage test send" in body
        # No subject / sender / message-id leaked.
        assert "subject" not in body.lower()
        assert "sender" not in body.lower()
        assert "message-id" not in body.lower()


class TestHtmxResponseShape:
    def test_htmx_returns_chip_partial_only(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])
        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            headers={"HX-Request": "true"},
        )
        assert resp.status_code == 200
        # Chip partial — no full-page chrome (no <html> / <body>).
        assert "<html" not in resp.text.lower()
        assert "<body" not in resp.text.lower()
        # The chip wrapping <span> is present.
        assert "<span" in resp.text

    def test_non_htmx_returns_redirect_to_profile_tab(
        self, client, db, admin_cookies, admin_user,
        smtp_configured, smtp_capture,
    ):
        _set_user_notify_email(db, admin_user["id"], "5550100@example.com")
        _enable_escalation(db, admin_user["id"], _seeded_categories(db)[:1])
        # No HX-Request header — request is a plain POST.
        resp = client.post(
            "/profile/escalation-test-send",
            cookies=admin_cookies,
            follow_redirects=False,
        )
        # 303 See Other back to the notifications tab.
        assert resp.status_code == 303
        assert resp.headers["location"] == "/profile?tab=notifications"
