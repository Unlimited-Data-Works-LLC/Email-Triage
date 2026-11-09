"""Punch 599 — outbound Message-Id never calls ``socket.getfqdn()``.

``email.utils.make_msgid()`` with no ``domain`` calls ``socket.getfqdn()`` (a
reverse-DNS lookup) on every call. ``stamp_default_message_headers`` runs ON the
event loop inside the async ``background_sweepers._send_clock_escalations``, so a
slow resolver stalls the loop (latency), and the internal host FQDN lands in every
outbound Message-Id (infrastructure disclosure). The id's domain now comes from the
configured sender address, with a fixed non-resolving fallback
(``email-triage.invalid``, RFC 2606). One helper: ``mail_headers.make_message_id``.

Every test here makes ``socket.getfqdn`` raise, so any surviving call is a failure.
Structural pin: ``tests/test_punch599_message_id_domain_pin.py``.
"""
from __future__ import annotations

import socket
from email.message import EmailMessage

import pytest

from email_triage.mail_headers import MESSAGE_ID_FALLBACK_DOMAIN


@pytest.fixture(autouse=True)
def no_reverse_dns(monkeypatch):
    def _boom(*a, **k):
        raise AssertionError("socket.getfqdn() called while minting a Message-Id")
    monkeypatch.setattr(socket, "getfqdn", _boom)


def _domain(msgid: str) -> str:
    assert msgid.startswith("<") and msgid.endswith(">"), msgid
    return msgid[1:-1].rpartition("@")[2]


def test_stamp_uses_the_explicit_sender_domain():
    from email_triage.web.smtp_send import stamp_default_message_headers
    msg = EmailMessage()
    stamp_default_message_headers(msg, from_addr="alerts@clinic.example.org")
    assert _domain(msg["Message-Id"]) == "clinic.example.org"


def test_stamp_reads_the_from_header_when_no_address_is_passed():
    """background_sweepers (and send_simple_smtp_email) set From before stamping."""
    from email_triage.web.smtp_send import stamp_default_message_headers
    msg = EmailMessage()
    msg["From"] = '"Email Triage" <noreply@Mail.Example.COM>'
    stamp_default_message_headers(msg)
    assert _domain(msg["Message-Id"]) == "mail.example.com"


def test_stamp_without_any_sender_uses_the_fixed_fallback():
    from email_triage.web.smtp_send import stamp_default_message_headers
    msg = EmailMessage()
    stamp_default_message_headers(msg)
    assert _domain(msg["Message-Id"]) == MESSAGE_ID_FALLBACK_DOMAIN == "email-triage.invalid"


def test_mime_builder_uses_the_sender_domain():
    from email_triage.web._mime_builder import build_alternative_message
    msg = build_alternative_message(
        subject="s", from_addr="digest@triage.example.net", to="a@b.example",
        plain_body="p", html_body="<p>h</p>", source_tag="digest",
    )
    assert _domain(msg["Message-Id"]) == "triage.example.net"


@pytest.mark.parametrize("bad", [
    "", "not-an-address", "user@", "a@[10.0.0.1]", "a@exa mple.com",
    "a@evil.example\r\nBcc: x@y", "a@-bad-.example", "a@.example", "a@x..example",
])
def test_unusable_sender_domains_fall_back(bad):
    from email_triage.mail_headers import message_id_domain
    assert message_id_domain(bad) == MESSAGE_ID_FALLBACK_DOMAIN


def test_idn_sender_domain_is_ascii_encoded():
    from email_triage.mail_headers import message_id_domain
    assert message_id_domain("arzt@münchen.de") == "xn--mnchen-3ya.de"


def test_make_message_id_is_unique_and_well_formed():
    from email_triage.mail_headers import make_message_id
    a, b = make_message_id("x@y.example"), make_message_id("x@y.example")
    assert a != b
    assert _domain(a) == "y.example"


def test_send_simple_smtp_email_stamps_the_sender_domain(monkeypatch):
    """The plain-text send path builds, stamps and hands to transport; capture it."""
    from email_triage.web import smtp_send

    sent = {}
    monkeypatch.setattr(smtp_send, "send_smtp_message",
                        lambda msg, **k: sent.setdefault("msg", msg))
    smtp_send.send_simple_smtp_email(
        to_addr="dr@clinic.example", subject="s", body="b",
        from_addr="otp@login.example.org", smtp_host="localhost", smtp_port=25,
        smtp_user="", smtp_password="",
    )
    assert _domain(sent["msg"]["Message-Id"]) == "login.example.org"
