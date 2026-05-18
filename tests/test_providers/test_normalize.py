"""Tests for providers/_normalize.py build_email_message.

Specifically guards the HTML→text fallback added 2026-05-13 to fix
the IMAP + Gmail "No usable sent messages" symptom on
/profile/style-data/mine-now: modern senders (Outlook / web Outlook
/ Apple Mail) emit HTML-only multipart/alternative composes, and
the providers' ``_extract_body`` paths only look at text/plain.
Without the fallback, downstream consumers reading ``body_text``
(style mining, RAG indexing, body-based list rules) silently see
nothing.

These tests pin the fallback shape so a future refactor of
``build_email_message`` doesn't regress it.
"""

from __future__ import annotations

from datetime import datetime, timezone

from email_triage.providers._normalize import build_email_message


def test_body_text_filled_from_html_when_empty():
    """HTML-only message → body_text is the stripped-HTML rendering."""
    msg = build_email_message(
        message_id="1",
        provider="imap",
        sender="me@example.com",
        recipients=["you@example.com"],
        subject="HTML-only sent item",
        body_text="",  # provider couldn't find text/plain part
        body_html="<html><body><p>Hello there.</p><p>Best,<br>Me</p></body></html>",
        date=datetime.now(timezone.utc),
    )
    assert msg.body_text, "body_text should be populated from HTML fallback"
    assert "Hello there" in msg.body_text
    assert "Best" in msg.body_text
    # Body html preserved alongside.
    assert msg.body_html.startswith("<html>")


def test_body_text_preserved_when_both_present():
    """text/plain present + html present → body_text untouched."""
    msg = build_email_message(
        message_id="2",
        provider="imap",
        sender="me@example.com",
        recipients=["you@example.com"],
        subject="Multipart with real text/plain",
        body_text="Hello there.\n\nBest,\nMe",
        body_html="<html><body><p>Hello there.</p></body></html>",
        date=datetime.now(timezone.utc),
    )
    assert msg.body_text == "Hello there.\n\nBest,\nMe"


def test_body_text_empty_when_both_empty():
    """No plain text, no HTML → body_text stays empty (no crash)."""
    msg = build_email_message(
        message_id="3",
        provider="imap",
        sender="me@example.com",
        recipients=["you@example.com"],
        subject="Empty body",
        body_text="",
        body_html="",
        date=datetime.now(timezone.utc),
    )
    assert msg.body_text == ""
    assert msg.body_html == ""


def test_links_still_extracted_alongside_fallback():
    """Fallback path doesn't drop link extraction."""
    msg = build_email_message(
        message_id="4",
        provider="gmail_api",
        sender="newsletter@example.com",
        recipients=["me@example.com"],
        subject="HTML newsletter",
        body_text="",
        body_html=(
            '<html><body><p>Read more at '
            '<a href="https://example.com/article">our blog</a>.</p>'
            '</body></html>'
        ),
        date=datetime.now(timezone.utc),
    )
    # body_text carries the link inlined (html_to_text_with_links shape).
    assert "blog" in msg.body_text
    # links list also computed from html.
    assert msg.links
    assert any(href == "https://example.com/article" for _text, href in msg.links)
