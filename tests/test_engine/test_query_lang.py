"""Tests for the provider-agnostic mail-query language (#138.3).

The IMAP / Gmail / O365 providers each used to carry their own
``_translate_filter`` + ``_translate_query`` pair. They now delegate
to ``email_triage.engine.query_lang``. These tests verify:

* parser round-trips for the corpus of in-tree queries;
* emitter output matches the per-provider behaviour the existing
  test suites verified.
"""

from __future__ import annotations

from datetime import datetime

from email_triage.engine.models import MailFilter
from email_triage.engine.query_lang import (
    emit_gmail_filter,
    emit_imap_filter,
    emit_o365_filter,
    parse_imap_query,
    translate_imap_query_to_gmail,
    translate_imap_query_to_imap,
    translate_imap_query_to_o365,
)


# ---------------------------------------------------------------------------
# parse_imap_query
# ---------------------------------------------------------------------------

def test_parse_empty_query():
    p = parse_imap_query("")
    assert p.flags == {}
    assert p.after is None
    assert p.before is None
    assert p.remainder == []
    assert p.imap_all is False


def test_parse_unseen_token():
    p = parse_imap_query("UNSEEN")
    assert p.flags == {"unread": True}


def test_parse_seen_token():
    p = parse_imap_query("SEEN")
    assert p.flags == {"unread": False}


def test_parse_all_token():
    p = parse_imap_query("ALL")
    assert p.imap_all is True
    assert p.flags == {}


def test_parse_since_date():
    p = parse_imap_query("SINCE 16-Apr-2026")
    assert p.after == datetime(2026, 4, 16)


def test_parse_before_date():
    p = parse_imap_query("BEFORE 01-Jan-2026")
    assert p.before == datetime(2026, 1, 1)


def test_parse_unseen_plus_since():
    p = parse_imap_query("UNSEEN SINCE 16-Apr-2026")
    assert p.flags == {"unread": True}
    assert p.after == datetime(2026, 4, 16)


def test_parse_passes_unknown_through():
    p = parse_imap_query("FROM alice@example.com")
    assert p.remainder == ["FROM", "alice@example.com"]


def test_parse_invalid_date_passes_through():
    p = parse_imap_query("SINCE not-a-date")
    assert p.after is None
    assert p.remainder == ["SINCE", "not-a-date"]


# ---------------------------------------------------------------------------
# emit_imap_filter
# ---------------------------------------------------------------------------

def test_emit_imap_filter_empty():
    assert emit_imap_filter(None) == ""
    assert emit_imap_filter(MailFilter()) == ""


def test_emit_imap_filter_unread():
    assert emit_imap_filter(MailFilter(unread=True)) == "UNSEEN"
    assert emit_imap_filter(MailFilter(unread=False)) == "SEEN"


def test_emit_imap_filter_combined():
    f = MailFilter(
        unread=True,
        from_addr="alice@example.com",
        subject="hello",
        after=datetime(2026, 4, 16),
    )
    out = emit_imap_filter(f)
    assert out == 'UNSEEN FROM "alice@example.com" SUBJECT "hello" SINCE 16-Apr-2026'


# ---------------------------------------------------------------------------
# emit_gmail_filter
# ---------------------------------------------------------------------------

def test_emit_gmail_filter_empty():
    assert emit_gmail_filter(None) == ""
    assert emit_gmail_filter(MailFilter()) == ""


def test_emit_gmail_filter_unread():
    assert emit_gmail_filter(MailFilter(unread=True)) == "is:unread"
    assert emit_gmail_filter(MailFilter(unread=False)) == "is:read"


def test_emit_gmail_filter_label_folder():
    f = MailFilter(label="work", folder="Inbox")
    assert emit_gmail_filter(f) == "label:work in:Inbox"


def test_emit_gmail_filter_subject_with_spaces_quoted():
    f = MailFilter(subject="Q3 budget review")
    assert emit_gmail_filter(f) == 'subject:"Q3 budget review"'


def test_emit_gmail_filter_after_before_dates():
    f = MailFilter(
        after=datetime(2026, 4, 16),
        before=datetime(2026, 5, 1),
    )
    assert emit_gmail_filter(f) == "after:2026/04/16 before:2026/05/01"


# ---------------------------------------------------------------------------
# emit_o365_filter
# ---------------------------------------------------------------------------

def test_emit_o365_filter_empty():
    assert emit_o365_filter(None) == ""
    assert emit_o365_filter(MailFilter()) == ""


def test_emit_o365_filter_unread():
    assert emit_o365_filter(MailFilter(unread=True)) == "isRead eq false"
    assert emit_o365_filter(MailFilter(unread=False)) == "isRead eq true"


def test_emit_o365_filter_subject_quote_escape():
    f = MailFilter(subject="o'reilly")
    assert emit_o365_filter(f) == "contains(subject,'o''reilly')"


def test_emit_o365_filter_combined_with_and():
    f = MailFilter(
        unread=True,
        from_addr="alice@example.com",
    )
    assert (
        emit_o365_filter(f)
        == "isRead eq false and from/emailAddress/address eq 'alice@example.com'"
    )


# ---------------------------------------------------------------------------
# IMAP query → provider-native translators
# ---------------------------------------------------------------------------

def test_translate_imap_to_imap_pass_through():
    assert translate_imap_query_to_imap("UNSEEN") == "UNSEEN"
    assert translate_imap_query_to_imap("ALL") == "ALL"


def test_translate_imap_to_imap_is_unread_shortcut():
    assert translate_imap_query_to_imap("is:unread") == "UNSEEN"
    assert translate_imap_query_to_imap("is:unread FROM x") == "UNSEEN FROM x"


def test_translate_imap_to_gmail_unseen():
    assert translate_imap_query_to_gmail("UNSEEN") == "is:unread"


def test_translate_imap_to_gmail_seen():
    assert translate_imap_query_to_gmail("SEEN") == "is:read"


def test_translate_imap_to_gmail_all_drops():
    """RFC 3501 ALL has no Gmail equivalent — emitter drops it."""
    assert translate_imap_query_to_gmail("ALL") == ""


def test_translate_imap_to_gmail_since_date():
    assert (
        translate_imap_query_to_gmail("SINCE 16-Apr-2026")
        == "after:2026/04/16"
    )


def test_translate_imap_to_gmail_combined():
    assert (
        translate_imap_query_to_gmail("UNSEEN SINCE 16-Apr-2026")
        == "is:unread after:2026/04/16"
    )


def test_translate_imap_to_gmail_passes_native_syntax_through():
    """Operator-supplied Gmail syntax shouldn't be mangled."""
    assert (
        translate_imap_query_to_gmail("from:alice@example.com")
        == "from:alice@example.com"
    )


def test_translate_imap_to_o365_is_unread_shortcut():
    assert translate_imap_query_to_o365("is:unread") == "isRead eq false"


def test_translate_imap_to_o365_from_shortcut():
    assert (
        translate_imap_query_to_o365("from:alice@example.com")
        == "from/emailAddress/address eq 'alice@example.com'"
    )


def test_translate_imap_to_o365_passes_odata_through():
    """Already-OData filter strings flow through unchanged."""
    src = "isRead eq true and importance eq 'high'"
    assert translate_imap_query_to_o365(src) == src


def test_translate_imap_to_o365_unrecognised_returns_empty():
    """Unknown tokens signal the caller to use ``$search`` instead."""
    assert translate_imap_query_to_o365("UNSEEN") == ""


# ---------------------------------------------------------------------------
# Provider class wrappers stay green via delegation
# ---------------------------------------------------------------------------

def test_gmail_provider_translate_filter_delegates():
    """GmailApiProvider._translate_filter delegates to query_lang."""
    from email_triage.providers.gmail_api import GmailApiProvider
    f = MailFilter(unread=True, from_addr="alice@example.com")
    assert GmailApiProvider._translate_filter(f) == emit_gmail_filter(f)


def test_o365_provider_translate_filter_delegates():
    o365 = pytest_importorskip_module("email_triage.providers.office365")
    f = MailFilter(unread=False, label="work")
    assert o365.Office365Provider._translate_filter(f) == emit_o365_filter(f)


def test_imap_provider_translate_filter_delegates():
    imap = pytest_importorskip_module("email_triage.providers.imap")
    f = MailFilter(unread=True, subject="ping")
    assert imap.ImapProvider._translate_filter(f) == emit_imap_filter(f)


def pytest_importorskip_module(name):
    """Helper — import_module-or-skip without a fixture."""
    import importlib
    import pytest

    try:
        return importlib.import_module(name)
    except ImportError as e:
        pytest.skip(f"optional dep missing: {e}")
