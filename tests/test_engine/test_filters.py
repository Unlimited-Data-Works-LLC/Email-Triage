"""Tests for MailFilter -> per-provider query translation."""

from datetime import datetime, timezone

from email_triage.engine.models import MailFilter
from email_triage.providers.gmail_api import GmailApiProvider
from email_triage.providers.imap import ImapProvider
from email_triage.providers.office365 import Office365Provider


def _f(**kw):
    return MailFilter.from_dict(kw)


class TestGmailFilter:
    def test_empty_returns_empty_string(self):
        assert GmailApiProvider._translate_filter(MailFilter()) == ""

    def test_unread_label_after(self):
        out = GmailApiProvider._translate_filter(_f(
            unread=True, label="Priority",
            after="2026-04-01T00:00:00Z",
        ))
        assert "is:unread" in out
        assert "label:Priority" in out
        assert "after:2026/04/01" in out

    def test_subject_quoted_when_spaces(self):
        out = GmailApiProvider._translate_filter(_f(subject="Q1 review"))
        assert 'subject:"Q1 review"' in out

    def test_from_to_folder(self):
        out = GmailApiProvider._translate_filter(_f(
            from_addr="boss@x.com", to_addr="me@y.com", folder="INBOX",
        ))
        assert "from:boss@x.com" in out
        assert "to:me@y.com" in out
        assert "in:INBOX" in out

    def test_unread_false_is_read(self):
        assert "is:read" in GmailApiProvider._translate_filter(_f(unread=False))


class TestOfficeFilter:
    def test_empty_returns_empty_string(self):
        assert Office365Provider._translate_filter(MailFilter()) == ""

    def test_unread_subject_after(self):
        out = Office365Provider._translate_filter(_f(
            unread=True, subject="Q1 review",
            after="2026-04-01T00:00:00Z",
        ))
        assert "isRead eq false" in out
        assert "contains(subject,'Q1 review')" in out
        assert "receivedDateTime ge 2026-04-01T00:00:00Z" in out

    def test_label_via_categories(self):
        out = Office365Provider._translate_filter(_f(label="Priority"))
        assert "categories/any(c:c eq 'Priority')" in out

    def test_from_to_addresses(self):
        out = Office365Provider._translate_filter(_f(
            from_addr="boss@x.com", to_addr="me@y.com",
        ))
        assert "from/emailAddress/address eq 'boss@x.com'" in out
        assert "toRecipients/any(r:r/emailAddress/address eq 'me@y.com')" in out


class TestImapFilter:
    def test_empty_returns_empty_string(self):
        assert ImapProvider._translate_filter(MailFilter()) == ""

    def test_unread_from_subject_dates(self):
        out = ImapProvider._translate_filter(_f(
            unread=True,
            from_addr="boss@x.com",
            subject="Quarterly",
            after="2026-04-01T00:00:00Z",
            before="2026-05-01T00:00:00Z",
        ))
        assert "UNSEEN" in out
        assert 'FROM "boss@x.com"' in out
        assert 'SUBJECT "Quarterly"' in out
        assert "SINCE 01-Apr-2026" in out
        assert "BEFORE 01-May-2026" in out

    def test_unread_false_seen(self):
        assert "SEEN" in ImapProvider._translate_filter(_f(unread=False))

    def test_label_keyword(self):
        out = ImapProvider._translate_filter(_f(label="Priority"))
        assert "KEYWORD Priority" in out
