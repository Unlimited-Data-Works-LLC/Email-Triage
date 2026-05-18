"""Query-stage self-skip + defense-in-depth secondary check (#117).

The X-Email-Triage header is the primary loop guard, but every triage
run still pays a per-message FETCH on its own outbound digests / draft
replies. This pushes the exclusion up to the SEARCH stage so self-mail
never enters the result set.

Defense in depth: even with the SEARCH filter active, a downstream
forwarder may have stripped the X-Email-Triage header. The secondary
sender-equality check catches that.

Test fixtures use abstract typed placeholders — no real domains.
"""

from __future__ import annotations

import pytest

from email_triage.mail_headers import (
    build_self_skip_query,
    is_self_origin,
)


# ---------------------------------------------------------------------------
# Provider-specific query rewrite
# ---------------------------------------------------------------------------


class TestBuildSelfSkipQueryGmail:
    def test_appends_negative_from_clause(self):
        q = build_self_skip_query(
            "is:unread newer_than:7d",
            "triage@install.test",
            provider_type="gmail_api",
        )
        assert "is:unread newer_than:7d" in q
        assert "-from:triage@install.test" in q

    def test_empty_base_query(self):
        q = build_self_skip_query(
            "", "triage@install.test", provider_type="gmail_api",
        )
        assert q == "-from:triage@install.test"

    def test_empty_self_from_returns_base(self):
        q = build_self_skip_query(
            "is:unread", "", provider_type="gmail_api",
        )
        assert q == "is:unread"

    def test_display_name_stripped(self):
        """SMTP from_addr can carry display name + brackets — the
        query clause should use the bare address."""
        q = build_self_skip_query(
            "is:unread",
            "Email Triage <triage@install.test>",
            provider_type="gmail_api",
        )
        assert "-from:triage@install.test" in q
        # No leftover bracket / display name.
        assert "<" not in q
        assert "Email Triage" not in q


class TestBuildSelfSkipQueryImap:
    def test_appends_not_from_clause(self):
        q = build_self_skip_query(
            "UNSEEN SINCE 01-Jan-2026",
            "triage@install.test",
            provider_type="imap",
        )
        assert "UNSEEN SINCE 01-Jan-2026" in q
        assert 'NOT FROM "triage@install.test"' in q

    def test_empty_base_uses_all(self):
        """IMAP SEARCH needs at least one criterion — emit ALL when
        the base is empty."""
        q = build_self_skip_query(
            "", "triage@install.test", provider_type="imap",
        )
        assert q.startswith("ALL")
        assert 'NOT FROM "triage@install.test"' in q

    def test_address_lowercased(self):
        """Addresses are case-insensitive; lowercasing keeps SEARCH
        comparisons stable."""
        q = build_self_skip_query(
            "ALL", "Triage@Install.Test", provider_type="imap",
        )
        assert 'NOT FROM "triage@install.test"' in q


class TestBuildSelfSkipQueryOffice365:
    def test_filter_clause_appends(self):
        q = build_self_skip_query(
            "isRead eq false",
            "triage@install.test",
            provider_type="office365",
        )
        # Wraps original $filter and ANDs with the exclusion.
        assert "isRead eq false" in q
        assert "from/emailAddress/address ne 'triage@install.test'" in q
        assert " and " in q

    def test_empty_base_returns_clause_only(self):
        q = build_self_skip_query(
            "", "triage@install.test", provider_type="office365",
        )
        assert q == "from/emailAddress/address ne 'triage@install.test'"


class TestBuildSelfSkipQueryOther:
    def test_unknown_provider_returns_base_unchanged(self):
        """Unknown providers can't be safely rewritten; fall back to
        the base query and let the fetch-stage check catch self-mail."""
        q = build_self_skip_query(
            "anything", "triage@install.test", provider_type="exotic",
        )
        assert q == "anything"


# ---------------------------------------------------------------------------
# Defense-in-depth secondary check
# ---------------------------------------------------------------------------


class TestIsSelfOrigin:
    def test_exact_match(self):
        assert is_self_origin(
            "triage@install.test", "triage@install.test",
        ) is True

    def test_case_insensitive(self):
        assert is_self_origin(
            "TRIAGE@INSTALL.TEST", "triage@install.test",
        ) is True

    def test_display_name_on_sender(self):
        """Sender often arrives as ``Display Name <addr>``; the bare
        address must still match."""
        assert is_self_origin(
            "Email Triage <triage@install.test>",
            "triage@install.test",
        ) is True

    def test_display_name_on_self(self):
        assert is_self_origin(
            "triage@install.test",
            "Email Triage <triage@install.test>",
        ) is True

    def test_different_address_no_match(self):
        assert is_self_origin(
            "alice@elsewhere.test", "triage@install.test",
        ) is False

    def test_empty_self_returns_false(self):
        # No install-wide self-from configured ⇒ no self-loop to detect.
        assert is_self_origin("alice@x.test", "") is False

    def test_empty_sender_returns_false(self):
        assert is_self_origin("", "triage@install.test") is False

    def test_both_empty_returns_false(self):
        assert is_self_origin("", "") is False
