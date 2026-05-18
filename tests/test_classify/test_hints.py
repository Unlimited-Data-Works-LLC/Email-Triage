"""Tests for list-hint matching logic."""

from datetime import datetime, timezone

from email_triage.classify.hints import collect_hints, find_skip_ai_hint
from email_triage.engine.models import (
    ClassificationList,
    EmailMessage,
    ListHint,
    ListRule,
    RuleType,
)


def _make_email(**overrides) -> EmailMessage:
    defaults = dict(
        message_id="m1",
        provider="test",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Hello world",
        body_text="Body text.",
        date=datetime(2026, 4, 14, 12, 0, tzinfo=timezone.utc),
    )
    defaults.update(overrides)
    return EmailMessage(**defaults)


def _make_list(id: int, name: str, category: str, is_global: bool = False) -> ClassificationList:
    return ClassificationList(
        id=id, name=name, category=category, is_global=is_global,
    )


def _make_rule(id: int, list_id: int, rule_type: RuleType, pattern: str, skip_ai: bool = False) -> ListRule:
    return ListRule(
        id=id, list_id=list_id, rule_type=rule_type,
        pattern=pattern, skip_ai=skip_ai,
    )


class TestSenderMatching:
    def test_exact_sender_match(self):
        msg = _make_email(sender="boss@company.com")
        cl = _make_list(1, "VIP", "to-respond")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER, "boss@company.com")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1
        assert hints[0].category == "to-respond"

    def test_sender_case_insensitive(self):
        msg = _make_email(sender="Boss@Company.com")
        cl = _make_list(1, "VIP", "to-respond")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER, "boss@company.com")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_sender_no_match(self):
        msg = _make_email(sender="other@example.com")
        cl = _make_list(1, "VIP", "to-respond")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER, "boss@company.com")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 0

    def test_sender_display_name_form_matches(self):
        """2026-05-12 — operator caught: ``EmailMessage.sender``
        from Gmail / IMAP carries the raw From header value, which
        for most real mail is ``"Display Name" <addr@domain>``. The
        prior naive ``sender.lower() == pattern.lower()`` compare
        failed because the display-name string never equals the bare
        pattern. Parse both sides to the bare address before compare.
        """
        msg = _make_email(sender='"Boss" <boss@company.com>')
        cl = _make_list(1, "VIP", "to-respond")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER, "boss@company.com")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1


class TestSenderDomainMatching:
    def test_domain_match(self):
        msg = _make_email(sender="anyone@hospital.org")
        cl = _make_list(1, "Hospital", "grant-related")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "hospital.org")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1
        assert hints[0].category == "grant-related"

    def test_domain_with_at_prefix(self):
        msg = _make_email(sender="user@billing.com")
        cl = _make_list(1, "Billing", "invoices")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "@billing.com")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_domain_case_insensitive(self):
        msg = _make_email(sender="user@Hospital.ORG")
        cl = _make_list(1, "Hospital", "grant-related")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "hospital.org")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_domain_no_match(self):
        msg = _make_email(sender="user@other.com")
        cl = _make_list(1, "Hospital", "grant-related")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "hospital.org")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 0

    def test_domain_display_name_form_matches(self):
        """2026-05-12 — display-name form of the From header was
        leaving a trailing ``>`` in the domain extract. Operator's
        CTOx rule never fired in production because the matcher saw
        ``ctox.com>`` and the equality check missed. Pin against
        regression."""
        msg = _make_email(sender='"Vendor" <news@vendor.example>')
        cl = _make_list(1, "Vendor", "marketing")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "vendor.example")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_domain_subdomain_matches(self):
        """2026-05-12 — operator caught a sender_domain rule that
        never fired because vendor mail came from marketing /
        newsletter / mail subdomains (e.g. ``news@email.ctox.com``).
        Pattern ``ctox.com`` now matches both ``ctox.com`` and any
        subdomain ``*.ctox.com``. Dot boundary required so
        ``notvendor.example`` still doesn't match ``vendor.example``."""
        # Pattern matches the apex domain.
        msg = _make_email(sender="x@vendor.example")
        cl = _make_list(1, "Vendor", "marketing")
        rules = {1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "vendor.example")]}
        assert len(collect_hints(msg, [cl], rules)) == 1
        # Pattern matches a subdomain.
        msg = _make_email(sender="x@news.vendor.example")
        assert len(collect_hints(msg, [cl], rules)) == 1
        # Pattern matches a 2-level subdomain.
        msg = _make_email(sender="x@list.marketing.vendor.example")
        assert len(collect_hints(msg, [cl], rules)) == 1
        # Pattern does NOT match a sibling domain that just happens
        # to share a suffix (dot-boundary check).
        msg = _make_email(sender="x@notvendor.example")
        assert len(collect_hints(msg, [cl], rules)) == 0
        msg = _make_email(sender="x@vendor.example.evil")
        assert len(collect_hints(msg, [cl], rules)) == 0


class TestSubjectMatching:
    def test_substring_match(self):
        msg = _make_email(subject="RE: Invoice #1234 attached")
        cl = _make_list(1, "Invoices", "invoices")
        rules = {1: [_make_rule(1, 1, RuleType.SUBJECT, "invoice")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_regex_match(self):
        msg = _make_email(subject="Invoice #INV-2026-0042")
        cl = _make_list(1, "Invoices", "invoices")
        rules = {1: [_make_rule(1, 1, RuleType.SUBJECT, r"INV-\d{4}-\d{4}")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 1

    def test_invalid_regex_falls_back_safely(self):
        msg = _make_email(subject="Something [weird")
        cl = _make_list(1, "Test", "fyi")
        # Invalid regex — unclosed bracket. Should not crash.
        rules = {1: [_make_rule(1, 1, RuleType.SUBJECT, "[weird")]}
        hints = collect_hints(msg, [cl], rules)
        # Substring match should still work.
        assert len(hints) == 1

    def test_subject_no_match(self):
        msg = _make_email(subject="Lunch plans")
        cl = _make_list(1, "Invoices", "invoices")
        rules = {1: [_make_rule(1, 1, RuleType.SUBJECT, "invoice")]}
        hints = collect_hints(msg, [cl], rules)
        assert len(hints) == 0


class TestMultipleListsAndRules:
    def test_multiple_matches(self):
        msg = _make_email(sender="boss@company.com", subject="Invoice for review")
        lists = [
            _make_list(1, "VIP", "to-respond"),
            _make_list(2, "Billing", "invoices"),
        ]
        rules = {
            1: [_make_rule(1, 1, RuleType.SENDER, "boss@company.com")],
            2: [_make_rule(2, 2, RuleType.SUBJECT, "invoice")],
        }
        hints = collect_hints(msg, lists, rules)
        assert len(hints) == 2
        categories = {h.category for h in hints}
        assert "to-respond" in categories
        assert "invoices" in categories

    def test_global_sorted_first(self):
        msg = _make_email(sender="user@hospital.org")
        lists = [
            _make_list(1, "Personal", "fyi", is_global=False),
            _make_list(2, "Global Hospital", "grant-related", is_global=True),
        ]
        rules = {
            1: [_make_rule(1, 1, RuleType.SENDER_DOMAIN, "hospital.org")],
            2: [_make_rule(2, 2, RuleType.SENDER_DOMAIN, "hospital.org")],
        }
        hints = collect_hints(msg, lists, rules)
        assert len(hints) == 2
        assert hints[0].is_global is True
        assert hints[1].is_global is False

    def test_empty_rules(self):
        msg = _make_email()
        cl = _make_list(1, "Empty", "fyi")
        hints = collect_hints(msg, [cl], {})
        assert len(hints) == 0

    def test_no_lists(self):
        msg = _make_email()
        hints = collect_hints(msg, [], {})
        assert len(hints) == 0


class TestSkipAi:
    def test_find_skip_ai_hint(self):
        hints = [
            ListHint(category="fyi", rule_type=RuleType.SENDER, pattern="a@b.com", skip_ai=False),
            ListHint(category="invoices", rule_type=RuleType.SUBJECT, pattern="invoice", skip_ai=True),
        ]
        result = find_skip_ai_hint(hints)
        assert result is not None
        assert result.category == "invoices"
        assert result.skip_ai is True

    def test_no_skip_ai_returns_none(self):
        hints = [
            ListHint(category="fyi", rule_type=RuleType.SENDER, pattern="a@b.com", skip_ai=False),
        ]
        assert find_skip_ai_hint(hints) is None

    def test_empty_returns_none(self):
        assert find_skip_ai_hint([]) is None

    def test_global_skip_ai_takes_precedence(self):
        """Global hints are sorted first by collect_hints, so find_skip_ai_hint
        naturally picks the global one first."""
        msg = _make_email(sender="billing@corp.com")
        lists = [
            _make_list(1, "Personal", "fyi", is_global=False),
            _make_list(2, "Global", "invoices", is_global=True),
        ]
        rules = {
            1: [_make_rule(1, 1, RuleType.SENDER, "billing@corp.com", skip_ai=True)],
            2: [_make_rule(2, 2, RuleType.SENDER, "billing@corp.com", skip_ai=True)],
        }
        hints = collect_hints(msg, lists, rules)
        skip = find_skip_ai_hint(hints)
        assert skip is not None
        assert skip.is_global is True
        assert skip.category == "invoices"
