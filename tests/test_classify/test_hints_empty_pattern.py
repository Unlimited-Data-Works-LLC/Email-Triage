"""Engine defense-in-depth for  — empty-pattern matches-everything.

The SUBJECT branch of ``_rule_matches`` previously did a substring
test ``pattern.lower() in message.subject.lower()`` BEFORE the regex
attempt. With ``pattern == ""`` Python's ``in`` operator returns True
for any subject ("the empty string is a substring of every string"),
so a saved empty-pattern rule would silently match every email and —
if the rule had ``skip_ai=True`` — force-skip-AI on every message.

The web/API entry points now reject empty patterns at the boundary
(see ``tests/test_web/test_rule_empty_pattern.py``), but a historic
row could still exist in a long-lived install, and any future entry
point would need to remember the rule. The engine short-circuits an
empty pattern at the top of ``_rule_matches`` as a second layer.
"""

from __future__ import annotations

from datetime import datetime, timezone

from email_triage.classify.hints import _rule_matches, collect_hints
from email_triage.engine.models import (
    ClassificationList,
    EmailMessage,
    ListRule,
    RuleType,
)


def _make_email(subject: str = "arbitrary subject", sender: str = "a@b.com") -> EmailMessage:
    return EmailMessage(
        message_id="m-empty-1",
        provider="test",
        sender=sender,
        recipients=["y@example.com"],
        subject=subject,
        body_text="",
        date=datetime(2026, 5, 24, 12, 0, tzinfo=timezone.utc),
    )


def _make_rule(rule_type: RuleType, pattern: str, skip_ai: bool = False) -> ListRule:
    return ListRule(
        id=1, list_id=1, rule_type=rule_type,
        pattern=pattern, skip_ai=skip_ai,
    )


class TestEmptyPatternDefenseInDepth:
    def test_empty_subject_pattern_does_not_match(self):
        """Pre-fix: ``"" in any_subject`` was True → match-everything.
        Post-fix: top-of-function guard returns False for empty pattern."""
        rule = _make_rule(RuleType.SUBJECT, "")
        msg = _make_email(subject="anything at all")
        assert _rule_matches(rule, msg) is False

    def test_whitespace_only_subject_pattern_does_not_match(self):
        """Whitespace-only patterns are equivalent to empty after the
        boundary's ``strip()`` — also rejected by the engine guard."""
        rule = _make_rule(RuleType.SUBJECT, "   \t \n ")
        msg = _make_email(subject="anything at all")
        assert _rule_matches(rule, msg) is False

    def test_empty_sender_pattern_does_not_match(self):
        """The SENDER branch compares parseaddr-extracted values; an
        empty pattern would extract to ``""`` and silently match a
        sender whose parse also produced ``""`` (malformed senders in
        the wild). Guard short-circuits before that compare."""
        rule = _make_rule(RuleType.SENDER, "")
        msg = _make_email(sender='"" <>')  # malformed sender → parseaddr empty
        assert _rule_matches(rule, msg) is False

    def test_empty_sender_domain_pattern_does_not_match(self):
        """The SENDER_DOMAIN branch already short-circuits on an
        empty extracted domain, but the guard covers the case where
        the pattern is empty and the message domain isn't — defense
        is consistent across all three rule types."""
        rule = _make_rule(RuleType.SENDER_DOMAIN, "")
        msg = _make_email(sender="user@hospital.org")
        assert _rule_matches(rule, msg) is False

    def test_empty_pattern_with_skip_ai_does_not_force_skip(self):
        """Worst-case from the backlog : a saved empty rule with
        skip_ai=True would force-skip-AI on every email. Verify the
        full ``collect_hints`` + ``find_skip_ai_hint`` path returns
        no hints when only an empty-pattern rule exists."""
        from email_triage.classify.hints import find_skip_ai_hint

        rule = _make_rule(RuleType.SUBJECT, "", skip_ai=True)
        cl = ClassificationList(
            id=1, name="EvilEmpty", category="to-respond",
            owner_id=None, is_global=False,
        )
        hints = collect_hints(_make_email(), [cl], {1: [rule]})
        assert hints == []
        assert find_skip_ai_hint(hints) is None

    def test_non_empty_pattern_still_matches(self):
        """Sanity: guard didn't break the happy path."""
        rule = _make_rule(RuleType.SUBJECT, "invoice")
        msg = _make_email(subject="RE: Invoice for review")
        assert _rule_matches(rule, msg) is True
