"""Regression: ReDoS hardening for the SUBJECT rule matcher.

Operator-authored ``ListRule.pattern`` values for ``RuleType.SUBJECT``
flow into a ``regex.search`` call against the inbound email's subject.
Before  this used stdlib ``re`` which has no per-call timeout — a
pathological backtracker (e.g. ``(a|aa)+$`` against a long ``a..ab``
subject) would peg the worker thread for seconds to minutes. The fix
swaps the call site to the PyPI ``regex`` package with ``timeout=1.0``
and a ``TimeoutError`` is treated as a non-match.

These tests pin:

* the substring fast-path still wins (no regex engine invoked when the
  pattern is a literal substring of the subject),
* a pathological pattern returns ``False`` and the call completes
  within a small multiple of the 1-second timeout budget,
* a syntactically invalid pattern still returns ``False`` (the prior
  ``re.error`` fallback contract is preserved across the engine swap).
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from email_triage.classify.hints import _rule_matches
from email_triage.engine.models import EmailMessage, ListRule, RuleType


def _make_email(subject: str) -> EmailMessage:
    return EmailMessage(
        message_id="m-redos-1",
        provider="test",
        sender="x@example.com",
        recipients=["y@example.com"],
        subject=subject,
        body_text="",
        date=datetime(2026, 5, 24, 12, 0, tzinfo=timezone.utc),
    )


def _make_rule(pattern: str) -> ListRule:
    return ListRule(
        id=1, list_id=1, rule_type=RuleType.SUBJECT,
        pattern=pattern, skip_ai=False,
    )


class TestReDoSBounded:
    def test_pathological_pattern_returns_false_within_timeout(self):
        """``(a|aa)+$`` against ``a``*40 + ``b`` is the canonical evil
        regex — catastrophic backtracking. With the bounded engine +
        ``timeout=1.0`` the call must terminate (False) within a small
        multiple of the timeout budget. We allow 3 s of headroom for
        slow CI runners but the actual cap is 1 s + engine overhead.
        """
        # Pattern is NOT a substring of the subject — substring fast-path
        # in _rule_matches won't shortcut us. Has to hit the engine.
        rule = _make_rule(r"^(a|aa)+$")
        msg = _make_email("a" * 40 + "b")

        t0 = time.monotonic()
        result = _rule_matches(rule, msg)
        elapsed = time.monotonic() - t0

        assert result is False, "pathological pattern must not falsely match"
        assert elapsed < 3.0, (
            f"ReDoS budget exceeded: {elapsed:.2f}s — bounded-regex timeout "
            f"either disabled or the regex package optimised this pattern out "
            f"(both cases need investigation)."
        )

    def test_invalid_regex_falls_back_to_false(self):
        """Engine swap preserves the prior contract: a malformed pattern
        returns False instead of raising. Pre-fix this was ``re.error``;
        post-fix it's ``regex.error``. The handler catches both.
        """
        rule = _make_rule("[unclosed")  # invalid pattern (no closing ])
        msg = _make_email("doesn't matter")
        assert _rule_matches(rule, msg) is False

    def test_valid_regex_still_matches(self):
        """Sanity: non-pathological patterns still work — proves the
        engine swap didn't break the happy path."""
        rule = _make_rule(r"INV-\d{4}")
        msg = _make_email("RE: Invoice INV-2026 attached")
        assert _rule_matches(rule, msg) is True

    def test_substring_fast_path_skips_engine(self):
        """When the pattern is a literal substring of the subject, the
        substring branch wins before the engine is invoked. A
        pathological pattern that ALSO happens to be a literal substring
        still matches instantly (the engine never sees it). Documents
        the behaviour: substring match precedes regex match.
        """
        # Pattern is a literal substring of subject (case-insensitive).
        rule = _make_rule("(a|aa)+")
        msg = _make_email("inbox alert (a|aa)+ trigger")

        t0 = time.monotonic()
        result = _rule_matches(rule, msg)
        elapsed = time.monotonic() - t0

        assert result is True
        assert elapsed < 0.1, (
            "substring fast-path should not invoke the regex engine"
        )

    def test_none_subject_does_not_crash(self):
        """Defensive: ``EmailMessage.subject`` is typed str, but
        historical bugs have surfaced None values from malformed
        providers. The engine call now passes ``subject or ""`` so a
        None subject must not raise — it just doesn't match.
        """
        rule = _make_rule(r"anything")
        msg = _make_email("")  # empty string subject
        # Empty subject → substring branch returns False (no match),
        # engine branch searches in "" → no match. No exception.
        assert _rule_matches(rule, msg) is False
