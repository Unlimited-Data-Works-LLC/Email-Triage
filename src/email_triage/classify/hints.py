"""List-hint matching logic.

Collects matching classification-list rules for an email message and
returns them as ListHint objects.  These hints are passed to the LLM
as advisory context, unless ``skip_ai=True`` on a matching rule —
in which case the hint short-circuits classification entirely.
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Sequence

from email_triage.engine.models import (
    ClassificationList,
    EmailMessage,
    ListHint,
    ListRule,
    RuleType,
)


def _extract_address(sender: str) -> str:
    """Pull the bare address out of a From-header value.

    ``EmailMessage.sender`` carries the raw ``From:`` header which is
    typically ``"Display Name" <user@domain.tld>`` — display name +
    angle brackets surrounding the address. Without parsing, the
    naive ``rsplit("@", 1)[-1]`` form leaves the closing ``>`` and
    every sender match silently fails (operator caught a CTOx rule
    that never fired in production — sender was
    ``"CTOx" <news@email.ctox.com>``, the matcher saw
    ``email.ctox.com>`` and the equality check missed).

    ``email.utils.parseaddr`` handles the display-name form, RFC 5321
    address syntax, and quoted display names. Falls back to the raw
    string if parsing returns nothing usable.
    """
    if not sender:
        return ""
    _name, addr = parseaddr(sender)
    if addr:
        return addr.lower()
    # parseaddr returns empty when input is unparseable. Best-effort
    # fallback: strip surrounding whitespace + angle brackets so a
    # bare ``user@domain`` (no display name, no brackets) still works.
    return sender.strip().strip("<>").lower()


def _extract_domain(sender: str) -> str:
    """Return the lowercased domain portion of the sender's address.

    Empty string when the sender has no ``@`` (which is malformed but
    appears occasionally in the wild). The address is extracted via
    ``_extract_address`` first so display-name form doesn't corrupt
    the rsplit.
    """
    addr = _extract_address(sender)
    if "@" not in addr:
        return ""
    return addr.rsplit("@", 1)[-1]


def _rule_matches(rule: ListRule, message: EmailMessage) -> bool:
    """Check whether a single rule matches the given message."""
    if rule.rule_type == RuleType.SENDER:
        # Operator types a bare address (e.g. ``news@ctox.com``); the
        # incoming ``message.sender`` may be the display-name form
        # (``"CTOx" <news@ctox.com>``). Parse both sides to a bare
        # address before comparing.
        return _extract_address(message.sender) == _extract_address(rule.pattern)

    if rule.rule_type == RuleType.SENDER_DOMAIN:
        # Pattern should be a domain like "hospital.org" or
        # "@hospital.org". Subdomain match too — a pattern of
        # ``ctox.com`` covers ``news@email.ctox.com`` (the common
        # newsletter / marketing pattern) but NOT ``notctox.com``
        # (dot boundary required). Without subdomain match every
        # vendor's marketing-subdomain mail dodges the rule.
        domain = rule.pattern.lstrip("@").lower().lstrip(".")
        if not domain:
            return False
        sender_domain = _extract_domain(message.sender)
        if not sender_domain:
            return False
        if sender_domain == domain:
            return True
        return sender_domain.endswith("." + domain)

    if rule.rule_type == RuleType.SUBJECT:
        # Substring match first; if the pattern looks like a regex, try that.
        pattern = rule.pattern
        if message.subject and pattern.lower() in message.subject.lower():
            return True
        try:
            return bool(re.search(pattern, message.subject, re.IGNORECASE))
        except re.error:
            return False

    return False


def collect_hints(
    message: EmailMessage,
    lists: Sequence[ClassificationList],
    rules_by_list: dict[int, list[ListRule]],
) -> list[ListHint]:
    """Find all rules that match ``message`` and return them as ListHints.

    Parameters
    ----------
    message:
        The email to match against.
    lists:
        All classification lists to consider (personal + global).
    rules_by_list:
        Mapping from ``ClassificationList.id`` to its rules.

    Returns
    -------
    List of matching hints, ordered global-first then personal.
    """
    hints: list[ListHint] = []

    for cl in lists:
        rules = rules_by_list.get(cl.id, [])
        for rule in rules:
            if _rule_matches(rule, message):
                hints.append(ListHint(
                    category=cl.category,
                    rule_type=rule.rule_type,
                    pattern=rule.pattern,
                    skip_ai=rule.skip_ai,
                    list_name=cl.name,
                    is_global=cl.is_global,
                ))

    # Sort: global hints first, then personal.
    hints.sort(key=lambda h: (not h.is_global, h.category))
    return hints


def find_skip_ai_hint(hints: list[ListHint]) -> ListHint | None:
    """Return the first hint with ``skip_ai=True``, or None.

    When a skip_ai hint exists, the caller should bypass LLM classification
    and use the hint's category directly.  Global skip_ai rules take
    precedence over personal ones (due to the sort order from collect_hints).
    """
    for h in hints:
        if h.skip_ai:
            return h
    return None
