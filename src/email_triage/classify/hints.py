"""List-hint matching logic.

Collects matching classification-list rules for an email message and
returns them as ListHint objects.  These hints are passed to the LLM
as advisory context, unless ``skip_ai=True`` on a matching rule —
in which case the hint short-circuits classification entirely.
"""

from __future__ import annotations

import re
from typing import Sequence

# PyPI ``regex`` package — used only at the SUBJECT-rule match site
# below, where the pattern is operator-authored and an evil regex
# would otherwise hang the worker thread. Stdlib ``re`` has no
# timeout. Other ``re`` uses in this module (static developer
# patterns) keep stdlib because they're not attacker-controlled.
import regex as _bounded_regex

from email_triage.engine.models import (
    ClassificationList,
    EmailMessage,
    ListHint,
    ListRule,
    RuleType,
)


# -c (2026-07-11) — CONFIG-DRIVEN ReDoS safety budget, per
# feedback_dynamic_over_hardcoding. This is a per-match compute-bound
# safety timeout on operator-authored SUBJECT regex patterns (not a
# network timeout). Default 1.0 s preserves prior behavior; raising it
# accommodates slow / complex operator patterns at the cost of a
# longer worker stall on an evil regex.
_HINT_REGEX_TIMEOUT_SECS: float = 1.0


def configure_hint_regex_timeout(timeout_secs: float) -> None:
    """-c — set the process-wide ReDoS safety budget for the SUBJECT
    rule-match site. Called at boot from ``load_config`` with
    ``classifier.hint_regex_timeout_secs``. Rejects non-positive values.
    """
    global _HINT_REGEX_TIMEOUT_SECS
    if isinstance(timeout_secs, (int, float)) and timeout_secs > 0:
        _HINT_REGEX_TIMEOUT_SECS = float(timeout_secs)


def get_hint_regex_timeout_secs() -> float:
    return _HINT_REGEX_TIMEOUT_SECS


def _extract_address(sender: str) -> str:
    """Pull the bare address out of a From-header value.

    ``EmailMessage.sender`` carries the raw ``From:`` header which is
    typically ``"Display Name" <user@domain.tld>``. A naive
    ``rsplit("@", 1)[-1]`` leaves the closing ``>`` so every sender
    match silently fails (the production CTOx rule that never fired:
    ``"CTOx" <news@email.ctox.com>`` → the matcher saw
    ``email.ctox.com>``).

    A7 (census 2026-06-09): delegates to the bare-address SSOT
    ``mail_headers.extract_bare_address`` (the ``<([^>]+)>`` regex
    resolves the CTOx case identically), replacing the local
    ``parseaddr``-based variant so all sender-match sites share one
    extractor.
    """
    from email_triage.mail_headers import extract_bare_address
    return extract_bare_address(sender)


def _extract_domain(sender: str) -> str:
    """Return the lowercased domain portion of the sender's address.

    Empty string when the sender has no ``@``. Delegates to the
    ``mail_headers.extract_domain`` SSOT (N-71, divergence census
    2026-06-09) which composes on ``extract_bare_address`` and
    applies ``rsplit("@", 1)[-1]`` — the security-correct split
    that resolves double-@ spoof addresses to the REAL (last) domain.
    """
    from email_triage.mail_headers import extract_domain as _ed
    return _ed(sender)


def _rule_matches(rule: ListRule, message: EmailMessage) -> bool:
    """Check whether a single rule matches the given message."""
    #  defense-in-depth: an empty / whitespace-only pattern is
    # nonsensical for every rule type (SENDER, SENDER_DOMAIN, SUBJECT).
    # In particular the SUBJECT branch's substring fast-path treats
    # ``"" in any_subject`` as True, so a saved empty rule would match
    # every email and force-skip-AI on every message in the worst case.
    # The web/API insert + update paths reject empty patterns at the
    # boundary now, but historic rows could still exist and any future
    # entry point would also need to remember the rule; short-circuit
    # here so the engine itself can never honor one.
    if not rule.pattern or not rule.pattern.strip():
        return False

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

    if rule.rule_type == RuleType.LIST_ID:
        # RFC 2919: `List-Id: "Human name" <list.host.tld>`. Match on the
        # bracketed identifier (or full value if unbracketed). Case-
        # insensitive on the header key AND value per common IMAP shape;
        # operator's pattern is lowercased for the compare. List-Id is NOT
        # an email address (no `@`), so extract_bare_address does not
        # apply; partition-based slicing avoids the A7-flagged
        # `<(...)>` regex + `.index("<")` slice idioms.
        raw = ""
        for k, v in (message.headers or {}).items():
            if k.lower() == "list-id":
                raw = v or ""
                break
        # Preserve the old `<([^>]+)>` regex's failure mode: only the
        # FIRST fully-bracketed segment counts; a malformed `<value` (no
        # closing `>`) falls back to the raw value, same as the regex's
        # `search` returning None (DA NTH-1 fold, 2026-07-18).
        _, open_sep, rest = raw.partition("<")
        inner_candidate, close_sep, _ = rest.partition(">")
        inner = inner_candidate if (open_sep and close_sep) else raw
        haystack = inner.strip().lower()
        needle = rule.pattern.strip().lstrip("<").rstrip(">").lower()
        return bool(haystack) and haystack == needle

    if rule.rule_type == RuleType.SUBJECT:
        # Substring match first; if the pattern looks like a regex, try that.
        pattern = rule.pattern
        if message.subject and pattern.lower() in message.subject.lower():
            return True
        # Bounded ReDoS surface: operator-authored ``pattern`` against
        # message.subject. Stdlib ``re`` has no per-call timeout, so a
        # pathological backtracker pegs the worker. ``regex.search`` with
        # a module-level timeout budget (-c: config-driven via
        # classifier.hint_regex_timeout_secs) raises TimeoutError after
        # that many seconds — we treat that exactly like a non-match,
        # same as a malformed pattern.
        try:
            return bool(_bounded_regex.search(
                pattern,
                message.subject or "",
                flags=_bounded_regex.IGNORECASE,
                timeout=_HINT_REGEX_TIMEOUT_SECS,
            ))
        except (_bounded_regex.error, TimeoutError):
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
