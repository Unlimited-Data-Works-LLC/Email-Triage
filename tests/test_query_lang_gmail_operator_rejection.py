"""Runtime unit test — ``translate_imap_query_to_imap`` rejects Gmail-operator
syntax at the translator SSOT (N-390 root fix, 2026-07-12).

Root cause: ``sent_mail_capture.py:270`` fallback path was passing the Gmail-
search-operator string ``"in:sent"`` verbatim as an IMAP SEARCH criterion.
Gmail's provider-side search honours it via ``X-GM-RAW``; IMAP (dovecot) does
NOT — server BAD-replied on every sweep tick for the ``ettest`` account
(observed 4×/day for weeks; confirmed post-deploy via ``da325373``'s ``#92
fold`` shape hints: ``imap_verb=None imap_query_len=7`` = ``"in:sent"``).

Layer-1 fix hardened ``translate_imap_query_to_imap`` to REJECT Gmail-operator
prefixes at the SSOT (fail-CLOSED to empty criteria + WARNING) so a future
forgotten caller cannot smuggle Gmail-syntax to a dovecot ``client.search(...)``
and reproduce N-390.

Existing behaviour is preserved: ``is:unread`` → ``UNSEEN`` (the ONE ``is:*``
form that IS translated); every other input passes through unchanged.
"""

from __future__ import annotations

import pytest

from email_triage.engine.query_lang import translate_imap_query_to_imap


# ============================================================================
# Existing preserved behaviour — regression fence
# ============================================================================

@pytest.mark.parametrize(
    "query,expected",
    [
        # is:unread → UNSEEN (the ONE Gmail-op form that IS translated)
        ("is:unread", "UNSEEN"),
        ("is:unread FROM alice@example.com", "UNSEEN FROM alice@example.com"),
        # Native IMAP SEARCH criteria pass through unchanged
        ("UNSEEN", "UNSEEN"),
        ("ALL", "ALL"),
        ("SINCE 1-Jan-2026", "SINCE 1-Jan-2026"),
        ("SUBJECT foo FROM bar@baz", "SUBJECT foo FROM bar@baz"),
    ],
)
def test_translate_imap_query_preserves_legit_input(
    query: str, expected: str
) -> None:
    """Legitimate IMAP SEARCH criteria + the one ``is:unread`` shortcut pass
    through unchanged (regression fence around the N-390 hardening)."""
    assert translate_imap_query_to_imap(query) == expected


# ============================================================================
# N-390 hardening — Gmail-operator syntax REJECTED
# ============================================================================

@pytest.mark.parametrize(
    "gmail_syntax_query",
    [
        # The exact production trigger — sent_mail_capture fallback
        "in:sent",
        # Every Gmail ``in:`` bucket
        "in:inbox",
        "in:trash",
        "in:spam",
        "in:anywhere",
        # ``label:`` — Gmail label operator
        "label:important",
        "label:foo/bar",
        # ``is:*`` other than ``is:unread`` (which IS translated)
        "is:read",
        "is:starred",
        "is:sent",
        "is:important",
        # Whitespace-prefixed still triggers (strip() applied before check)
        "  in:sent",
        "\tlabel:foo",
    ],
)
def test_gmail_operator_syntax_returns_empty(gmail_syntax_query: str) -> None:
    """Every Gmail-operator prefix is REJECTED (fail-CLOSED to empty).

    Empty return signals the caller ("no criteria" — the caller either falls
    back to ``ALL`` semantics upstream OR, better, refuses to run the search —
    both preferable to a dovecot BAD-reply).
    """
    assert translate_imap_query_to_imap(gmail_syntax_query) == ""


def test_is_unread_still_translated_despite_prefix_check() -> None:
    """``is:unread`` MUST still translate to ``UNSEEN`` (order of guard clauses
    is correctness-critical — the ``is:unread`` translation runs BEFORE the
    Gmail-operator rejection, otherwise the fix would break the one legit
    ``is:*`` shortcut)."""
    assert translate_imap_query_to_imap("is:unread") == "UNSEEN"
    assert translate_imap_query_to_imap("is:unread SINCE 1-Jan-2026") == (
        "UNSEEN SINCE 1-Jan-2026"
    )
