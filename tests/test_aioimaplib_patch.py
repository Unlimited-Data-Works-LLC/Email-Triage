"""Tests for the aioimaplib upstream-bug runtime patch.

Validates:
1. Importing the patch module installs the iterative version on
   ``IMAP4ClientProtocol``.
2. The iterative version handles a 5000-line synthetic response
   without exceeding Python's recursion limit (which the recursive
   upstream version would).

The patch addresses upstream issue #118
(https://github.com/bamthomas/aioimaplib/issues/118) — recursion
explosion when fetching messages with many CRLF-separated lines.
"""

from __future__ import annotations

import sys

import pytest


aioimaplib = pytest.importorskip("aioimaplib")
from aioimaplib.aioimaplib import IMAP4ClientProtocol  # noqa: E402

from email_triage.providers import _aioimaplib_patch  # noqa: E402


def test_patch_installed_on_class():
    """Importing the patch module replaces the class method."""
    assert _aioimaplib_patch._PATCHED is True
    assert (
        IMAP4ClientProtocol._handle_responses.__name__
        == "_handle_responses_iter"
    )


def test_patch_apply_is_idempotent():
    """Re-invoking apply_aioimaplib_patch is a no-op (no double-wrap)."""
    before = IMAP4ClientProtocol._handle_responses
    _aioimaplib_patch.apply_aioimaplib_patch()
    after = IMAP4ClientProtocol._handle_responses
    assert before is after


def test_iterative_handles_large_response_without_recursion():
    """5000 CRLF-separated lines must not blow Python's stack.

    Default recursionlimit is 1000; the recursive upstream version
    fails at ~985 lines deep (per the actual production trace). The
    iterative replacement should consume the entire buffer with a
    flat call stack.
    """
    payload = b"* OK foo\r\n" * 5000

    class StubProto:
        """Minimal IMAP4ClientProtocol stand-in for the patched method."""

        pending_sync_command = None

    def line_handler(line, current_cmd):
        # No-op handler — for this test we only care that the parser
        # walks the entire buffer without recursion.
        return None

    # Tighten the recursion limit so the test would catch a regression
    # even on machines with a generous default.
    original_limit = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        # Should return cleanly (data exhausted, no current_cmd).
        IMAP4ClientProtocol._handle_responses(
            StubProto(), payload, line_handler, None,
        )
    finally:
        sys.setrecursionlimit(original_limit)


def test_iterative_raises_incomplete_read_on_partial_line():
    """Half-line at end of buffer must surface IncompleteRead."""
    from aioimaplib.aioimaplib import IncompleteRead

    payload = b"* OK foo\r\n* OK partial-no-crlf"

    class StubProto:
        pending_sync_command = None

    def line_handler(line, current_cmd):
        return None

    with pytest.raises(IncompleteRead):
        IMAP4ClientProtocol._handle_responses(
            StubProto(), payload, line_handler, None,
        )
