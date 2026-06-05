"""Tests for _safe_int — the request-input int parser.

``int(form.get("x"))`` raises ValueError on a non-numeric value (a
tampered form field, ``?offset=abc``) — uncaught, that escapes the
handler as a 500. ``_safe_int`` coerces missing / blank / non-numeric
input to a caller-supplied default instead.
"""

from __future__ import annotations

from email_triage.web.routers.ui._shared import _safe_int


def test_parses_numeric_string():
    assert _safe_int("42", 0) == 42


def test_passes_through_int():
    assert _safe_int(7, 0) == 7


def test_non_numeric_string_falls_back():
    assert _safe_int("abc", 9) == 9


def test_none_falls_back():
    assert _safe_int(None, 3) == 3


def test_empty_string_falls_back():
    assert _safe_int("", 5) == 5


def test_float_string_falls_back():
    # int("1.5") raises ValueError — a float-shaped string is not a
    # valid int and must fall back rather than 500.
    assert _safe_int("1.5", 0) == 0


def test_default_is_zero():
    assert _safe_int("x") == 0


def test_negative_string_parses():
    assert _safe_int("-12", 0) == -12


def test_whitespace_padded_numeric_parses():
    # int() tolerates surrounding whitespace.
    assert _safe_int("  8  ", 0) == 8
