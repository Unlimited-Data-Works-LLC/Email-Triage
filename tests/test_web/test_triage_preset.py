"""Tests for the Run Triage search-preset dropdown (#61)."""

from datetime import date, timedelta

from email_triage.web.routers.ui import _triage_preset_to_query


def test_preset_unread_today():
    today = date.today().strftime("%d-%b-%Y")
    assert _triage_preset_to_query("unread_today", "") == f"UNSEEN SINCE {today}"


def test_preset_unread_week():
    week_ago = (date.today() - timedelta(days=7)).strftime("%d-%b-%Y")
    assert _triage_preset_to_query("unread_week", "") == f"UNSEEN SINCE {week_ago}"


def test_preset_unread_month():
    month_ago = (date.today() - timedelta(days=30)).strftime("%d-%b-%Y")
    assert _triage_preset_to_query("unread_month", "") == f"UNSEEN SINCE {month_ago}"


def test_preset_all_today():
    today = date.today().strftime("%d-%b-%Y")
    assert _triage_preset_to_query("all_today", "") == f"SINCE {today}"


def test_preset_unread_no_cap():
    assert _triage_preset_to_query("unread", "") == "UNSEEN"


def test_other_passes_freeform():
    assert _triage_preset_to_query("other", "FROM boss@example.com") == "FROM boss@example.com"


def test_other_empty_defaults_to_unseen():
    assert _triage_preset_to_query("other", "") == "UNSEEN"


def test_legacy_no_preset_with_text_returns_text():
    """Legacy callers (no preset, only freeform query) keep working."""
    assert _triage_preset_to_query("", "FROM x@y.com") == "FROM x@y.com"


def test_legacy_no_preset_empty_defaults_unseen():
    assert _triage_preset_to_query("", "") == "UNSEEN"


def test_unknown_preset_falls_back():
    """Unknown preset + no freeform falls back to UNSEEN."""
    assert _triage_preset_to_query("bogus", "") == "UNSEEN"
