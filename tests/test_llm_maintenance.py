"""Tests for LLM maintenance windows (#149 Bundle C)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from email_triage.llm_maintenance import (
    MaintenanceWindow,
    _matches_at,
    _parse_cron,
    active_window_for,
    parse_windows,
)


# ---------------------------------------------------------------------------
# Cron expression parsing + matching
# ---------------------------------------------------------------------------

def test_parse_cron_nightly_at_one_am():
    """``0 1 * * *`` matches every day at exactly 01:00."""
    minutes, hours, doms, months, dows = _parse_cron("0 1 * * *")
    assert minutes == {0}
    assert hours == {1}
    assert doms == set(range(1, 32))
    assert months == set(range(1, 13))
    assert dows == set(range(0, 7))


def test_parse_cron_weekly_sunday_three_am():
    """``0 3 * * 0`` matches Sundays at 03:00."""
    minutes, hours, doms, months, dows = _parse_cron("0 3 * * 0")
    assert minutes == {0}
    assert hours == {3}
    assert dows == {0}


def test_parse_cron_hourly():
    """``*/15 * * * *`` matches every quarter hour."""
    minutes, _, _, _, _ = _parse_cron("*/15 * * * *")
    assert minutes == {0, 15, 30, 45}


def test_parse_cron_rejects_bad_expression():
    with pytest.raises(ValueError):
        _parse_cron("0 25 * * *")  # hour out of range
    with pytest.raises(ValueError):
        _parse_cron("0 1 * *")     # missing field


def test_matches_at_nightly():
    """Cron 0 1 * * * matches at 2026-05-10 01:00 UTC, not at 01:01."""
    assert _matches_at("0 1 * * *", datetime(2026, 5, 10, 1, 0, tzinfo=timezone.utc))
    assert not _matches_at("0 1 * * *", datetime(2026, 5, 10, 1, 1, tzinfo=timezone.utc))
    assert not _matches_at("0 1 * * *", datetime(2026, 5, 10, 0, 0, tzinfo=timezone.utc))


# ---------------------------------------------------------------------------
# parse_windows (YAML round-trip)
# ---------------------------------------------------------------------------

def test_parse_windows_accepts_well_formed_list():
    raw = [
        {"host": "llm-host", "cron": "0 1 * * *",
         "duration_minutes": 30, "backend": "ollama"},
    ]
    windows = parse_windows(raw)
    assert len(windows) == 1
    assert windows[0].host == "llm-host"
    assert windows[0].duration_minutes == 30


def test_parse_windows_skips_malformed_entry():
    raw = [
        {"host": "llm-host", "cron": "garbage",
         "duration_minutes": 30, "backend": "ollama"},
        {"host": "llm-host", "cron": "0 1 * * *",
         "duration_minutes": 30, "backend": "ollama"},
    ]
    windows = parse_windows(raw)
    # Bad row dropped; good row kept.
    assert len(windows) == 1


def test_parse_windows_returns_empty_for_none():
    assert parse_windows(None) == []
    assert parse_windows([]) == []


# ---------------------------------------------------------------------------
# active_window_for
# ---------------------------------------------------------------------------

def test_active_window_inside_window():
    """01:15 falls inside a 30-min window starting at 01:00."""
    windows = [MaintenanceWindow(
        host="llm-host", cron="0 1 * * *",
        duration_minutes=30, backend="ollama",
    )]
    now = datetime(2026, 5, 10, 1, 15, tzinfo=timezone.utc)
    active = active_window_for("ollama", windows, now=now)
    assert active is not None
    assert active.window.host == "llm-host"
    assert active.started_at == datetime(2026, 5, 10, 1, 0, tzinfo=timezone.utc)
    assert active.ends_at == datetime(2026, 5, 10, 1, 30, tzinfo=timezone.utc)


def test_active_window_outside_window():
    """02:00 is outside a 30-min window starting at 01:00."""
    windows = [MaintenanceWindow(
        host="llm-host", cron="0 1 * * *",
        duration_minutes=30, backend="ollama",
    )]
    now = datetime(2026, 5, 10, 2, 0, tzinfo=timezone.utc)
    assert active_window_for("ollama", windows, now=now) is None


def test_active_window_filters_by_backend():
    """A window for a different backend doesn't match."""
    windows = [MaintenanceWindow(
        host="llm-host", cron="* * * * *",
        duration_minutes=30, backend="openai",
    )]
    now = datetime(2026, 5, 10, 1, 15, tzinfo=timezone.utc)
    assert active_window_for("ollama", windows, now=now) is None
    # And matches when the backend lines up.
    assert active_window_for("openai", windows, now=now) is not None


# ---------------------------------------------------------------------------
# Integration with the watcher's enqueue+log path
# ---------------------------------------------------------------------------

def test_inside_window_log_uses_info_severity_indirectly():
    """Smoke-test that the maintenance-window matcher returns the
    rich ActiveWindow shape expected by the log line. The log
    severity itself is set in app.py based on whether the matcher
    returns non-None."""
    windows = [MaintenanceWindow(
        host="llm-host", cron="0 1 * * *",
        duration_minutes=30, backend="ollama",
    )]
    now = datetime(2026, 5, 10, 1, 5, tzinfo=timezone.utc)
    active = active_window_for("ollama", windows, now=now)
    assert active is not None
    # The downstream log line stringifies ends_at in HH:MM UTC.
    assert active.ends_at.strftime("%H:%M UTC") == "01:30 UTC"
