""" -- unit tests for `email_triage._hm_render` SSOT.

Covers the audience-tz-aware `HH:MM` rendering contract:
`render_hm_for_audience(dt, *, audience_tz=None)` -- audience_tz=None
returns "HH:MM UTC" (matches  wire format); audience_tz=<zone>
returns "HH:MM <tz-label>" in that zone.
"""
from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from email_triage._hm_render import render_hm_for_audience


class TestRenderHmForAudience:
    def test_audience_tz_none_returns_utc_label(self):
        dt = datetime(2026, 7, 11, 14, 30, tzinfo=timezone.utc)
        assert render_hm_for_audience(dt) == "14:30 UTC"

    def test_audience_tz_none_explicit_kwarg(self):
        dt = datetime(2026, 7, 11, 14, 30, tzinfo=timezone.utc)
        assert render_hm_for_audience(dt, audience_tz=None) == "14:30 UTC"

    def test_naive_datetime_treated_as_utc(self):
        # Fail-safe: naive input treated as UTC per SSOT docstring.
        dt = datetime(2026, 7, 11, 14, 30)
        assert render_hm_for_audience(dt) == "14:30 UTC"

    def test_audience_tz_eastern_shifts_wallclock(self):
        # 14:30 UTC in July DST -> 10:30 EDT (UTC-4).
        dt = datetime(2026, 7, 11, 14, 30, tzinfo=timezone.utc)
        eastern = ZoneInfo("America/New_York")
        result = render_hm_for_audience(dt, audience_tz=eastern)
        assert result.startswith("10:30 ")
        # EDT label per %Z on Windows may be "Eastern Daylight Time"
        # or "EDT" -- accept both by checking the wall-clock time.
        assert " " in result
        _, label = result.split(" ", 1)
        assert label  # non-empty label

    def test_audience_tz_utc_zone_returns_utc(self):
        dt = datetime(2026, 7, 11, 14, 30, tzinfo=timezone.utc)
        # ZoneInfo("UTC") vs timezone.utc yield different %Z labels
        # on some platforms; call this out as a contract-nuance test.
        result = render_hm_for_audience(dt, audience_tz=ZoneInfo("UTC"))
        assert result.startswith("14:30 ")

    def test_aware_non_utc_input_normalized(self):
        # Input is in Eastern; audience_tz=None -> should output UTC.
        eastern = ZoneInfo("America/New_York")
        dt = datetime(2026, 7, 11, 10, 30, tzinfo=eastern)
        # 10:30 EDT is 14:30 UTC.
        assert render_hm_for_audience(dt) == "14:30 UTC"
