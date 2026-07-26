"""Unit tests for the US-locale display formatter (2026-07-13, op ask).

Covers :func:`email_triage._us_datetime.format_us_datetime` — the
server-side entry point behind the Jinja filter ``us_datetime`` and
every non-browser rendering surface (email digests, Signal messages,
JSON display fields).

The browser-side JS twin in ``web/templates/base.html`` is exercised by
the rendered-view tests (``test_web/test_admin_stats_watcher_states_regression``
already asserts the ``<time data-us-datetime>`` element type; adding
JS-level assertions is a Playwright-level concern out of scope here).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest

from email_triage._us_datetime import format_us_datetime


# A single reference tz for deterministic assertions across CI runners.
# Server-local at test time is whatever the host reports; we pass an
# explicit `tz=` so the format shape is deterministic regardless.
_EDT = timezone(timedelta(hours=-4), name="EDT")
_EST = timezone(timedelta(hours=-5), name="EST")
_UTC = timezone.utc


class TestBasicShape:
    def test_shape_edt_afternoon(self):
        dt = datetime(2026, 7, 13, 13, 12, 33, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "7/13/2026 9:12:33 AM EDT"

    def test_shape_pm_conversion(self):
        # 20:47 UTC → 16:47 EDT → 4:47:00 PM EDT
        dt = datetime(2026, 7, 13, 20, 47, 0, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "7/13/2026 4:47:00 PM EDT"

    def test_shape_midnight_wraps_prev_day(self):
        # 03:59 UTC → 23:59 EDT (prev day) → 11:59:52 PM EDT
        dt = datetime(2026, 7, 13, 3, 59, 52, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "7/12/2026 11:59:52 PM EDT"

    def test_shape_noon_pm_semantics(self):
        # 16:00 UTC → 12:00 EDT → 12:00:00 PM (noon is PM, not AM)
        dt = datetime(2026, 7, 13, 16, 0, 0, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "7/13/2026 12:00:00 PM EDT"

    def test_shape_midnight_am_semantics(self):
        # 04:00 UTC → 00:00 EDT → 12:00:00 AM (midnight is AM 12, not 0)
        dt = datetime(2026, 7, 13, 4, 0, 0, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "7/13/2026 12:00:00 AM EDT"

    def test_no_leading_zero_on_month_or_day(self):
        # Single-digit month + day render bare, matching '7/13/2026' shape.
        dt = datetime(2026, 3, 5, 15, 30, 0, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "3/5/2026 11:30:00 AM EDT"

    def test_leading_zero_on_minute_and_second(self):
        # Minutes/seconds pad to 2 digits so the string is readable.
        dt = datetime(2026, 3, 5, 15, 5, 3, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EDT) == "3/5/2026 11:05:03 AM EDT"


class TestInputCoercion:
    def test_iso_string_utc_z_suffix(self):
        assert format_us_datetime("2026-07-13T13:12:33Z", tz=_EDT) == \
            "7/13/2026 9:12:33 AM EDT"

    def test_iso_string_offset_form(self):
        assert format_us_datetime("2026-07-13T13:12:33+00:00", tz=_EDT) == \
            "7/13/2026 9:12:33 AM EDT"

    def test_naive_datetime_assumed_utc(self):
        # Naive datetime → assumed UTC, then converted to target tz.
        dt = datetime(2026, 7, 13, 13, 12, 33)  # no tzinfo
        assert format_us_datetime(dt, tz=_EDT) == "7/13/2026 9:12:33 AM EDT"


class TestNullAndErrorCases:
    def test_none_returns_em_dash(self):
        assert format_us_datetime(None) == "—"

    def test_empty_string_returns_em_dash(self):
        assert format_us_datetime("") == "—"

    def test_unparseable_string_returns_em_dash(self):
        assert format_us_datetime("not a date") == "—"

    def test_non_datetime_non_string_returns_em_dash(self):
        assert format_us_datetime(12345) == "—"


class TestTimezoneVariants:
    def test_est_winter(self):
        # January in EST (no DST): 14:12 UTC → 09:12 EST
        dt = datetime(2026, 1, 15, 14, 12, 33, tzinfo=_UTC)
        assert format_us_datetime(dt, tz=_EST) == "1/15/2026 9:12:33 AM EST"

    def test_utc_zone_when_explicit(self):
        # If caller passes UTC as target, tz abbrev is 'UTC'.
        dt = datetime(2026, 7, 13, 13, 12, 33, tzinfo=_UTC)
        # Some platforms report 'UTC', others 'Coordinated Universal Time'.
        # Assert the numeric shape + AM/PM; tz-abbrev spelling is best-effort.
        result = format_us_datetime(dt, tz=_UTC)
        assert result.startswith("7/13/2026 1:12:33 PM")


class TestJinjaFilterEntry:
    def test_filter_wrapper_delegates(self):
        from email_triage._us_datetime import us_datetime_filter
        # Filter drops the `tz=` kwarg (Jinja filter signature is 1-arg).
        # Just confirm it produces a string on a valid ISO input.
        result = us_datetime_filter("2026-07-13T13:12:33Z")
        # Format is server-local (test host); shape check only.
        assert "2026" in result
        assert " AM" in result or " PM" in result
        assert "7/" in result and "/2026" in result

    def test_filter_wrapper_none_input(self):
        from email_triage._us_datetime import us_datetime_filter
        assert us_datetime_filter(None) == "—"
