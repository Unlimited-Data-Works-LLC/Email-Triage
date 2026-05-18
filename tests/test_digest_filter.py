"""Tests for digest filter + window resolution.

Covers:
- ``resolve_window`` for each of the nine WindowKind values.
- ``since_last_sent`` first-fire fallback to 24h.
- ``resolve_provider_query`` advanced-vs-structured branching.
- ``resolve_provider_query`` folder selection: bare / wildcard /
  multi-folder all map to a usable ``MailFilter.folder``.
- ``row_matches_filter`` for each dimension: categories
  (incl. UNCLASSIFIED + wildcard), tags (AND), list_id substring,
  has_attachment, actions (AND).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest


from email_triage.actions.digest_configs import (  # noqa: E402
    DigestConfig, DigestFilter, DigestWindow,
)
from email_triage.actions.digest_filter import (  # noqa: E402
    resolve_provider_query,
    resolve_window,
    row_matches_filter,
)


_NOW_UTC = datetime(2026, 5, 5, 16, 30, tzinfo=timezone.utc)
_NOW_LOCAL_TZ = "America/New_York"  # UTC-4 EDT in May


# ---------------------------------------------------------------------------
# resolve_window
# ---------------------------------------------------------------------------


def test_window_rolling_24h():
    s, e = resolve_window(
        DigestWindow(kind="rolling_24h"), now=_NOW_UTC,
    )
    assert datetime.fromisoformat(s) == _NOW_UTC - timedelta(hours=24)
    assert datetime.fromisoformat(e) == _NOW_UTC


def test_window_today_uses_local_midnight():
    """today = local midnight to now. EDT midnight UTC = 04:00 UTC."""
    s, e = resolve_window(
        DigestWindow(kind="today"), now=_NOW_UTC, tz=_NOW_LOCAL_TZ,
    )
    midnight_local = datetime(
        2026, 5, 5, 0, 0, tzinfo=ZoneInfo(_NOW_LOCAL_TZ),
    )
    assert datetime.fromisoformat(s) == midnight_local.astimezone(timezone.utc)


def test_window_yesterday_is_full_local_day():
    s, e = resolve_window(
        DigestWindow(kind="yesterday"), now=_NOW_UTC, tz=_NOW_LOCAL_TZ,
    )
    midnight_local = datetime(
        2026, 5, 5, 0, 0, tzinfo=ZoneInfo(_NOW_LOCAL_TZ),
    )
    yesterday_local = midnight_local - timedelta(days=1)
    assert datetime.fromisoformat(s) == yesterday_local.astimezone(timezone.utc)
    assert datetime.fromisoformat(e) == midnight_local.astimezone(timezone.utc)


def test_window_last_7d():
    s, e = resolve_window(
        DigestWindow(kind="last_7d"), now=_NOW_UTC,
    )
    assert datetime.fromisoformat(s) == _NOW_UTC - timedelta(days=7)


def test_window_this_week_starts_monday():
    """2026-05-05 is a Tuesday → start = Monday 2026-05-04 local."""
    s, _ = resolve_window(
        DigestWindow(kind="this_week"), now=_NOW_UTC, tz=_NOW_LOCAL_TZ,
    )
    monday_local = datetime(
        2026, 5, 4, 0, 0, tzinfo=ZoneInfo(_NOW_LOCAL_TZ),
    )
    assert datetime.fromisoformat(s) == monday_local.astimezone(timezone.utc)


def test_window_last_30d():
    s, _ = resolve_window(
        DigestWindow(kind="last_30d"), now=_NOW_UTC,
    )
    assert datetime.fromisoformat(s) == _NOW_UTC - timedelta(days=30)


def test_window_this_month_starts_at_local_first():
    s, _ = resolve_window(
        DigestWindow(kind="this_month"), now=_NOW_UTC, tz=_NOW_LOCAL_TZ,
    )
    first_local = datetime(
        2026, 5, 1, 0, 0, tzinfo=ZoneInfo(_NOW_LOCAL_TZ),
    )
    assert datetime.fromisoformat(s) == first_local.astimezone(timezone.utc)


def test_window_custom_uses_supplied_iso():
    w = DigestWindow(
        kind="custom",
        custom_start_iso="2026-04-01T00:00:00+00:00",
        custom_end_iso="2026-04-15T00:00:00+00:00",
    )
    s, e = resolve_window(w, now=_NOW_UTC)
    assert datetime.fromisoformat(s) == datetime(2026, 4, 1, tzinfo=timezone.utc)
    assert datetime.fromisoformat(e) == datetime(2026, 4, 15, tzinfo=timezone.utc)


def test_window_since_last_sent_uses_state():
    """Reads the per-digest send-state ts and starts there."""
    last = "2026-05-04T10:00:00+00:00"
    s, e = resolve_window(
        DigestWindow(kind="since_last_sent"),
        now=_NOW_UTC, last_sent_iso=last,
    )
    assert datetime.fromisoformat(s) == datetime(
        2026, 5, 4, 10, 0, tzinfo=timezone.utc,
    )


def test_window_since_last_sent_first_fire_falls_back_to_24h():
    """No prior send → don't return an empty digest. Treat as 24h."""
    s, e = resolve_window(
        DigestWindow(kind="since_last_sent"),
        now=_NOW_UTC, last_sent_iso=None,
    )
    assert datetime.fromisoformat(s) == _NOW_UTC - timedelta(hours=24)


def test_window_unknown_kind_degrades_to_24h():
    s, _ = resolve_window(
        DigestWindow(kind="totally-made-up"), now=_NOW_UTC,
    )
    assert datetime.fromisoformat(s) == _NOW_UTC - timedelta(hours=24)


# ---------------------------------------------------------------------------
# resolve_provider_query
# ---------------------------------------------------------------------------


def test_resolve_provider_query_structured_only():
    """Empty advanced field → MailFilter populated with the
    provider-friendly dimensions (folder / read_state / from /
    subject / time window). raw_query is ''."""
    cfg = DigestConfig(
        kind="custom", name="x",
        filter=DigestFilter(
            read_state="unread",
            folders=["INBOX"],
            from_addr="boss@example.com",
            subject="invoice",
        ),
    )
    mfilter, raw = resolve_provider_query(
        cfg, since_iso="2026-05-01T00:00:00+00:00",
    )
    assert raw == ""
    assert mfilter.unread is True
    assert mfilter.folder == "INBOX"
    assert mfilter.from_addr == "boss@example.com"
    assert mfilter.subject == "invoice"
    assert mfilter.after == datetime(2026, 5, 1, tzinfo=timezone.utc)


def test_resolve_provider_query_advanced_takes_over():
    """Non-empty advanced → raw_query carries it; structured
    from/subject are NOT mirrored into MailFilter (operator
    explicitly opted into raw control)."""
    cfg = DigestConfig(
        kind="custom", name="x",
        filter=DigestFilter(
            advanced='KEYWORD $EmailTriaged FROM "x@y"',
            from_addr="ignored@example.com",
            subject="ignored",
        ),
    )
    mfilter, raw = resolve_provider_query(
        cfg, since_iso="2026-05-01T00:00:00+00:00",
    )
    assert raw == 'KEYWORD $EmailTriaged FROM "x@y"'
    # Structured from/subject are NOT mirrored.
    assert mfilter.from_addr is None
    assert mfilter.subject is None
    # Time window still wraps.
    assert mfilter.after == datetime(2026, 5, 1, tzinfo=timezone.utc)


def test_resolve_provider_query_wildcard_folder():
    cfg = DigestConfig(
        kind="custom", name="x",
        filter=DigestFilter(folders=["*"]),
    )
    mfilter, _ = resolve_provider_query(cfg, since_iso="")
    assert mfilter.folder == "*"


def test_resolve_provider_query_multi_folder_uses_wildcard():
    """Multi-folder without the explicit wildcard maps to '*' so
    the cross-folder backend handles fanout; row_matches_filter
    is intentionally NOT used to narrow folders (folder isn't on
    the triage_runs entry)."""
    cfg = DigestConfig(
        kind="custom", name="x",
        filter=DigestFilter(folders=["INBOX", "Newsletters"]),
    )
    mfilter, _ = resolve_provider_query(cfg, since_iso="")
    assert mfilter.folder == "*"


# ---------------------------------------------------------------------------
# row_matches_filter
# ---------------------------------------------------------------------------


def _entry(**kw):
    base = {
        "message_id": "1",
        "category": "newsletter",
        "labels": [],
        "actions": [],
        "attachments": [],
        "headers": {},
    }
    base.update(kw)
    return base


def test_row_passes_when_filter_is_empty():
    assert row_matches_filter(_entry(), DigestFilter()) is True


def test_row_categories_match():
    f = DigestFilter(categories=["newsletter", "ai-news"])
    assert row_matches_filter(_entry(category="newsletter"), f) is True
    assert row_matches_filter(_entry(category="ai-news"), f) is True
    assert row_matches_filter(_entry(category="bills"), f) is False


def test_row_categories_unclassified():
    f = DigestFilter(categories=["UNCLASSIFIED"])
    assert row_matches_filter(_entry(category=""), f) is True
    assert row_matches_filter(_entry(category="newsletter"), f) is False


def test_row_categories_wildcard_passes_any_classified():
    f = DigestFilter(categories=["*"])
    assert row_matches_filter(_entry(category="anything"), f) is True
    # Empty cat should NOT pass wildcard — wildcard means "any
    # classified", UNCLASSIFIED is its own bucket.
    assert row_matches_filter(_entry(category=""), f) is False


def test_row_tags_must_all_match():
    f = DigestFilter(tags=["$EmailTriaged", "$Important"])
    e = _entry(labels=["$EmailTriaged", "$Important", "$Recent"])
    assert row_matches_filter(e, f) is True
    e2 = _entry(labels=["$EmailTriaged"])  # missing $Important
    assert row_matches_filter(e2, f) is False


def test_row_list_id_substring_match():
    f = DigestFilter(list_id="ai.example.com")
    e = _entry(headers={"List-Id": "<ai-news.ai.example.com>"})
    assert row_matches_filter(e, f) is True
    e2 = _entry(headers={"List-Id": "<other.example.com>"})
    assert row_matches_filter(e2, f) is False


def test_row_has_attachment():
    f_yes = DigestFilter(has_attachment=True)
    f_no = DigestFilter(has_attachment=False)
    with_att = _entry(attachments=[{"filename": "x.ics"}])
    without = _entry(attachments=[])
    assert row_matches_filter(with_att, f_yes) is True
    assert row_matches_filter(with_att, f_no) is False
    assert row_matches_filter(without, f_yes) is False
    assert row_matches_filter(without, f_no) is True


def test_row_actions_must_all_be_present():
    f = DigestFilter(actions=["moved", "labeled"])
    e_both = _entry(actions=["moved", "labeled", "drafted"])
    e_one = _entry(actions=["moved"])
    assert row_matches_filter(e_both, f) is True
    assert row_matches_filter(e_one, f) is False


# ---------------------------------------------------------------------------
# digest_should_fire
# ---------------------------------------------------------------------------


from email_triage.actions.digest_configs import (  # noqa: E402
    DigestConfig, DigestSchedule,
)
from email_triage.actions.digest_filter import (  # noqa: E402
    digest_should_fire,
)


def _local(t):
    """Helper — wall-clock at the supplied HH:MM today, EDT for tests."""
    return datetime(
        2026, 5, 5,
        int(t.split(":")[0]), int(t.split(":")[1]),
        tzinfo=ZoneInfo("America/New_York"),
    )


def test_should_fire_disabled_returns_false():
    cfg = DigestConfig(
        kind="custom", name="x", enabled=False,
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
    )
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:10"),
    ) is False


def test_should_fire_time_match_required():
    cfg = DigestConfig(
        kind="custom", name="x",
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
    )
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:10"),
    ) is True
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:11"),
    ) is False


def test_should_fire_weekly_requires_weekday_match():
    """2026-05-05 is a Tuesday (weekday=1)."""
    cfg = DigestConfig(
        kind="custom", name="x",
        schedule=DigestSchedule(
            cadence="weekly", time_local="08:10",
            days_of_week=[0, 2, 4],  # Mon, Wed, Fri only
        ),
    )
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:10"),
    ) is False
    cfg.schedule.days_of_week = [0, 1, 2]  # include Tuesday
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:10"),
    ) is True


def test_should_fire_monthly_requires_first_of_month():
    cfg = DigestConfig(
        kind="custom", name="x",
        schedule=DigestSchedule(cadence="monthly", time_local="08:10"),
    )
    # 2026-05-05 is the 5th — should NOT fire.
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=_local("08:10"),
    ) is False
    # Force to the 1st by reaching directly.
    first = datetime(
        2026, 5, 1, 8, 10, tzinfo=ZoneInfo("America/New_York"),
    )
    assert digest_should_fire(
        cfg, last_sent_iso=None, now_local=first,
    ) is True


def test_should_fire_idempotence_window_blocks_resend():
    """A successful fire 30 minutes ago shouldn't re-fire on the
    next minute that lands in the same target time."""
    cfg = DigestConfig(
        kind="custom", name="x",
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
    )
    # 30 min ago — within the 23h refusal window.
    last = (
        _local("08:10") - timedelta(minutes=30)
    ).astimezone(timezone.utc).isoformat()
    assert digest_should_fire(
        cfg, last_sent_iso=last, now_local=_local("08:10"),
    ) is False


def test_should_fire_after_full_day_resends():
    cfg = DigestConfig(
        kind="custom", name="x",
        schedule=DigestSchedule(cadence="daily", time_local="08:10"),
    )
    # 24h ago — outside the 23h window.
    last = (
        _local("08:10") - timedelta(hours=24)
    ).astimezone(timezone.utc).isoformat()
    assert digest_should_fire(
        cfg, last_sent_iso=last, now_local=_local("08:10"),
    ) is True
