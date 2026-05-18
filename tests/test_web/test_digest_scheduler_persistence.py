"""Tests for #141 — digest scheduler persistent + elapsed-window
correctness.

Covers the two bugs the new ``_digest_scheduler_tick`` design fixes:

1. **Restart-amnesia.** Old code tracked "already fired today" in a
   process-local ``set``. A restart between the schedule minute and
   end-of-day re-fired the digest. The replacement persists the
   "ran" flag in the ``settings`` table — survives a simulated
   restart (we drop and rebuild the only piece of in-memory state
   the scheduler held: the surrounding task itself).

2. **Precise-match miss.** Old code matched ``current_time ==
   sched_time``. A tick that ran past 60 s woke at HH:MM+1 and
   skipped the day silently. The replacement uses an elapsed
   window (``current_time >= sched_time``) so a slow tick still
   catches up.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.web.app import (
    _digest_scheduler_last_run_key,
    _digest_scheduler_tick,
)
from email_triage.web.db import get_setting, set_setting


def _mk_account(db, *, owner_id: int, name: str = "acct1") -> int:
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(name, provider_type, config_json, is_active, "
        " created_at, updated_at, user_id) "
        "VALUES (?, 'imap', ?, 1, ?, ?, ?)",
        (
            name,
            json.dumps({"username": "u@example.com", "host": "h", "port": 993}),
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00",
            owner_id,
        ),
    )
    db.commit()
    return cursor.lastrowid


def _add_daily_schedule(
    db, acct_id: int, *, time_utc: str, category: str = "newsletters",
) -> None:
    set_setting(db, f"digest_schedules:{acct_id}", [{
        "time_utc": time_utc,
        "category": category,
        "enabled": True,
        "cadence": "daily",
    }])


@pytest.fixture
def patched_run(monkeypatch):
    """Stub ``_run_scheduled_digest`` so the tick body is observable
    without exercising the IMAP / classifier setup."""
    stub = AsyncMock(return_value=None)
    monkeypatch.setattr(
        "email_triage.web.app._run_scheduled_digest", stub,
    )
    return stub


def test_persistent_last_run_survives_restart(
    app, db, regular_user, patched_run,
):
    """A restart between schedule-minute and end-of-day must NOT
    re-fire. With the in-memory set, dropping the local variable
    re-fired; with the persistent flag, the flag survives and the
    second tick is a no-op."""
    acct_id = _mk_account(db, owner_id=regular_user["id"])
    _add_daily_schedule(db, acct_id, time_utc="07:00")

    # Tick 1: at 07:00 — fires.
    fire_time = datetime(2026, 5, 9, 7, 0, 0, tzinfo=timezone.utc)
    fired1 = asyncio.run(_digest_scheduler_tick(app, fire_time))
    assert fired1 == [(acct_id, 0, "newsletters")]
    assert patched_run.await_count == 1

    # Verify the persisted flag is in place.
    key = _digest_scheduler_last_run_key(acct_id, 0, "2026-05-09")
    assert get_setting(db, key) is not None

    # Simulated process restart: drop in-process state. Persistent
    # flag is the only protection between the same minute and the
    # next tick.
    patched_run.reset_mock()

    # Tick 2 (post-restart): same minute, same day. Must NOT re-fire.
    fired2 = asyncio.run(_digest_scheduler_tick(app, fire_time))
    assert fired2 == [], "restart must not re-fire the same-day digest"
    assert patched_run.await_count == 0


def test_slow_tick_still_catches_up(app, db, regular_user, patched_run):
    """If the prior tick took >60 s and we wake at HH:MM+N (N>=1),
    the elapsed-window match still fires that day's digest."""
    acct_id = _mk_account(db, owner_id=regular_user["id"])
    _add_daily_schedule(db, acct_id, time_utc="07:00")

    # Pretend the previous tick's body took 90 s; we wake at 07:01:30.
    # Old code: current_time == sched_time fails ("07:01" != "07:00")
    # → skip the day. New code: "07:01" >= "07:00" → fires.
    late = datetime(2026, 5, 9, 7, 1, 30, tzinfo=timezone.utc)
    fired = asyncio.run(_digest_scheduler_tick(app, late))
    assert fired == [(acct_id, 0, "newsletters")]
    assert patched_run.await_count == 1


def test_pre_schedule_does_not_fire(app, db, regular_user, patched_run):
    """Before the schedule time, no fire (the elapsed window only
    opens at HH:MM)."""
    acct_id = _mk_account(db, owner_id=regular_user["id"])
    _add_daily_schedule(db, acct_id, time_utc="07:00")

    early = datetime(2026, 5, 9, 6, 59, 0, tzinfo=timezone.utc)
    fired = asyncio.run(_digest_scheduler_tick(app, early))
    assert fired == []
    assert patched_run.await_count == 0


def test_two_ticks_same_day_only_one_fire(
    app, db, regular_user, patched_run,
):
    """Multiple ticks within the elapsed window on the same day
    must yield exactly one fire (idempotency check)."""
    acct_id = _mk_account(db, owner_id=regular_user["id"])
    _add_daily_schedule(db, acct_id, time_utc="07:00")

    t1 = datetime(2026, 5, 9, 7, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 5, 9, 7, 5, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 5, 9, 23, 59, 0, tzinfo=timezone.utc)
    fired = []
    for t in (t1, t2, t3):
        fired.extend(asyncio.run(_digest_scheduler_tick(app, t)))
    assert fired == [(acct_id, 0, "newsletters")]


def test_next_day_fires_again(app, db, regular_user, patched_run):
    """The dedup flag is per-day. Tomorrow's tick fires again."""
    acct_id = _mk_account(db, owner_id=regular_user["id"])
    _add_daily_schedule(db, acct_id, time_utc="07:00")

    today = datetime(2026, 5, 9, 7, 0, 0, tzinfo=timezone.utc)
    tomorrow = datetime(2026, 5, 10, 7, 0, 0, tzinfo=timezone.utc)
    fired_today = asyncio.run(_digest_scheduler_tick(app, today))
    fired_tomorrow = asyncio.run(_digest_scheduler_tick(app, tomorrow))
    assert fired_today == [(acct_id, 0, "newsletters")]
    assert fired_tomorrow == [(acct_id, 0, "newsletters")]
    assert patched_run.await_count == 2
