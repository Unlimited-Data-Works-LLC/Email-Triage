"""Punch 605: an update check that is ON but never ticks is reported.

Before the fix ``update_check_stale`` returned None for the record before any
attempt (``last_success_at`` None, 0 failures), so a checker that was turned
on and never ran (dead sweep task, stuck lease) was surfaced by neither arm:
``not_running`` fired only after at least one success.

Now the record carries an anchor for "no attempt expected before": ``armed_at``
(stamped at boot, outside the tick, when the check is ON and nothing has been
recorded), else ``last_off_at`` (the last tick that found the check OFF, so a
runtime enable is measured from then), else the process start. Empty record
older than STALE_AFTER_HOURS past the anchor -> ``not_running``.
"""
from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta, timezone

import pytest

from email_triage import update_check as uc

_URL = uc.DEFAULT_RELEASE_CHECK_URL
_NOW = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


def _ago(hours: float) -> str:
    return (_NOW - timedelta(hours=hours)).isoformat()


def _empty(**kw):
    h = {"last_success_at": None, "consecutive_failures": 0,
         "last_failure_at": None, "last_failure_kind": None,
         "last_failure_status": None}
    h.update(kw)
    return h


@pytest.mark.parametrize("health, reason", [
    (_empty(armed_at=_ago(uc.STALE_AFTER_HOURS + 1)), uc.STALE_REASON_NOT_RUNNING),
    (_empty(armed_at=_ago(uc.STALE_AFTER_HOURS - 1)), None),
    (_empty(last_off_at=_ago(uc.STALE_AFTER_HOURS + 1)), uc.STALE_REASON_NOT_RUNNING),
    (_empty(last_off_at=_ago(1)), None),                       # runtime enable, alive ticker
    # armed_at wins over an older last_off_at (enabled in YAML while down).
    (_empty(armed_at=_ago(1), last_off_at=_ago(72)), None),
    (_empty(armed_at="garbage"), uc.STALE_REASON_NOT_RUNNING),  # cannot prove freshness
    # An attempt recorded: the existing arms decide, the anchor is not read.
    (_empty(consecutive_failures=3, armed_at=_ago(500)), None),
])
def test_empty_record_is_measured_from_its_anchor(health, reason):
    got = uc.update_check_stale(health, _URL, now=_NOW)
    assert (got and got["reason"]) == reason
    if got:
        assert got["since"] is None   # renders "since the check was turned on"


def test_process_start_is_the_last_resort_anchor(monkeypatch):
    monkeypatch.setattr(uc, "_PROCESS_STARTED_AT", _NOW - timedelta(hours=uc.STALE_AFTER_HOURS + 1))
    assert uc.update_check_stale(_empty(), _URL, now=_NOW)["reason"] == uc.STALE_REASON_NOT_RUNNING
    monkeypatch.setattr(uc, "_PROCESS_STARTED_AT", _NOW - timedelta(hours=1))
    assert uc.update_check_stale(_empty(), _URL, now=_NOW) is None


def test_still_nothing_while_off():
    assert uc.update_check_stale(_empty(armed_at=_ago(500)), "", now=_NOW) is None


def test_arm_stamps_once_and_only_an_empty_record(db):
    uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=_ago(10))
    assert uc.load_check_health(db)["last_off_at"] == _ago(10)
    assert uc.load_check_health(db)["armed_at"] is None
    uc.arm_check_health(db, _URL, now_iso=_ago(5))
    uc.arm_check_health(db, _URL, now_iso=_ago(1))            # keeps the first stamp
    assert uc.load_check_health(db)["armed_at"] == _ago(5)
    uc.arm_check_health(db, "", now_iso=_ago(0))              # OFF: no-op
    assert uc.load_check_health(db)["armed_at"] == _ago(5)
    uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=_ago(0))
    assert uc.load_check_health(db)["armed_at"] is None       # OFF clears the arm
    uc.record_check_outcome(db, uc.OUTCOME_OK, now_iso=_ago(0))
    uc.arm_check_health(db, _URL, now_iso=_ago(0))
    assert uc.load_check_health(db)["armed_at"] is None       # attempt recorded: no stamp


def test_boot_path_arms_the_check():
    """The stamp must run outside the hourly tick (a dead ticker never runs
    record_check_outcome): the lifespan function that sets app.state.started_at
    also calls arm_check_health."""
    from email_triage.web import app as app_mod
    tree = ast.parse(inspect.getsource(app_mod))
    boot = [fn for fn in ast.walk(tree)
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))
            and "app.state.started_at" in ast.unparse(fn)
            and not any(isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and "app.state.started_at" in ast.unparse(c)
                        for c in ast.walk(fn) if c is not fn)]
    assert boot, "no function sets app.state.started_at: the probe is not in the set"
    assert any(isinstance(n, ast.Call) and ast.unparse(n.func).endswith("arm_check_health")
               for fn in boot for n in ast.walk(fn))


def test_never_ticked_check_renders_the_banner_and_the_daily_line(
    client, db, admin_cookies, app, strict_undefined_templates,
):
    from email_triage.config import TriageConfig
    from email_triage.web.daily_health import gather_health_state

    real_now = datetime.now(timezone.utc)
    old = (real_now - timedelta(hours=uc.STALE_AFTER_HOURS + 1)).isoformat()
    uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=real_now.isoformat())
    uc.arm_check_health(db, _URL, now_iso=old)
    try:
        page = client.get("/dashboard", cookies=admin_cookies)
        assert page.status_code == 200
        start = page.text.index('id="update-check-stale-banner"')
        banner = page.text[start:page.text.index("</aside>", start)]
        assert f'data-reason="{uc.STALE_REASON_NOT_RUNNING}"' in banner
        assert "The update check has stopped running" in banner
        assert "since the check was turned on" in banner
        assert "internet access" not in banner

        state = gather_health_state(db, TriageConfig(), app=app)
        assert state["update_check_stale"]["reason"] == uc.STALE_REASON_NOT_RUNNING
        assert any("stopped running" in r and "since it was turned on" in r
                   for r in state["attention_reasons"])
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=real_now.isoformat())


def test_freshly_armed_check_renders_no_banner(client, db, admin_cookies, app):
    real_now = datetime.now(timezone.utc).isoformat()
    uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=real_now)
    uc.arm_check_health(db, _URL, now_iso=real_now)
    try:
        page = client.get("/dashboard", cookies=admin_cookies)
        assert 'id="update-check-stale-banner"' not in page.text
    finally:
        uc.record_check_outcome(db, uc.OUTCOME_OFF, now_iso=real_now)
