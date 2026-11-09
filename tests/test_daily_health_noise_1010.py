"""Daily-health noise fixes (2026-10-10).

1. ``gather_health_state``: ERROR rows lead the error tail, so ten routine
   WARNINGs can no longer push every ERROR out of it.
2. ``_update_check_once``: the "no readable security marker" log is WARNING
   once per (latest_tag, meta_status) per process, INFO on repeats.
3. ``_compute_msal_master_key_status_block``: no WARNING when the first
   observation is "available"; WARNING on a first non-available observation
   and on a later recovery to "available".
"""

from __future__ import annotations
from _db_tracking import track

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI

from email_triage.config import TriageConfig
from email_triage.web.db import init_db


@pytest.fixture
def db():
    return track(init_db(":memory:"))


def _seed_log(db, *, level: str, message: str) -> None:
    from email_triage.web.db import insert_log_entry
    insert_log_entry(
        db,
        ts=datetime.now(timezone.utc).isoformat(),
        level=level,
        logger="test",
        message=message,
    )
    db.commit()


class _RecLog:
    def __init__(self):
        self.calls: list[tuple[str, str, dict]] = []

    def _rec(self, level):
        def _f(msg, *a, **k):
            self.calls.append((level, msg, k))
        return _f

    def __getattr__(self, name):
        if name in ("debug", "info", "warning", "error", "critical"):
            return self._rec(name)
        raise AttributeError(name)


# ---------------------------------------------------------------------------
# 1. ERROR rows survive a flood of newer WARNINGs in the tail
# ---------------------------------------------------------------------------

def test_error_tail_keeps_errors_older_than_ten_warnings(db, monkeypatch):
    from email_triage.web import daily_health as dh
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: None)

    _seed_log(db, level="ERROR", message="boom-1")
    _seed_log(db, level="ERROR", message="boom-2")
    for i in range(12):
        _seed_log(db, level="WARNING", message=f"routine-{i}")

    state = dh.gather_health_state(db, TriageConfig())

    assert state["error_count_24h"] == 2
    assert len(state["error_rows"]) == 10
    assert [r["level"] for r in state["error_rows"][:2]] == ["ERROR", "ERROR"]
    # Newest first within the ERROR group (db HN1 N1).
    assert [r["message"] for r in state["error_rows"][:2]] == ["boom-2", "boom-1"]
    assert state["warning_count_24h"] == 12


def test_error_tail_render_escapes_and_states_truncation(db, monkeypatch):
    # hipaa HN1 A2 + DA HN1 F2: the HTML tail escapes every field and both
    # renders say how much of the 24h log they show.
    from email_triage.web import daily_health as dh
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: None)
    _seed_log(db, level="ERROR", message="<script>x</script>")
    for i in range(11):
        _seed_log(db, level="WARNING", message=f"a<b {i}")
    cfg = TriageConfig()
    state = dh.gather_health_state(db, cfg)
    html, text = dh._render_html(state, cfg), dh._render_text(state, cfg)
    state_rows = len(state["error_rows"])
    assert state_rows == 10
    assert "<script>x" not in html and "&lt;script&gt;x" in html
    assert "a&lt;b" in html
    assert "showing 10 of 12 entries (1 error(s), 11 warning(s))" in html
    assert "showing 10 of 12 entries: 1 error(s), 11 warning(s)" in text


# ---------------------------------------------------------------------------
# 2. Update-check marker log: WARNING once per (tag, status), then INFO
# ---------------------------------------------------------------------------

_MARKER_MSG = "no readable security marker"
_BAD_MARKER = "<!-- email-triage-release-meta: {not json -->"
_OK_MARKER = '<!-- email-triage-release-meta: {"schema": 1, "security": false} -->'


def test_update_check_marker_warns_once_per_tag_and_status(monkeypatch):
    from email_triage import update_check as uc
    from email_triage.web import background_sweepers as bs
    from email_triage.web import daily_health as dh
    from email_triage.web import db_threadpool

    payload = {"tag_name": "v0.1.2", "html_url": "https://example.invalid/r",
               "body": "no marker here"}
    monkeypatch.setattr(dh, "fetch_latest_release", lambda url: dict(payload))
    monkeypatch.setattr(uc, "record_check_outcome", lambda *a, **k: None)
    monkeypatch.setattr(uc, "save_release_facts", lambda *a, **k: None)

    async def _direct(fn, *a, **k):
        return fn(*a, **k)

    monkeypatch.setattr(db_threadpool, "db_call", _direct)
    rec = _RecLog()
    monkeypatch.setattr(bs, "log", rec)

    app = FastAPI()
    cfg = TriageConfig()
    cfg.admin_email.release_check_url = "https://example.invalid/latest"
    app.state.config = cfg
    app.state.db = None
    app.state.update_check_facts = None

    def _tick():
        rec.calls.clear()
        assert asyncio.run(bs._update_check_once(app)) == "ok"
        return [lvl for lvl, msg, _ in rec.calls if _MARKER_MSG in msg]

    # Not newer than the running version (prod 2026-10-10: v0.1.2 vs 0.2.0):
    # the marker cannot matter, so never a WARNING (DA HN1 F1).
    assert _tick() == ["info"]
    assert _tick() == ["info"]
    # A newer release with no readable marker is treated as a security update:
    # WARNING once per (tag, status), INFO on repeats.
    payload["tag_name"] = "v99.0.0"
    assert _tick() == ["warning"]          # first sighting
    assert _tick() == ["info"]             # same tag + status: demoted
    payload["tag_name"] = "v99.0.1"
    assert _tick() == ["warning"]          # new release
    assert _tick() == ["info"]
    payload["body"] = _BAD_MARKER
    assert app.state.update_check_facts.meta_status == uc.META_ABSENT
    assert _tick() == ["warning"]          # same tag, new status
    assert app.state.update_check_facts.meta_status == uc.META_UNPARSEABLE
    assert _tick() == ["info"]
    # A marker that reads again re-arms the warning (db HN1 F1 / hipaa A1).
    payload["body"] = _OK_MARKER
    assert _tick() == []
    assert app.state.update_check_facts.meta_status == uc.META_OK
    payload["body"] = _BAD_MARKER
    assert _tick() == ["warning"]


# ---------------------------------------------------------------------------
# 3. msal master-key status: a healthy first observation is not a transition
# ---------------------------------------------------------------------------

def test_msal_master_key_first_available_is_silent_but_recovery_warns(
    monkeypatch,
):
    from email_triage.providers import _msal_cache_crypto as _mkc
    from email_triage.web.routers import health as health_mod

    gate = {"state": (False, "available")}
    monkeypatch.setattr(_mkc, "n151_soft_gate_state", lambda: gate["state"])
    warned: list[dict] = []
    monkeypatch.setattr(
        health_mod.logger, "warning",
        lambda msg, *a, **k: warned.append(k.get("extra") or {}),
    )

    def _probe(request):
        return health_mod._compute_msal_master_key_status_block(request)

    # Healthy first observation after boot: no WARNING.
    healthy = SimpleNamespace(app=FastAPI())
    assert _probe(healthy)["reason"] == "available"
    assert warned == []
    assert _probe(healthy)["reason"] == "available"
    assert warned == []

    # Non-available first observation: WARNING with no prior reason.
    degraded = SimpleNamespace(app=FastAPI())
    gate["state"] = (True, "unavailable")
    assert _probe(degraded)["reason"] == "unavailable"
    assert [(w["reason"], w["prev_reason"]) for w in warned] == [
        ("unavailable", None),
    ]

    # Recovery to "available" still warns.
    gate["state"] = (False, "available")
    assert _probe(degraded)["reason"] == "available"
    assert [(w["reason"], w["prev_reason"]) for w in warned] == [
        ("unavailable", None), ("available", "unavailable"),
    ]

    # A later degrade on the healthy-first process warns too.
    gate["state"] = (True, "unavailable")
    _probe(healthy)
    assert warned[-1]["reason"] == "unavailable"
    assert warned[-1]["prev_reason"] == "available"
