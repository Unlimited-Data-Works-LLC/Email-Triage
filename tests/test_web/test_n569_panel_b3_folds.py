"""Punch 569, SME panel B3 folds (2026-10-07): one arm per fold, each with teeth.

Finding ids: hipaa F1/F2b/F3, db F569-1/-2/-4/-5, DA F569-2/-4/-8 (the panel files
are panel-b3-{hipaa,db,da}.md). The tripwire (hipaa F2 / db F569-3 / DA F569-1)
lives in ``tests/test_n569_manifest_set_history_pin.py``.
"""

from __future__ import annotations

import json
import sys
from unittest.mock import patch

import pytest
from _db_tracking import track

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web.admin_alerts import EMBEDDING_RUNTIME_UPDATE_EVENT, fire_on_transition
from email_triage.web.auth import SESSION_COOKIE_NAME
from _portal_loop import _one_portal_loop

ROUTE = "/config/ai-backends/embedding-update"


def _wait_for_failure_row(db, timeout: float = 10.0) -> None:
    """The background update's failure row is the liveness signal (punch 577)."""
    import time

    from email_triage.web.db_writelock import get_write_lock

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with get_write_lock():
            if _update_rows(db, "failure"):
                return
        time.sleep(0.02)
    raise AssertionError(f"no failure row within {timeout}s")


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    # The punch-569 CLICK notices: embedding.auto_update OFF (the automatic
    # wording is tests/test_web/test_autoupd_notices.py).
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


def _update_rows(db, outcome=None):
    sql = "SELECT outcome, detail FROM auth_events WHERE event_type = 'embedding_runtime_update'"
    if outcome:
        sql += f" AND outcome = '{outcome}'"
    return [tuple(r) for r in db.execute(sql + " ORDER BY id").fetchall()]


# ---------------------------------------------------------------------------
# A. hipaa F1 / DA F569-3: boot recovery is written to the audit chain
# ---------------------------------------------------------------------------

def _boot(tmp_path, monkeypatch, *, prev: bool, row_status: str | None = None):
    from fastapi.testclient import TestClient

    from email_triage import secrets as _secrets_mod
    from email_triage.config import TriageConfig
    from email_triage.web.app import create_app
    from email_triage.web.db import init_db

    db_path = tmp_path / "triage.db"
    conn = track(init_db(str(db_path)))
    if row_status:
        eb._update_state(conn, status=row_status)
        conn.commit()
    conn.close()
    prefix, _site, _m = make_verified_prefix(tmp_path, monkeypatch)
    if prev:
        eb.previous_prefix(prefix).mkdir()  # a crash after the swap left .prev
    config = TriageConfig()
    config.persistence.db_path = str(db_path)
    config.persistence.encryption_enabled = False

    class _StubSecrets:
        def __init__(self):
            self._s: dict[str, str] = {}
        def get(self, k): return self._s.get(k)
        def set(self, k, v): self._s[k] = v
        def list_keys(self): return list(self._s.keys())

    with patch.object(
        _secrets_mod, "bootstrap_secrets_from_config",
        lambda conn, cfg, *, master_key=None: _StubSecrets(),
    ):
        with TestClient(create_app(config)):
            pass
    return track(init_db(str(db_path))), prefix


def test_boot_recovery_writes_one_audit_row(tmp_path, monkeypatch):
    conn, prefix = _boot(tmp_path, monkeypatch, prev=True)
    rows = _update_rows(conn)
    assert len(rows) == 1, rows
    outcome, detail = rows[0]
    assert outcome == "success"
    assert detail.startswith("boot recovery: ")
    assert "retired the previous set" in detail
    # Operator ruling R5 (2026-10-25): a named system actor, never blank.
    from email_triage.web.embedding_update_runner import BOOT_RECOVERY_ACTOR_EMAIL
    actors = [r[0] for r in conn.execute(
        "SELECT email FROM auth_events WHERE event_type = 'embedding_runtime_update'"
    ).fetchall()]
    assert actors == [BOOT_RECOVERY_ACTOR_EMAIL]
    assert not eb.previous_prefix(prefix).exists() or eb.removal_tombstones(prefix)


def test_a_clean_boot_writes_no_recovery_row(tmp_path, monkeypatch):
    conn, _prefix = _boot(tmp_path, monkeypatch, prev=False)
    assert _update_rows(conn) == []


# ---------------------------------------------------------------------------
# B. db F569-1: the in-flight row is released on every exit
# ---------------------------------------------------------------------------

def test_boot_releases_a_row_a_stopped_process_left_in_flight(tmp_path, monkeypatch):
    conn, _prefix = _boot(tmp_path, monkeypatch, prev=False, row_status="downloading")
    state = eb.get_install_status(conn)
    assert state["status"] == "failed"
    assert state["last_error_class"] == "Interrupted"
    (outcome, detail), = _update_rows(conn)
    assert outcome == "success" and "left downloading" in detail


def test_reconcile_points_a_staging_path_back_at_the_live_prefix(db, tmp_path, monkeypatch):
    """DA F569-8: after a crash the row may name ``<prefix>.next``."""
    prefix, _site, _m = make_verified_prefix(tmp_path, monkeypatch)
    eb._update_state(db, status="installed",
                     runtime_deps_path=str(eb.staging_prefix(prefix)))
    done = eb.reconcile_interrupted_install_row(db)
    assert "staging prefix" in done
    state = eb.get_install_status(db)
    assert state["runtime_deps_path"] == str(prefix)
    assert state["status"] == "installed"  # not in flight: status untouched
    assert eb.reconcile_interrupted_install_row(db) == ""  # idempotent


def test_an_update_task_that_raises_releases_the_row(
    app, client, db, admin_cookies, monkeypatch, tmp_path,
):
    from email_triage.web import embedding_update_runner as ei

    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "rdeps"))

    def boom(**_kw):
        raise RuntimeError("disk vanished")

    monkeypatch.setattr(ei, "update_runtime", boom)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    with _one_portal_loop(client):
        client.post(ROUTE, headers={"HX-Request": "true"})
        _wait_for_failure_row(db)
    state = eb.get_install_status(db)
    assert state["status"] == "failed", state
    assert state["last_error_class"] == "RuntimeError"
    assert state["status"] not in eb._IN_FLIGHT_STATUSES  # the next click is not refused


# ---------------------------------------------------------------------------
# F. db F569-2 (mutant MB): the update route's own lock guard
# ---------------------------------------------------------------------------

def test_an_update_in_flight_refuses_the_update_route(client, db, admin_cookies, monkeypatch, tmp_path):
    from email_triage.web import embedding_update_runner as ei

    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "rdeps"))
    entered: list[bool] = []
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: entered.append(True))
    before = eb.get_install_status(db)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    assert eb._update_lock.acquire(blocking=False)
    try:
        resp = client.post(ROUTE, headers={"HX-Request": "true"})
    finally:
        eb._update_lock.release()
    assert not entered
    assert "already in progress" in " ".join(resp.text.split())
    assert any("already in flight" in d for _o, d in _update_rows(db, "failure"))
    after = eb.get_install_status(db)
    for col in ("status", "attempt_count", "progress_files_done"):
        if col in before:
            assert after[col] == before[col], col


# ---------------------------------------------------------------------------
# G. db F569-4 / DA F569-6: a marker set_version below 1 refuses
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [0, -1])
def test_a_set_version_below_one_refuses(tmp_path, monkeypatch, bad):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    assert eb.runtime_status().state == eb.STATE_STALE_OK  # control arm
    marker["set_version"] = bad
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    st = eb.runtime_status()
    assert st.state == eb.STATE_REFUSED and st.reason_token == "set_mismatch"


# ---------------------------------------------------------------------------
# H. hipaa F3 / DA F569-7: a sideload update's INTENT row names the bundle
# ---------------------------------------------------------------------------

def test_a_sideload_update_records_its_source_dir(client, db, admin_cookies, monkeypatch, tmp_path):
    from email_triage.web import embedding_update_runner as ei

    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "rdeps"))
    # The background update is not this arm's subject (the INTENT row is
    # written in the request hop); make it a no-op rather than shim asyncio.
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: eb.UpdateResult(
        status="failed", error_class="NotUnderTest",
    ))
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    client.post(ROUTE, data={"source_dir": str(bundle)}, headers={"HX-Request": "true"})
    (outcome, detail), = _update_rows(db, "attempt")
    assert "method=sideload" in detail and f"source_dir={bundle}" in detail


# ---------------------------------------------------------------------------
# I. db F569-5: a precomputed section is used, not rescanned under the lock
# ---------------------------------------------------------------------------

def test_a_precomputed_runtime_section_is_not_rescanned(db, monkeypatch):
    from email_triage.config import TriageConfig
    from email_triage.web import daily_health as dh

    calls: list[bool] = []
    monkeypatch.setattr(dh, "gather_embedding_runtime_section",
                        lambda cfg: calls.append(True) or None)
    sentinel = {"headline": "x", "consequence": "y", "kind": "update"}
    state = dh.gather_health_state(db, TriageConfig(), embedding_runtime_section=sentinel)
    assert state["embedding_runtime"] is sentinel and calls == []
    dh.gather_health_state(db, TriageConfig())  # default: computed here
    assert calls == [True]


# ---------------------------------------------------------------------------
# K. DA F569-4: no probe (and so no false-alarm email) while an update runs
# ---------------------------------------------------------------------------

async def test_no_alert_probe_while_an_update_runs(db, tmp_path, monkeypatch):
    from email_triage.web.db import delete_setting

    make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    evt = EMBEDDING_RUNTIME_UPDATE_EVENT
    delete_setting(db, admin_alerts._settings_key(evt.key))

    class _Cfg:
        class push:
            public_url = ""

    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert eb._update_lock.acquire(blocking=False)
        try:
            assert await fire_on_transition(evt, _Cfg(), db) == "noop"
        finally:
            eb._update_lock.release()
        assert send.call_count == 0
        assert await fire_on_transition(evt, _Cfg(), db) == "sent"  # control arm


# ---------------------------------------------------------------------------
# D. hipaa F2b: the email states the release-time flag, not "no problem"
# ---------------------------------------------------------------------------

def test_the_email_says_not_marked_rather_than_no(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    active, ctx = admin_alerts._embedding_runtime_probe()
    assert active
    _html, text = admin_alerts._assemble_embedding_runtime_alert(ctx)
    assert "Security:  no (not marked as a security fix at release)" in text


# ---------------------------------------------------------------------------
# E. DA F569-2: the pause is disclosed BEFORE the click
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("loaded", [True, False])
def test_the_pause_is_disclosed_before_the_click(
    client, db, admin_cookies, strict_undefined_templates, tmp_path, monkeypatch, loaded,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    monkeypatch.setattr(eb, "_modules_loaded_from", lambda p: ["torch"] if loaded else [])
    monkeypatch.setattr(eb, "runtime_status_memo", eb.runtime_status)
    banner = client.get("/config?tab=general", cookies=admin_cookies)
    card = client.get("/config/ai-backends/embedding-install-status", cookies=admin_cookies)
    for resp in (banner, card):
        assert resp.status_code == 200, resp.text[:400]
        flat = " ".join(resp.text.split())
        assert (eb.UPDATE_PAUSE_NOTE in flat) is loaded, resp.request.url
