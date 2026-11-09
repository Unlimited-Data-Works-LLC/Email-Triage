"""hipaa-sme R3 (2026-10-25): integrity refusals are never auto-healed.

A prefix that no longer matches its own record (``disk_marker_mismatch``,
``duplicate_versions``), whose record is unreadable (``marker_invalid``), or whose
image manifest is unreadable (``manifest_unreadable``) is possible tamper evidence
(§164.312(c)(1)). The automatic updater must not overwrite it as a routine update,
and that has to hold EVEN WHEN the image's manifest has moved past the install,
which is the normal case every few days (MUST-R3-1: before the reorder, drift was
classified first and a tampered prefix read ``security_drift``).

Each test plants the tamper in an install whose image manifest is a SECURITY change
(or whose record would classify as ``set_mismatch``), runs the real trigger with the
real status funnel, and checks what the tooth names: the integrity token, no INTENT
row, ``update_runtime`` never entered, the URGENT alert, the bytes unchanged. The
control arms show the same install WITHOUT the tamper IS auto-updated, so the
integrity refusal is the only difference.
"""

from __future__ import annotations

import hashlib
import html as _html
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from _embedding_runtime_fixture import make_versioned_prefix
from _pin_harness import iter_files, relpath

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web import embedding_update_runner as ru
from email_triage.web.admin_alerts import (
    EMBEDDING_RUNTIME_INTEGRITY_EVENT,
    EMBEDDING_RUNTIME_UPDATE_EVENT,
    _settings_key,
    fire_on_transition,
)
from email_triage.web.db import delete_setting

TOKENS = ("disk_marker_mismatch", "duplicate_versions", "marker_invalid", "manifest_unreadable")


class _Cfg:
    class push:
        public_url = "https://triage.example.test/"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(eb, "_auto_deferred", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


@pytest.fixture
def fake_app(db):
    return SimpleNamespace(state=SimpleNamespace(db=db))


def _rows(db):
    return [
        tuple(r) for r in db.execute(
            "SELECT outcome, detail, email FROM auth_events "
            "WHERE event_type = 'embedding_runtime_update' ORDER BY id"
        ).fetchall()
    ]


def _tree_digest(root: Path) -> str:
    h = hashlib.sha256()
    for p in iter_files(root, "*"):  # the shared walker (R5b), not a hand-rolled rglob
        h.update(relpath(p, root).encode())
        if p.is_file():
            h.update(p.read_bytes())
    return h.hexdigest()


def _dist_info(site: Path, name: str, version: str) -> Path:
    d = site / f"{name.replace('-', '_')}-{version}.dist-info"
    d.mkdir(exist_ok=True)
    (d / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8",
    )
    return d


def _tamper(token: str, prefix: Path, site: Path, mpath: Path) -> None:
    if token == "disk_marker_mismatch":
        _dist_info(site, "planted-pkg", "6.6.6")  # a distribution the record never named
    elif token == "duplicate_versions":
        _dist_info(site, "fake-a", "9.9")  # a second version of a recorded name
    elif token == "marker_invalid":
        eb.installed_marker_path(prefix).unlink()
    elif token == "manifest_unreadable":
        mpath.write_text("{ not json", encoding="utf-8")
    else:  # pragma: no cover
        raise AssertionError(token)


def _security_install(tmp_path, monkeypatch):
    return make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0569",),
    )


class _Update:
    def __init__(self, retired=()):
        self.calls = 0
        self.retired = list(retired)

    def __call__(self, **kw):
        self.calls += 1
        eb._update_state(kw["conn"], status="installed", current_file=None, clear_error=True)
        return eb.UpdateResult(
            status="updated", from_set_version=1, to_set_version=2, retired=self.retired,
        )


# ---------------------------------------------------------------------------
# MUST-R3-1: the tooth
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", TOKENS)
async def test_a_tampered_prefix_under_a_moved_manifest_reports_its_integrity_token_and_is_left_alone(
    db, fake_app, tmp_path, monkeypatch, token,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    # Control: untampered, the manifest move is an ordinary security drift.
    assert eb.runtime_status().reason_token == "security_drift"
    _tamper(token, prefix, site, mpath)
    before = _tree_digest(prefix)
    status = eb.runtime_status()
    assert status.reason_token == token, status.reason
    assert status.integrity_refusal and not status.auto_updatable
    assert status.state == eb.STATE_REFUSED and not status.serving

    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    install_row = eb.get_install_status(db)["status"]
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert update.calls == 0, "the updater entered update_runtime over a tampered prefix"
    # No INTENT row (the updater did not claim the prefix); the ONE row is the durable
    # record of the DETECTION (hipaa-sme MUST-1, §164.308(a)(6)(ii)).
    rows = _rows(db)
    assert [r[0] for r in rows] == ["denied:integrity"], rows
    assert rows[0][2] == ru.SYSTEM_ACTOR_EMAIL and token in rows[0][1]
    assert eb.get_install_status(db)["status"] == install_row
    assert _tree_digest(prefix) == before, "the prefix bytes changed"
    assert eb.auto_update_failure() is None  # not a failed update: nothing was tried


@pytest.mark.parametrize("token", TOKENS)
async def test_the_detection_row_is_written_once_per_token_per_process_and_again_after_a_restart(
    db, fake_app, tmp_path, monkeypatch, token,
):
    """hipaa-sme MUST-1 tooth (fold 2): a refusal no admin ever clicks still leaves ONE
    chained row per token per process: none on a repeat tick, one more after a restart."""
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper(token, prefix, site, mpath)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert [r[0] for r in _rows(db)] == ["denied:integrity"]
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert [r[0] for r in _rows(db)] == ["denied:integrity"], "a repeat tick wrote a second row"
    restarted = SimpleNamespace(state=SimpleNamespace(db=db))  # a new process: no memory
    assert await ru.auto_update_once(restarted) == "integrity"
    rows = _rows(db)
    assert [r[0] for r in rows] == ["denied:integrity"] * 2
    assert all(r[2] == ru.SYSTEM_ACTOR_EMAIL and token in r[1] for r in rows)
    assert update.calls == 0


@pytest.mark.audit_failure_expected(
    match="outcome=denied:integrity", count=1,
    reason="the refused detection write is the point of the test",
)
async def test_a_detection_row_that_could_not_be_written_is_retried_on_the_next_tick(
    db, fake_app, tmp_path, monkeypatch,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    real = ru.record_auth_event
    fail = {"left": 1}

    def flaky(*a, **kw):
        if fail["left"]:
            fail["left"] -= 1
            raise sqlite3.OperationalError("database is locked")
        return real(*a, **kw)

    monkeypatch.setattr(ru, "record_auth_event", flaky)
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert _rows(db) == [], "the refused write left a row"
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert [r[0] for r in _rows(db)] == ["denied:integrity"]  # retried, then once
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert len(_rows(db)) == 1


@pytest.mark.parametrize(
    ("security", "control_token"),
    [(True, "security_drift"), (False, "set_mismatch")],
    ids=["security-manifest", "non-security-manifest"],
)
async def test_an_unplaced_record_with_a_planted_distribution_is_still_an_integrity_refusal(
    db, fake_app, tmp_path, monkeypatch, security, control_token,
):
    """The twin for an unplaced record: a schema-1 record cannot say which set it is
    (drift cannot place it; punch 664: on a manifest whose later step is a security
    fix that is ``security_drift``, otherwise ``set_mismatch``), and the planted
    distribution must still win. Both manifests are pinned, so the non-security
    ``set_mismatch`` arm keeps its own coverage (DA S3)."""
    prefix, site, mpath = make_versioned_prefix(
        tmp_path, monkeypatch, steps=(security,),
        advisories=("CVE-2099-0569",) if security else (),
    )
    marker_path = eb.installed_marker_path(prefix)
    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    marker["schema"] = 1
    marker.pop("record_digests", None)
    marker_path.write_text(json.dumps(marker), encoding="utf-8")
    control = eb.runtime_status()
    assert control.reason_token == control_token and control.auto_updatable, control.reason
    _dist_info(site, "planted-pkg", "6.6.6")
    status = eb.runtime_status()
    assert status.reason_token == "disk_marker_mismatch" and status.integrity_refusal
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert update.calls == 0
    assert [r[0] for r in _rows(db)] == ["denied:integrity"]  # the detection row only


async def test_the_untampered_control_install_IS_updated_automatically(
    db, fake_app, tmp_path, monkeypatch,
):
    _security_install(tmp_path, monkeypatch)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert update.calls == 1


# ---------------------------------------------------------------------------
# The URGENT alert, the click kept available
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("token", TOKENS)
def test_the_urgent_alert_names_the_token_and_the_click_email_stays_silent(
    tmp_path, monkeypatch, token,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper(token, prefix, site, mpath)
    active, ctx = admin_alerts._embedding_integrity_probe()
    assert active and ctx["notice"]["integrity_wait"] is True
    assert ctx["notice"]["integrity_token"] == token
    assert admin_alerts._embedding_runtime_probe() == (False, {"reason": None})
    ctx["app_url"] = "https://triage.example.test"
    html, text = admin_alerts._assemble_embedding_integrity_alert(ctx)
    assert token in ctx["notice"]["headline"] or token in ctx["notice"]["consequence"]
    # hipaa-sme SHOULD-2 (fold 2): the email carries WHAT changed (bounded), rendered in
    # both bodies, because the log holds only the token and the audit row of the heal
    # does not exist until after the click.
    reason = ctx["notice"]["integrity_reason"]
    assert reason and len(reason) <= 400
    assert f"What changed: {reason}" in text
    assert "What changed:" in html and _html.escape(reason) in html
    assert "application log" not in text and "application log" not in html
    if token == "manifest_unreadable":
        assert "fault is in the image" in text and "Redeploy a good image" in text
        assert "click [Update embedding runtime]" not in text
    else:
        assert "does not replace it by itself" in text
        assert "click [Update embedding runtime]" in text
        assert "kept on the data volume for inspection" in text
        assert "https://triage.example.test/config?tab=ai_backends" in text
    assert "every 6 hours" in text and "<a href=" in html or token == "manifest_unreadable"


async def test_the_integrity_alert_repeats_every_six_hours_until_fixed(db, tmp_path, monkeypatch):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    evt = EMBEDDING_RUNTIME_INTEGRITY_EVENT
    assert evt.repeat_while_degraded is True and evt.cooldown_hours == 6
    assert evt.subject.startswith("[email-triage] URGENT")
    delete_setting(db, _settings_key(evt.key))
    t0 = datetime(2026, 10, 25, tzinfo=timezone.utc)
    with patch.object(admin_alerts, "_send_admin_alert", return_value=True) as send:
        assert await fire_on_transition(evt, _Cfg(), db, now=t0) == "sent"
        assert await fire_on_transition(evt, _Cfg(), db, now=t0 + timedelta(hours=1)) == "suppressed"
        assert await fire_on_transition(evt, _Cfg(), db, now=t0 + timedelta(hours=7)) == "sent"
        assert send.call_count == 2


def test_with_the_switch_off_an_integrity_refusal_is_the_569_click_notice(tmp_path, monkeypatch):
    """Exactly today's 569 behaviour when auto-update is off: the click email, no
    urgent event, the original wording."""
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    n = eb.update_notice()
    assert n["kind"] == "update" and n["integrity_wait"] is False
    assert "could not be verified" in n["consequence"]
    assert admin_alerts._embedding_integrity_probe() == (False, {"reason": None})
    active, _ctx = admin_alerts._embedding_runtime_probe()
    assert active


def test_the_integrity_notice_is_a_click_notice_with_its_own_words(tmp_path, monkeypatch):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    n = eb.update_notice()
    assert n["kind"] == "update" and n["serving"] is False
    assert n["headline"].startswith("Embedding runtime refused: the installed files changed")
    assert "disk_marker_mismatch" in n["headline"]
    assert "does not replace it by itself" in n["consequence"]
    assert "evidence" in n["consequence"] and "kept for inspection" in n["consequence"]


# ---------------------------------------------------------------------------
# SHOULD-R3-2: an admin's heal keeps the evidence
# ---------------------------------------------------------------------------

async def test_an_admins_heal_of_an_integrity_refusal_records_what_changed_and_keeps_the_old_files(
    db, fake_app, tmp_path, monkeypatch, admin_user,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    purges: list[object] = []
    monkeypatch.setattr(ru, "schedule_tombstone_purge", lambda app: purges.append(app))
    monkeypatch.setattr(ru, "update_runtime", _Update(retired=["prefix.removing-1"]))
    out = await ru.apply_runtime_update(fake_app, actor=ru.UpdateActor.from_user(admin_user))
    assert out.status == "updated"
    rows = _rows(db)
    intent = rows[0][1]
    assert "integrity_reason=disk_marker_mismatch" in intent
    assert "planted-pkg" in intent, "the audit row must name what changed"
    assert len(intent) < 1500
    assert "evidence_kept=True" in rows[1][1]
    assert purges == [], "the retired set was purged: the evidence is gone"


async def test_a_routine_update_still_purges_what_it_retired(
    db, fake_app, tmp_path, monkeypatch, admin_user,
):
    _security_install(tmp_path, monkeypatch)
    purges: list[object] = []
    monkeypatch.setattr(ru, "schedule_tombstone_purge", lambda app: purges.append(app))
    monkeypatch.setattr(ru, "update_runtime", _Update(retired=["prefix.removing-1"]))
    out = await ru.apply_runtime_update(fake_app, actor=ru.UpdateActor.from_user(admin_user))
    assert out.status == "updated" and len(purges) == 1
    rows = _rows(db)
    assert "integrity_reason" not in rows[0][1] and "evidence_kept" not in rows[1][1]


# ---------------------------------------------------------------------------
# The rendered view (PD-17): the button stays for integrity refusals
# ---------------------------------------------------------------------------

def test_the_banner_keeps_its_button_for_an_integrity_refusal(
    client, admin_cookies, strict_undefined_templates, tmp_path, monkeypatch,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    assert "Embedding runtime refused: the installed files changed" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' in resp.text
    assert "does not replace it by itself" in flat


def test_the_card_keeps_its_button_for_an_integrity_refusal_and_says_why(
    client, admin_cookies, strict_undefined_templates, tmp_path, monkeypatch, db,
):
    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    eb._update_state(db, status="installed", install_method="auto")
    db.commit()
    resp = client.get("/config/ai-backends/embedding-install-status", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    assert ">Update embedding runtime</button>" in flat
    assert "The app does not replace this runtime by itself" in flat
    assert "kept for inspection" in flat
    assert "Retry the update now" not in flat


def test_the_daily_health_tells_the_admin_to_act_for_an_integrity_refusal(
    db, app, tmp_path, monkeypatch,
):
    from email_triage.web.daily_health import _render_html, _render_text, gather_health_state

    prefix, site, mpath = _security_install(tmp_path, monkeypatch)
    _tamper("disk_marker_mismatch", prefix, site, mpath)
    state = gather_health_state(db, app.state.config)
    assert state["embedding_runtime"]["integrity_wait"] is True
    assert state["embedding_runtime"]["headline"] in state["attention_reasons"]
    html = _render_html(state, app.state.config)
    text = _render_text(state, app.state.config)
    assert "Update embedding runtime" in html and "[Update embedding runtime]" in text
