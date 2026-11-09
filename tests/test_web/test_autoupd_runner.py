"""Operator decision 2026-10-25 -- the embedding runtime updates ITSELF.

Behavioural arms for ``web/embedding_update_runner`` (the ONE funnel the click and
the sweeper share): what the automatic run does for a stale non-security change, a
security change, a verify failure, a second concurrent run, the switch off, an
absent runtime, and how it is attributed. ``update_runtime`` (the domain funnel,
covered by ``tests/test_embedding_bits/test_n569_update_funnel.py``) is replaced at
the runner's own boundary; everything around it is real, against a real prefix and
the real audit chain.
"""

from __future__ import annotations

import asyncio
import sys
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix

from email_triage import embedding_bits as eb
from email_triage.web import embedding_update_runner as ru
from email_triage.web.db import get_setting, set_setting


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.invalidate_runtime_ready_cache()


@pytest.fixture
def stale(tmp_path, monkeypatch):
    return make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))


@pytest.fixture
def security(tmp_path, monkeypatch):
    return make_versioned_prefix(
        tmp_path, monkeypatch, steps=(True,), advisories=("CVE-2099-0569",),
    )


@pytest.fixture
def fake_app(db):
    return SimpleNamespace(state=SimpleNamespace(db=db))


def _rows(db):
    return [
        tuple(r) for r in db.execute(
            "SELECT outcome, detail, email, user_id FROM auth_events "
            "WHERE event_type = 'embedding_runtime_update' ORDER BY id"
        ).fetchall()
    ]


class _Fake:
    """A stand-in for ``update_runtime`` at the runner boundary. Records what the
    world looked like at call time and releases the claimed row the way the real
    funnel does."""

    def __init__(self, db, *, status="updated", error_class="", raises=None,
                 gate: threading.Event | None = None, restart_required=False):
        self.db = db
        self.status = status
        self.error_class = error_class
        self.raises = raises
        self.gate = gate
        self.restart_required = restart_required
        self.calls = 0
        self.entered = threading.Event()
        self.seen: list[eb.RuntimeStatus] = []
        self.kw: dict = {}

    def __call__(self, **kw):
        self.calls += 1
        self.kw = kw
        self.seen.append(eb.runtime_status())
        self.entered.set()
        if self.gate is not None:
            assert self.gate.wait(10), "test gate never opened"
        if self.raises is not None:
            raise self.raises
        if self.status == "updated":
            eb._update_state(kw["conn"], status="installed", current_file=None, clear_error=True)
            return eb.UpdateResult(
                status="updated", from_set_version=1, to_set_version=2,
                restart_required=self.restart_required,
            )
        eb._update_state(
            kw["conn"], status="failed", current_file=None,
            last_error_class=self.error_class, last_error_msg="x",
        )
        return eb.UpdateResult(status="failed", error_class=self.error_class)


# ---------------------------------------------------------------------------
# The two cases the operator named
# ---------------------------------------------------------------------------

async def test_a_stale_non_security_runtime_is_updated_and_the_old_one_serves_while_staging(
    db, fake_app, stale, monkeypatch,
):
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert eb.runtime_status().state == eb.STATE_STALE_OK
    assert await ru.auto_update_once(fake_app) == "updated"
    assert fake.calls == 1
    # While the new set was staging, the old one was STILL serving.
    assert fake.seen[0].state == eb.STATE_STALE_OK and fake.seen[0].serving
    # The state says what changed, for the after-the-fact notice.
    rec = ru.recent_auto_update(ru.read_auto_state(db))
    assert rec["from_version"] == 1 and rec["to_version"] == 2
    assert rec["security"] == eb.SECURITY_NONE and rec["restart_required"] is False


async def test_a_security_change_is_updated_and_the_old_one_stays_refused_until_the_swap(
    db, fake_app, security, monkeypatch,
):
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert eb.runtime_status().state == eb.STATE_REFUSED
    assert await ru.auto_update_once(fake_app) == "updated"
    # Fail closed meanwhile: the old set was refused when the funnel ran.
    assert fake.seen[0].state == eb.STATE_REFUSED and not fake.seen[0].serving
    rec = ru.recent_auto_update(ru.read_auto_state(db))
    assert rec["security"] == eb.SECURITY_FIX and rec["advisories"] == ["CVE-2099-0569"]


# ---------------------------------------------------------------------------
# Failure: rollback is the funnel's; retry, backoff and the alert are ours
# ---------------------------------------------------------------------------

async def test_a_verify_failure_records_a_retry_with_backoff_and_alerts(
    db, fake_app, security, monkeypatch,
):
    fake = _Fake(db, status="failed", error_class="StagedSetNotVerified")
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "failed"
    state = ru.read_auto_state(db)
    assert state["failures"] == 1 and state["error_class"] == "StagedSetNotVerified"
    assert eb.auto_update_failure() == {"failures": 1, "error_class": "StagedSetNotVerified"}
    # Not retried in a tight loop: the backoff holds the next attempt back.
    assert await ru.auto_update_once(fake_app) == "backoff"
    assert fake.calls == 1
    # Once the backoff has elapsed it retries, and the delay doubles.
    stale_stamp = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    set_setting(db, ru.AUTO_STATE_KEY, {**state, "last_failure_at": stale_stamp})
    assert await ru.auto_update_once(fake_app) == "failed"
    assert fake.calls == 2 and ru.read_auto_state(db)["failures"] == 2
    assert ru.backoff_delay(1) == timedelta(minutes=15)
    assert ru.backoff_delay(2) == timedelta(minutes=30)
    assert ru.backoff_delay(3) == timedelta(hours=1)
    assert ru.backoff_delay(40) == ru.BACKOFF_CAP == timedelta(hours=6)
    # A security change that cannot be applied is URGENT and says it is retrying.
    from email_triage.web import admin_alerts

    active, ctx = admin_alerts._embedding_auto_failed_probe()
    assert active and ctx["notice"]["kind"] == "auto_failed"
    # The attempt left a failure row under the system actor.
    outcomes = [r[0] for r in _rows(db)]
    assert outcomes.count("failure") == 2


async def test_the_next_success_clears_the_failure_on_every_edge(
    db, fake_app, stale, monkeypatch,
):
    fake = _Fake(db, status="failed", error_class="PostSwapVerifyFailed")
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "failed"
    stale_stamp = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    set_setting(db, ru.AUTO_STATE_KEY, {**ru.read_auto_state(db), "last_failure_at": stale_stamp})
    monkeypatch.setattr(ru, "update_runtime", _Fake(db))
    assert await ru.auto_update_once(fake_app) == "updated"
    state = ru.read_auto_state(db)
    assert state["failures"] == 0 and state["last_failure_at"] is None
    assert eb.auto_update_failure() is None  # the process-local mirror too (PD-18)


async def test_a_failure_flag_is_also_cleared_when_the_runtime_is_made_current_another_way(
    db, fake_app, stale, tmp_path, monkeypatch,
):
    monkeypatch.setattr(ru, "update_runtime", _Fake(db, status="failed", error_class="X"))
    assert await ru.auto_update_once(fake_app) == "failed"
    make_verified_prefix(tmp_path / "fixed", monkeypatch)  # an admin fixed it by hand
    assert await ru.auto_update_once(fake_app) == "current"
    assert ru.read_auto_state(db)["failures"] == 0 and eb.auto_update_failure() is None


async def test_a_raise_inside_the_update_releases_the_row_and_counts_a_failure(
    db, fake_app, stale, monkeypatch,
):
    monkeypatch.setattr(ru, "update_runtime", _Fake(db, raises=RuntimeError("boom")))
    assert await ru.auto_update_once(fake_app) == "failed"
    assert eb.get_install_status(db)["status"] == "failed"  # not stuck "downloading"
    assert ru.read_auto_state(db)["failures"] == 1
    assert ru.read_auto_state(db)["error_class"] == "RuntimeError"


async def test_a_new_image_is_a_fresh_target_not_held_back_by_an_old_failure(
    db, fake_app, stale, monkeypatch,
):
    monkeypatch.setattr(ru, "update_runtime", _Fake(db, status="failed", error_class="X"))
    assert await ru.auto_update_once(fake_app) == "failed"
    set_setting(db, ru.AUTO_STATE_KEY, {**ru.read_auto_state(db), "target": "v0->v1"})
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "updated" and fake.calls == 1


# ---------------------------------------------------------------------------
# Single-flight, the switch, an absent runtime
# ---------------------------------------------------------------------------

async def test_a_second_run_while_one_is_in_flight_is_skipped(
    db, fake_app, stale, monkeypatch, admin_user,
):
    gate = threading.Event()
    fake = _Fake(db, gate=gate)
    monkeypatch.setattr(ru, "update_runtime", fake)
    first = asyncio.create_task(ru.auto_update_once(fake_app))
    for _ in range(500):
        if fake.entered.is_set():
            break
        await asyncio.sleep(0.02)
    assert fake.entered.is_set()
    # A second automatic tick AND a manual click both see it in flight.
    assert await ru.auto_update_once(fake_app) == "busy"
    refused = await ru.start_runtime_update(
        fake_app, actor=ru.UpdateActor.from_user(admin_user),
    )
    assert refused == ru.UPDATE_REFUSED_IN_FLIGHT
    gate.set()
    assert await first == "updated"
    assert fake.calls == 1


async def test_with_the_switch_off_nothing_runs_by_itself(db, fake_app, stale, monkeypatch):
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "disabled"
    assert fake.calls == 0 and _rows(db) == []
    # Exactly today's 569 behaviour: the notice asks for the click.
    n = eb.update_notice()
    assert n["kind"] == "update" and "until you update it" in n["consequence"]


async def test_an_absent_runtime_is_never_installed_from_here(db, fake_app, tmp_path, monkeypatch):
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "none"))
    eb.invalidate_runtime_ready_cache()
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "current" and fake.calls == 0


async def test_a_current_runtime_is_left_alone(db, fake_app, tmp_path, monkeypatch):
    make_verified_prefix(tmp_path, monkeypatch)
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "current" and fake.calls == 0


# ---------------------------------------------------------------------------
# Attribution (PD-3, §164.312(b))
# ---------------------------------------------------------------------------

async def test_the_audit_rows_of_an_unattended_run_carry_the_typed_system_actor(
    db, fake_app, stale, monkeypatch,
):
    monkeypatch.setattr(ru, "update_runtime", _Fake(db))
    assert await ru.auto_update_once(fake_app) == "updated"
    rows = _rows(db)
    assert [r[0] for r in rows] == ["attempt", "success"]
    for _outcome, _detail, email, user_id in rows:
        assert email == ru.SYSTEM_ACTOR_EMAIL and email.startswith("system:")
        assert email.strip() and email != "unknown" and user_id is None
    assert "trigger=automatic" in rows[0][1] and "method=auto" in rows[0][1]


def test_the_system_actor_is_typed_and_never_blank():
    a = ru.UpdateActor.system()
    assert a.automatic and a.user_id is None
    assert a.email == ru.SYSTEM_ACTOR_EMAIL and a.email.strip() and a.email != "unknown"
    b = ru.UpdateActor.from_user({"email": "admin@x.test", "id": 7})
    assert not b.automatic and b.email == "admin@x.test" and b.user_id == 7


async def test_a_click_is_attributed_to_the_admin_and_leaves_no_auto_state(
    db, fake_app, stale, monkeypatch, admin_user,
):
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    out = await ru.apply_runtime_update(
        fake_app, actor=ru.UpdateActor.system(),
    )
    assert out.status == "updated"
    # A manual run goes through start_runtime_update (background task).
    monkeypatch.setattr(ru, "update_runtime", _Fake(db, status="failed", error_class="X"))
    eb._update_state(db, status="installed")
    db.commit()
    refused = await ru.start_runtime_update(
        fake_app, actor=ru.UpdateActor.from_user(admin_user),
    )
    assert refused == ""
    for _ in range(500):
        if any(r[0] == "failure" for r in _rows(db)):
            break
        await asyncio.sleep(0.02)
    click_rows = [r for r in _rows(db) if r[2] == admin_user["email"]]
    assert [r[0] for r in click_rows] == ["attempt", "failure"]
    assert all(r[3] == admin_user["id"] for r in click_rows)
    # An admin's failed click is NOT an automatic failure: no retry bookkeeping.
    assert ru.read_auto_state(db)["failures"] == 0


# ---------------------------------------------------------------------------
# The durable state is robust, and a restart does not lose it
# ---------------------------------------------------------------------------

def test_a_corrupt_state_row_reads_as_empty(db):
    for bad in ("junk", [1, 2], {"failures": "many", "updated": 3}, {"failures": True}):
        set_setting(db, ru.AUTO_STATE_KEY, bad)
        s = ru.read_auto_state(db)
        assert s["failures"] == 0 and s["updated"] is None


def test_a_restart_rehydrates_the_failure_for_the_notice(db):
    ru.record_auto_failure(db, error_class="HashMismatch", target="v1->v2")
    eb.set_auto_update_failure(None)
    ru.rehydrate_auto_failure(db)
    assert eb.auto_update_failure() == {"failures": 1, "error_class": "HashMismatch"}
    ru.record_auto_success(db, updated={"at": ru.now_utc_iso()})
    ru.rehydrate_auto_failure(db)
    assert eb.auto_update_failure() is None


def test_the_retry_gate_survives_a_restart_because_it_lives_in_the_row(db):
    ru.record_auto_failure(db, error_class="X", target="v1->v2")
    state = ru.read_auto_state(db)  # what a fresh process reads
    assert not ru.retry_due(state, target="v1->v2")
    later = datetime.now(timezone.utc) + timedelta(minutes=16)
    assert ru.retry_due(state, target="v1->v2", now=later)
    assert ru.retry_due(state, target="v2->v3")  # another image: fresh


def test_the_updated_record_ages_out_of_the_notice_window(db):
    now = datetime.now(timezone.utc)
    state = {"updated": {"at": (now - timedelta(hours=2)).isoformat()}}
    assert ru.recent_auto_update(state, now=now) is not None
    state = {"updated": {"at": (now - timedelta(hours=25)).isoformat()}}
    assert ru.recent_auto_update(state, now=now) is None
    assert ru.recent_auto_update({"updated": {"at": "not a date"}}, now=now) is None
    assert ru.recent_auto_update({"updated": None}, now=now) is None


# ---------------------------------------------------------------------------
# The switch, through the config SSOT
# ---------------------------------------------------------------------------

def test_the_switch_defaults_on_and_follows_the_config(tmp_path):
    from email_triage.config import EmbeddingConfig, load_config

    assert EmbeddingConfig().auto_update is True
    for text, want in (
        ("embedding:\n  backend: sentence_transformers\n  auto_update: false\n", False),
        ("embedding:\n  backend: sentence_transformers\n  auto_update: true\n", True),
        ("embedding:\n  backend: sentence_transformers\n", True),
    ):
        p = tmp_path / "c.yaml"
        p.write_text(text, encoding="utf-8")
        assert load_config(p).embedding.auto_update is want, text


def test_the_lifespan_value_reaches_the_notice():
    eb.configure_auto_update(False)
    assert eb.auto_update_enabled() is False
    eb.configure_auto_update(True)
    assert eb.auto_update_enabled() is True
    eb.configure_auto_update(None)  # unset -> the config key's own default
    assert eb.auto_update_enabled() is True


async def test_the_sweeper_runs_the_runner_on_the_supervised_loop_and_is_inert_when_off(
    fake_app, monkeypatch,
):
    from email_triage.web import background_sweepers as bs
    from email_triage.web import task_supervisor

    captured: dict = {}

    async def fake_loop(name, interval, tick, **kw):
        captured.update(name=name, interval=interval, kw=kw)
        await tick()

    seen: list[object] = []

    async def fake_once(app):
        seen.append(app)
        return "current"

    monkeypatch.setattr(task_supervisor, "supervised_interval_loop", fake_loop)
    monkeypatch.setattr(ru, "auto_update_once", fake_once)
    fake_app.state.config = SimpleNamespace()
    await bs._embedding_auto_update_sweeper(fake_app)
    assert captured["name"] == "embedding-auto-update-sweeper"
    assert captured["interval"] == 600.0
    assert captured["kw"]["lease_name"] == "embedding-auto-update-sweeper"
    assert 0 < captured["kw"]["warmup_secs"] <= 30  # the boot trigger: first tick soon
    assert seen == [fake_app]
    assert fake_app.state.embedding_auto_update_sweeper_status["result"] == "current"
    captured.clear()
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    await bs._embedding_auto_update_sweeper(fake_app)
    assert captured == {}


# ---------------------------------------------------------------------------
# Punch 732 (panel py314 DA MUST): a base-image interpreter bump is replaced HERE
# ---------------------------------------------------------------------------

def _interpreter_bump(tmp_path, monkeypatch, *, drop_set_version=False):
    """An install recorded by ANOTHER interpreter: the v1 tree moved to a
    ``lib/python<other>`` dir the running interpreter never loads."""
    prefix, site, _manifest = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    major, minor = sys.version_info.major, sys.version_info.minor
    other = f"python{major}.{minor - 2 if minor >= 2 else minor + 2}"
    site.parent.rename(prefix / "lib" / other)
    if drop_set_version:
        import json
        marker_path = eb.installed_marker_path(prefix)
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        marker.pop("set_version", None)
        marker_path.write_text(json.dumps(marker), encoding="utf-8")
    eb.invalidate_runtime_ready_cache()
    return prefix, prefix / "lib" / other / "site-packages"


async def test_an_interpreter_mismatch_is_installed_by_itself_not_left_current(
    db, fake_app, tmp_path, monkeypatch,
):
    _interpreter_bump(tmp_path, monkeypatch)
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert fake.calls == 1
    assert fake.seen[0].reason_token == "interpreter_mismatch"
    details = [d for _o, d, _e, _u in _rows(db)]
    assert any("reason=interpreter_mismatch" in d and "old_tree_verified=true" in d
               for d in details), details


async def test_a_marker_without_set_version_still_has_a_target(
    db, fake_app, tmp_path, monkeypatch,
):
    _interpreter_bump(tmp_path, monkeypatch, drop_set_version=True)
    status = eb.runtime_status()
    assert status.reason_token == "interpreter_mismatch" and status.installed_set_version is None
    assert isinstance(ru.target_of(status), str) and ru.target_of(status)
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "updated" and fake.calls == 1


async def test_a_tampered_orphan_tree_waits_for_an_admin_and_is_not_wiped(
    db, fake_app, tmp_path, monkeypatch,
):
    _prefix, orphan = _interpreter_bump(tmp_path, monkeypatch)
    metadata = next(orphan.glob("*.dist-info")) / "METADATA"
    metadata.write_text(metadata.read_text(encoding="utf-8") + "X-Tampered: 1\n",
                        encoding="utf-8")
    eb.invalidate_runtime_ready_cache()
    fake = _Fake(db)
    monkeypatch.setattr(ru, "update_runtime", fake)
    assert await ru.auto_update_once(fake_app) == "integrity"
    assert fake.calls == 0 and orphan.is_dir()
