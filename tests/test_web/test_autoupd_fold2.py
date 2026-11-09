"""Panel T round 1 on the AUTOUPD class (2026-10-25): the folds that need a rendered or
a timed arm.

* hipaa SHOULD-1 / db S-A1 : an AUTOMATIC claim whose fresh status stopped being
  auto-updatable claims nothing (the R3 rule lives in the funnel, not only the trigger).
* db S-A2                  : an automatic attempt the process died in is counted, so the
  backoff holds across a restart.
* DA SHOULD-A1             : the R1 deferral CONVERGES (the boot gate holds the first
  embedding load until the first auto-update decision; a deferral that recurs escalates).
* hipaa NOTE-1             : an integrity heal keeps the replaced files out of every purge.
* db NOTE                  : only LOGIN event types count toward a login lockout.

The hipaa MUST-1 detection row and the SHOULD-2 email are in ``test_autoupd_integrity.py``.
"""

from __future__ import annotations

import asyncio
import sys
import types
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from _embedding_runtime_fixture import make_verified_prefix, make_versioned_prefix
from _pin_harness import enclosing_fn, walk_src

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web import embedding_update_runner as ru
from email_triage.web.db import set_setting


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    monkeypatch.setattr(eb, "_restart_pending", False)
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    monkeypatch.setattr(eb, "_auto_failure", None)
    monkeypatch.setattr(eb, "_auto_deferred", None)
    monkeypatch.setattr(eb, "_boot_gate_armed_at", None)
    monkeypatch.setattr(sys, "path", list(sys.path))
    eb.invalidate_runtime_ready_cache()
    yield
    eb.release_boot_update_gate()
    eb.invalidate_runtime_ready_cache()


def _app(db):
    """A FRESH app state = a fresh process (the per-process dedupe lives on it)."""
    return SimpleNamespace(state=SimpleNamespace(db=db))


def _rows(db):
    return [
        tuple(r) for r in db.execute(
            "SELECT outcome, detail, email FROM auth_events "
            "WHERE event_type = 'embedding_runtime_update' ORDER BY id"
        ).fetchall()
    ]


class _Update:
    def __init__(self, *, status="updated", error_class="", retired=(), log=None):
        self.calls = 0
        self.status, self.error_class = status, error_class
        self.retired = list(retired)
        self.log = log

    def __call__(self, **kw):
        self.calls += 1
        if self.log is not None:
            self.log.append("update")
        if self.status == "updated":
            eb._update_state(kw["conn"], status="installed", current_file=None, clear_error=True)
            return eb.UpdateResult(
                status="updated", from_set_version=1, to_set_version=2, retired=self.retired,
            )
        eb._update_state(
            kw["conn"], status="failed", current_file=None,
            last_error_class=self.error_class, last_error_msg="x",
        )
        return eb.UpdateResult(status="failed", error_class=self.error_class)


# ---------------------------------------------------------------------------
# hipaa SHOULD-1 / db S-A1: the funnel enforces R3, not only the trigger
# ---------------------------------------------------------------------------

async def test_a_status_that_flips_to_integrity_between_the_trigger_and_the_claim_claims_nothing(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    real = eb.runtime_status
    seen: list[int] = []

    def flipping(*a, **k):
        seen.append(1)
        if len(seen) == 1:  # the trigger's read: ordinary stale_ok
            return real(*a, **k)
        return eb.RuntimeStatus(  # the claim's fresh read: a tamper appeared
            state=eb.STATE_REFUSED, reason="disk_marker_mismatch: the tree changed (added: x)",
        )

    monkeypatch.setattr(ru, "runtime_status", flipping)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(_app(db)) == "refused"
    assert update.calls == 0, "update_runtime ran although the claim's status was an integrity refusal"
    assert _rows(db) == [], "an INTENT row was written for a claim the funnel must refuse"
    assert eb.get_install_status(db)["status"] != "downloading"
    assert len(seen) >= 2


async def test_the_funnel_refuses_an_automatic_actor_on_a_status_the_app_does_not_heal(
    db, tmp_path, monkeypatch, admin_user,
):
    """Enforced in the funnel itself, so a future automatic caller inherits it. A CLICK
    is a human deciding and is never refused on this ground."""
    prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    planted = site / "planted_pkg-6.6.6.dist-info"
    planted.mkdir()
    (planted / "METADATA").write_text("Metadata-Version: 2.1\nName: planted-pkg\nVersion: 6.6.6\n", encoding="utf-8")
    assert eb.runtime_status().integrity_refusal
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    out = await ru.apply_runtime_update(_app(db), actor=ru.UpdateActor.system())
    assert out.status == "refused" and out.refusal == ru.UPDATE_REFUSED_NOT_AUTOMATIC
    assert update.calls == 0 and _rows(db) == []
    click = await ru.apply_runtime_update(_app(db), actor=ru.UpdateActor.from_user(admin_user))
    assert click.status == "updated" and update.calls == 1  # the human's decision stands


async def test_a_runtime_that_became_current_between_the_reads_is_not_claimed(db, tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    real = eb.runtime_status
    seen: list[int] = []

    def then_current(*a, **k):
        seen.append(1)
        return real(*a, **k) if len(seen) == 1 else eb.RuntimeStatus(state=eb.STATE_OK, reason="ok")

    monkeypatch.setattr(ru, "runtime_status", then_current)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(_app(db)) == "refused"
    assert update.calls == 0 and _rows(db) == []


# ---------------------------------------------------------------------------
# db S-A2: a killed automatic attempt is counted
# ---------------------------------------------------------------------------

async def test_an_attempt_the_process_died_in_is_counted_and_backs_off_at_the_next_boot(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    claim, refused = await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert claim is not None and refused == ""
    assert ru.read_auto_state(db)["in_flight"], "the claim must mark the attempt"
    # The process dies here: _finish never runs. The 569 boot recovery releases the row.
    eb.reconcile_interrupted_install_row(db)
    assert eb.get_install_status(db)["status"] == "failed"
    # A new process: its mirrors start empty.
    eb.set_auto_update_failure(None)
    assert await ru.auto_update_once(_app(db)) == "backoff"
    state = ru.read_auto_state(db)
    assert state["failures"] == 1 and state["error_class"] == "Interrupted"
    assert state["in_flight"] is None
    assert update.calls == 0, "the killed attempt must not be retried before its backoff"
    assert eb.auto_update_failure() == {"failures": 1, "error_class": "Interrupted"}
    # It really is the ladder, not a one-off: a second death doubles the wait.
    stamp = (datetime.now(timezone.utc) - timedelta(minutes=16)).isoformat()
    set_setting(db, ru.AUTO_STATE_KEY, {**state, "last_failure_at": stamp})
    claim, _ = await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert claim is not None
    eb.reconcile_interrupted_install_row(db)
    assert await ru.auto_update_once(_app(db)) == "backoff"
    assert ru.read_auto_state(db)["failures"] == 2


async def test_the_marker_is_cleared_by_every_way_an_attempt_ends_so_nothing_is_double_counted(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    # a failure that lived to say so counts ONCE
    monkeypatch.setattr(ru, "update_runtime", _Update(status="failed", error_class="PipInstallError"))
    assert await ru.auto_update_once(_app(db)) == "failed"
    state = ru.read_auto_state(db)
    assert state["failures"] == 1 and state["in_flight"] is None
    assert await ru.auto_update_once(_app(db)) == "backoff"
    assert ru.read_auto_state(db)["failures"] == 1  # the next tick did not recount it
    # a success leaves no marker and no failure
    set_setting(db, ru.AUTO_STATE_KEY, {**state, "last_failure_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()})
    monkeypatch.setattr(ru, "update_runtime", _Update())
    assert await ru.auto_update_once(_app(db)) == "updated"
    state = ru.read_auto_state(db)
    assert state["failures"] == 0 and state["in_flight"] is None


async def test_a_marker_for_a_runtime_that_is_current_is_forgotten_not_counted(
    db, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path / "old", monkeypatch, steps=(False,))
    claim, _ = await ru._claim(_app(db), ru.UpdateActor.system(), None, None)
    assert claim is not None
    eb.reconcile_interrupted_install_row(db)
    make_verified_prefix(tmp_path / "now", monkeypatch)  # the swap had actually finished
    assert await ru.auto_update_once(_app(db)) == "current"
    state = ru.read_auto_state(db)
    assert state["failures"] == 0 and state["in_flight"] is None


# ---------------------------------------------------------------------------
# DA SHOULD-A1 (a): the boot gate, so the deferral converges
# ---------------------------------------------------------------------------

def _early_user(prefix_site, log):
    """A backend whose model load 'imports from the runtime prefix' (the only thing the
    loaded-here predicate reads) and an ``embed_text`` caller."""
    from email_triage.engine.embedding_backend import SentenceTransformersBackend

    backend = SentenceTransformersBackend(model="m")
    mod_file = prefix_site / "fake_st.py"
    mod_file.write_text("x = 1\n", encoding="utf-8")

    class _Model:
        def encode(self, text, convert_to_numpy=True):
            return SimpleNamespace(tolist=lambda: [0.5])

    def fake_load():
        log.append("load")
        mod = types.ModuleType("fake_st")
        mod.__file__ = str(mod_file)
        sys.modules["fake_st"] = mod
        return _Model()

    backend._load_model = fake_load
    return backend


async def test_an_early_embedding_user_does_not_defer_the_update_when_the_gate_holds_it(
    db, tmp_path, monkeypatch,
):
    _prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.delitem(sys.modules, "fake_st", raising=False)
    log: list[str] = []
    backend = _early_user(site, log)
    monkeypatch.setattr(ru, "update_runtime", _Update(log=log))
    assert eb.arm_boot_update_gate() is True and eb.boot_update_gate_pending()
    user = asyncio.create_task(backend.embed_text("hi"))
    await asyncio.sleep(0.6)
    assert log == [] and not user.done(), "the first load did not wait for the decision"
    try:
        assert await ru.auto_update_once(_app(db)) == "updated"  # APPLIED, not deferred
        assert await asyncio.wait_for(user, 10) == [0.5]
        assert log == ["update", "load"], log  # the update first, then the load
        assert not eb.boot_update_gate_pending()
        assert ru.read_auto_state(db)["deferred"] is None
    finally:
        sys.modules.pop("fake_st", None)


async def test_without_the_gate_the_same_early_user_defers_the_update(db, tmp_path, monkeypatch):
    """The control: this is the race the gate closes."""
    _prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.delitem(sys.modules, "fake_st", raising=False)
    log: list[str] = []
    backend = _early_user(site, log)
    update = _Update(log=log)
    monkeypatch.setattr(ru, "update_runtime", update)
    try:
        assert await backend.embed_text("hi") == [0.5]  # the early user loads first
        assert await ru.auto_update_once(_app(db)) == "deferred"
        assert update.calls == 0
    finally:
        sys.modules.pop("fake_st", None)


async def test_the_gate_is_bounded_past_the_cap_the_old_set_serves_and_a_deferral_is_recorded(
    db, tmp_path, monkeypatch,
):
    _prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.delitem(sys.modules, "fake_st", raising=False)
    monkeypatch.setattr(eb, "BOOT_UPDATE_GATE_CAP_SECS", 0.4)
    log: list[str] = []
    backend = _early_user(site, log)
    update = _Update(log=log)
    monkeypatch.setattr(ru, "update_runtime", update)
    assert eb.arm_boot_update_gate() is True
    try:
        assert await asyncio.wait_for(backend.embed_text("hi"), 10) == [0.5]
        assert log == ["load"] and not eb.boot_update_gate_pending()
        assert eb.auto_update_deferred() is not None  # surfaced at once
        assert await ru.auto_update_once(_app(db)) == "deferred"  # and recorded durably
        assert ru.read_auto_state(db)["deferred"]["count"] == 1 and update.calls == 0
    finally:
        sys.modules.pop("fake_st", None)


async def test_every_exit_of_the_first_decision_releases_the_gate(db, tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    assert eb.arm_boot_update_gate() is True

    def boom(*a, **k):
        raise RuntimeError("status exploded")

    monkeypatch.setattr(ru, "runtime_status", boom)
    with pytest.raises(RuntimeError):
        await ru.auto_update_once(_app(db))
    assert not eb.boot_update_gate_pending()
    monkeypatch.setattr(eb, "runtime_status", boom)
    assert eb.arm_boot_update_gate() is False  # a status read that raises arms nothing
    monkeypatch.undo()
    # The switch-off exit releases it too (the first check of the decision).
    make_versioned_prefix(tmp_path / "off", monkeypatch, steps=(False,))
    assert eb.arm_boot_update_gate() is True
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    assert await ru.auto_update_once(_app(db)) == "disabled"
    assert not eb.boot_update_gate_pending()


def test_the_gate_arms_only_for_a_stale_ok_runtime_with_auto_update_on(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path / "stale", monkeypatch, steps=(False,))
    monkeypatch.setattr(eb, "_AUTO_UPDATE", False)
    assert eb.arm_boot_update_gate() is False and not eb.boot_update_gate_pending()
    monkeypatch.setattr(eb, "_AUTO_UPDATE", True)
    assert eb.arm_boot_update_gate() is True
    eb.release_boot_update_gate()
    make_versioned_prefix(tmp_path / "sec", monkeypatch, steps=(True,))  # refused: never loaded
    assert eb.arm_boot_update_gate() is False
    make_verified_prefix(tmp_path / "ok", monkeypatch)
    assert eb.arm_boot_update_gate() is False
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "none"))
    eb.invalidate_runtime_ready_cache()
    assert eb.arm_boot_update_gate() is False


async def test_the_first_tick_runs_without_its_warmup_while_the_gate_holds_a_load(
    tmp_path, monkeypatch, db,
):
    from email_triage.web import background_sweepers as bs
    from email_triage.web import task_supervisor

    captured: dict = {}

    async def fake_loop(name, interval, tick, **kw):
        captured.update(kw)

    monkeypatch.setattr(task_supervisor, "supervised_interval_loop", fake_loop)
    app = SimpleNamespace(state=SimpleNamespace(db=db, config=SimpleNamespace()))
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    assert eb.arm_boot_update_gate() is True
    await bs._embedding_auto_update_sweeper(app)
    assert captured["warmup_secs"] == 1 and captured["startup_jitter_secs"] == 0.0
    eb.release_boot_update_gate()
    captured.clear()
    await bs._embedding_auto_update_sweeper(app)
    assert captured["warmup_secs"] == 20 and captured["startup_jitter_secs"] == 10.0


def test_the_gate_is_wired_in_the_lifespan_and_before_the_only_import_site():
    """Structural: the lifespan arms it; ``embed_text`` waits on it BEFORE ``_load_model``
    (the one in-process import of the runtime); ``auto_update_once`` releases it."""
    import ast

    sites: dict[str, list[tuple[str, int]]] = {"arm": [], "wait": [], "load": [], "release": []}
    for _path, rel, tree in walk_src():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name == "arm_boot_update_gate":
                sites["arm"].append((rel, node.lineno))
            elif name == "wait_for_boot_update_decision":
                sites["wait"].append((rel, node.lineno))
            elif name == "_load_model" and rel == "engine/embedding_backend.py":
                sites["load"].append((enclosing_fn(node), node.lineno))
            elif name == "release_boot_update_gate":
                sites["release"].append((rel, node.lineno))
    assert [r for r, _ in sites["arm"]] == ["web/app.py"]
    waits = [ln for r, ln in sites["wait"] if r == "engine/embedding_backend.py"]
    loads = [ln for fn, ln in sites["load"] if fn == "embed_text"]
    assert waits and loads and max(waits) < min(loads), (waits, loads)
    released_in = {r for r, _ in sites["release"]}
    assert {"web/app.py", "web/embedding_update_runner.py"} <= released_in


# ---------------------------------------------------------------------------
# DA SHOULD-A1 (b): a deferral that recurs escalates
# ---------------------------------------------------------------------------

async def test_a_deferral_that_recurs_for_three_starts_escalates_everywhere(
    db, app, tmp_path, monkeypatch,
):
    from email_triage.web.daily_health import gather_health_state

    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    for boot in (1, 2, 3):
        a = _app(db)  # a new process each time
        assert await ru.auto_update_once(a) == "deferred"
        assert await ru.auto_update_once(a) == "deferred"  # a tick in the same process
        assert ru.read_auto_state(db)["deferred"]["count"] == boot, "counted once per process"
        n = eb.update_notice()
        assert n["kind"] == "auto_deferred" and n["escalated"] is (boot >= 3)
        state = gather_health_state(db, app.state.config)
        flipped = any("deferred" in r.lower() for r in state["attention_reasons"])
        assert flipped is (boot >= 3), (boot, state["attention_reasons"])
        active, ctx = admin_alerts._embedding_deferred_probe()
        assert active is (boot >= 3)
    html, text = admin_alerts._assemble_embedding_deferred_alert(ctx)
    assert "keeps being deferred" in text and "3 starts running" in text
    assert "restart the container" in text.lower() and "Nothing is broken" in text
    assert "keeps being deferred" in html
    # the click email and the failure email stay silent for it
    assert admin_alerts._embedding_runtime_probe() == (False, {"reason": None})
    assert admin_alerts._embedding_auto_failed_probe() == (False, {"reason": None})
    # a start that applies it ends the streak
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: False)
    monkeypatch.setattr(ru, "update_runtime", _Update())
    assert await ru.auto_update_once(_app(db)) == "updated"
    assert ru.read_auto_state(db)["deferred"] is None
    assert eb.update_notice(eb.RuntimeStatus(state=eb.STATE_STALE_OK, reason="stale_ok: x"))["escalated"] is False


async def test_a_deferral_that_lasts_seven_days_escalates_at_its_first_count(db, tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    assert await ru.auto_update_once(_app(db)) == "deferred"
    state = ru.read_auto_state(db)
    old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
    set_setting(db, ru.AUTO_STATE_KEY, {**state, "deferred": {**state["deferred"], "since": old}})
    assert await ru.auto_update_once(_app(db)) == "deferred"
    assert ru.read_auto_state(db)["deferred"]["count"] == 2  # a second start, not yet three
    assert eb.update_notice()["escalated"] is True  # but eight days is enough


def test_the_escalation_thresholds_are_the_ruled_ones():
    assert eb.DEFERRAL_ESCALATE_COUNT == 3 and eb.DEFERRAL_ESCALATE_DAYS == 7
    assert eb.deferral_escalated({"count": 3}) and not eb.deferral_escalated({"count": 2})
    assert eb.deferral_escalated({"count": 1, "since": "2000-01-01T00:00:00+00:00"})
    assert not eb.deferral_escalated(None) and not eb.deferral_escalated({})


# ---------------------------------------------------------------------------
# hipaa NOTE-1: kept evidence survives every purge
# ---------------------------------------------------------------------------

async def test_an_integrity_heal_keeps_the_replaced_files_out_of_every_purge_and_names_them(
    db, tmp_path, monkeypatch, admin_user,
):
    prefix, site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    planted = site / "planted_pkg-6.6.6.dist-info"
    planted.mkdir()
    (planted / "METADATA").write_text("Metadata-Version: 2.1\nName: planted-pkg\nVersion: 6.6.6\n", encoding="utf-8")
    tomb = prefix.parent / (prefix.name + eb.REMOVAL_TOMBSTONE_INFIX + "123")
    tomb.mkdir()
    (tomb / "evidence.txt").write_text("the replaced set", encoding="utf-8")
    purges: list[object] = []
    monkeypatch.setattr(ru, "schedule_tombstone_purge", lambda app: purges.append(app))
    monkeypatch.setattr(ru, "update_runtime", _Update(retired=[tomb.name]))
    out = await ru.apply_runtime_update(_app(db), actor=ru.UpdateActor.from_user(admin_user))
    assert out.status == "updated" and purges == []
    kept = prefix.parent / (prefix.name + eb.EVIDENCE_INFIX + "123")
    assert kept.is_dir() and (kept / "evidence.txt").is_file() and not tomb.exists()
    # a later routine update's purge cannot touch it
    assert eb.purge_removal_tombstones() == [] and kept.is_dir()
    detail = _rows(db)[1][1]
    assert kept.name in detail and "until an admin removes them" in detail
    assert "no routine update purges them" in detail
    assert "/" not in kept.name and "\\" not in detail.split("as ", 1)[1][:80]  # names, not paths


async def test_a_routine_update_still_hands_its_tombstone_to_the_purge(db, tmp_path, monkeypatch, admin_user):
    prefix, _site, _m = make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    tomb = prefix.parent / (prefix.name + eb.REMOVAL_TOMBSTONE_INFIX + "9")
    tomb.mkdir()
    purges: list[object] = []
    monkeypatch.setattr(ru, "schedule_tombstone_purge", lambda app: purges.append(app))
    monkeypatch.setattr(ru, "update_runtime", _Update(retired=[tomb.name]))
    out = await ru.apply_runtime_update(_app(db), actor=ru.UpdateActor.from_user(admin_user))
    assert out.status == "updated" and len(purges) == 1 and tomb.is_dir()
    assert not any(eb.EVIDENCE_INFIX in p.name for p in prefix.parent.iterdir())


# ---------------------------------------------------------------------------
# db NOTE: only login event types count toward a lockout
# ---------------------------------------------------------------------------

def test_embedding_update_failure_rows_never_count_toward_a_login_lockout(db):
    from email_triage.web.db import record_auth_event
    from email_triage.web.login_guard import LoginLocked, check_login_allowed

    cfg = SimpleNamespace(auth=SimpleNamespace(
        login_per_email_max=3, login_per_email_window_secs=600,
        login_per_ip_max=3, login_per_ip_window_secs=600,
    ))
    for _ in range(8):  # an admin's failed / rejected update clicks
        record_auth_event(
            db, event_type="embedding_runtime_update", email="admin@x.test",
            outcome="failure", ip="10.0.0.9", detail="rejected — in flight",
        )
    check_login_allowed(db, email="admin@x.test", ip="10.0.0.9", config=cfg)  # does not raise
    # the deferral and the integrity detection use their own outcome tokens
    for outcome in ("deferred", "denied:integrity"):
        record_auth_event(
            db, event_type="embedding_runtime_update", email="admin@x.test",
            outcome=outcome, ip="10.0.0.9",
        )
    check_login_allowed(db, email="admin@x.test", ip="10.0.0.9", config=cfg)
    # the control: the same number of LOGIN failures does lock
    for _ in range(3):
        record_auth_event(
            db, event_type="login_otp", email="admin@x.test",
            outcome="failure", ip="10.0.0.9", detail="bad code",
        )
    with pytest.raises(LoginLocked):
        check_login_allowed(db, email="admin@x.test", ip="10.0.0.9", config=cfg)
