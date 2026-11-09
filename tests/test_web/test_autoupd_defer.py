"""Operator ruling R1 (2026-10-25): restart-after-load is DEFERRED, not applied.

A NON-security ``stale_ok`` update while this process has already imported from the
runtime prefix would pause embedding until a human restarts the container, which is
the operator intervention the whole change exists to remove. So the automatic
caller keeps the old set serving, records the deferral (a settings row and the
daily-health line, never silent), and applies the update at the next boot's first
sweeper tick. A SECURITY change is unaffected (a refused set is never loaded, so
the swap is always clean).

The pin the ruling asks for, "the restart-pending path is unreachable from the
automatic caller for a non-security set", has two halves here: the trigger
pre-checks the loaded predicate, and the funnel re-checks it at the swap
(``defer_if_loaded``) to close the race between the two.
"""

from __future__ import annotations

import ast
import sys
from types import SimpleNamespace

import pytest

from _embedding_runtime_fixture import make_versioned_prefix
from _pin_harness import assert_pin_has_teeth, enclosing_fn, walk_src

from email_triage import embedding_bits as eb
from email_triage.web import admin_alerts
from email_triage.web import embedding_update_runner as ru


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


class _Update:
    def __init__(self, *, result=None):
        self.calls = 0
        self.kw: dict = {}
        self.result = result

    def __call__(self, **kw):
        self.calls += 1
        self.kw = kw
        if self.result is not None:
            eb._update_state(
                kw["conn"], status="failed", current_file=None,
                last_error_class=self.result.error_class, last_error_msg="x",
            )
            return self.result
        eb._update_state(kw["conn"], status="installed", current_file=None, clear_error=True)
        return eb.UpdateResult(status="updated", from_set_version=1, to_set_version=2)


# ---------------------------------------------------------------------------
# The trigger
# ---------------------------------------------------------------------------

async def test_a_non_security_update_waits_while_the_runtime_is_loaded_here(
    db, fake_app, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    assert eb.runtime_status().state == eb.STATE_STALE_OK
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "deferred"
    assert update.calls == 0, "the update ran under a loaded runtime"
    assert _rows(db) == [], "a deferral must not claim the funnel (no INTENT row)"
    # The old set keeps serving.
    assert eb.runtime_status().serving
    # Recorded, never silent: a settings row and the notice.
    state = ru.read_auto_state(db)
    assert state["deferred"]["target"] == ru.target_of(eb.runtime_status())
    assert state["deferred"]["from_version"] == 1 and state["deferred"]["to_version"] == 2
    n = eb.update_notice()
    assert n["kind"] == "auto_deferred" and n["serving"] is True
    assert n["headline"].startswith("Embedding runtime update waits for the next restart")
    assert "applied by itself when the container next starts" in n["consequence"]
    # A second tick neither claims nor rewrites the row.
    since = state["deferred"]["since"]
    assert await ru.auto_update_once(fake_app) == "deferred"
    assert ru.read_auto_state(db)["deferred"]["since"] == since


async def test_the_next_boot_applies_the_waiting_update_and_clears_the_deferral(
    db, fake_app, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    monkeypatch.setattr(ru, "update_runtime", _Update())
    assert await ru.auto_update_once(fake_app) == "deferred"
    # A restart: a fresh process has not loaded the runtime, and its in-process
    # mirror starts empty (the durable row survives).
    eb.set_auto_update_deferred(None)
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: False)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert update.calls == 1
    assert update.kw["defer_if_loaded"] is True  # the funnel's own guard is armed
    assert ru.read_auto_state(db)["deferred"] is None
    assert eb.auto_update_deferred() is None


async def test_a_deferral_is_cleared_when_the_runtime_becomes_current_another_way(
    db, fake_app, tmp_path, monkeypatch,
):
    from _embedding_runtime_fixture import make_verified_prefix

    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    assert await ru.auto_update_once(fake_app) == "deferred"
    make_verified_prefix(tmp_path / "fixed", monkeypatch)  # an admin updated it by hand
    assert await ru.auto_update_once(fake_app) == "current"
    assert ru.read_auto_state(db)["deferred"] is None and eb.auto_update_deferred() is None


async def test_a_security_change_is_applied_even_when_the_runtime_is_loaded(
    db, fake_app, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(True,))
    assert eb.runtime_status().state == eb.STATE_REFUSED
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    assert await ru.auto_update_once(fake_app) == "updated"
    assert update.calls == 1
    assert update.kw["defer_if_loaded"] is False  # only a stale_ok set is deferrable


async def test_a_click_is_never_deferred(db, fake_app, tmp_path, monkeypatch, admin_user):
    """The admin chose: the click path keeps its pause note and applies."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: True)
    update = _Update()
    monkeypatch.setattr(ru, "update_runtime", update)
    out = await ru.apply_runtime_update(fake_app, actor=ru.UpdateActor.from_user(admin_user))
    assert out.status == "updated" and update.kw["defer_if_loaded"] is False


async def test_the_funnels_own_deferral_is_recorded_as_a_deferral_not_a_failure(
    db, fake_app, tmp_path, monkeypatch,
):
    """The race: the pre-check saw no load, then something imported the runtime
    before the swap. The funnel swaps nothing and says so."""
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    monkeypatch.setattr(ru, "_runtime_loaded_here", lambda: False)
    deferred = eb.UpdateResult(
        status="failed", error_class=eb.DEFERRED_ERROR_CLASS, retired=["staged.removing-1"],
    )
    purges: list[object] = []
    monkeypatch.setattr(ru, "schedule_tombstone_purge", lambda app: purges.append(app))
    monkeypatch.setattr(ru, "update_runtime", _Update(result=deferred))
    assert await ru.auto_update_once(fake_app) == "deferred"
    state = ru.read_auto_state(db)
    assert state["failures"] == 0, "a deferral must not start the retry backoff"
    assert state["deferred"] is not None and eb.auto_update_failure() is None
    assert eb.get_install_status(db)["status"] == "installed"  # the row is released
    rows = _rows(db)
    # Its own outcome token: a deferral is not a failure (panel T db NOTE).
    assert [r[0] for r in rows] == ["attempt", "deferred"]
    assert rows[1][1].startswith("deferred") and rows[1][2] == ru.SYSTEM_ACTOR_EMAIL
    assert len(purges) == 1  # only the staged copy was retired


# ---------------------------------------------------------------------------
# Never silent: the surfaces
# ---------------------------------------------------------------------------

def test_the_daily_health_carries_the_waiting_update_without_flipping_the_subject(
    db, app, tmp_path, monkeypatch,
):
    from email_triage.web.daily_health import _render_html, _render_text, gather_health_state

    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    eb.set_auto_update_deferred({"target": "1->2"})
    state = gather_health_state(db, app.state.config)
    er = state["embedding_runtime"]
    assert er["kind"] == "auto_deferred"
    assert not any("waits for the next restart" in r for r in state["attention_reasons"])
    for rendered in (_render_html(state, app.state.config), _render_text(state, app.state.config)):
        assert "Embedding runtime update waits for the next restart" in rendered
        assert "Click" not in rendered.split("Embedding runtime update waits")[1][:600]


def test_the_deferral_asks_for_no_click_and_sends_no_click_email(tmp_path, monkeypatch):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    eb.set_auto_update_deferred({"target": "1->2"})
    assert admin_alerts._embedding_runtime_probe() == (False, {"reason": None})
    assert admin_alerts._embedding_auto_failed_probe() == (False, {"reason": None})
    assert admin_alerts._embedding_integrity_probe() == (False, {"reason": None})


def test_the_banner_for_a_deferral_has_no_button(
    client, admin_cookies, strict_undefined_templates, tmp_path, monkeypatch,
):
    make_versioned_prefix(tmp_path, monkeypatch, steps=(False,))
    eb.set_auto_update_deferred({"target": "1->2"})
    resp = client.get("/config?tab=general", cookies=admin_cookies)
    assert resp.status_code == 200, resp.text[:600]
    flat = " ".join(resp.text.split())
    assert "Embedding runtime update waits for the next restart" in flat
    assert 'hx-post="/config/ai-backends/embedding-update"' not in resp.text


# ---------------------------------------------------------------------------
# Structural: the guard cannot be removed without a red test
# ---------------------------------------------------------------------------

_RUNNER = "web/embedding_update_runner.py"


def _runner_tree() -> ast.AST:
    for _path, rel, tree in walk_src():
        if rel == _RUNNER:
            return tree
    raise AssertionError(f"{_RUNNER} not found")


def _first_call_line(fn: ast.AST, name: str) -> int | None:
    lines = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and (getattr(n.func, "id", None) == name or getattr(n.func, "attr", None) == name)
    ]
    return min(lines) if lines else None


def deferral_guard_problems(tree: ast.AST) -> list[str]:
    """``auto_update_once`` must call the loaded predicate BEFORE it applies, and the
    funnel call in ``_finish`` must pass ``defer_if_loaded``."""
    out: list[str] = []
    # ``auto_update_once`` wraps ``_auto_update_decision`` (which releases the boot gate in a
    # ``finally``); the guard order is checked in whichever of them calls the apply.
    once = next(
        (
            n for n in ast.walk(tree)
            if isinstance(n, ast.AsyncFunctionDef)
            and n.name in ("_auto_update_decision", "auto_update_once")
            and _first_call_line(n, "apply_runtime_update") is not None
        ),
        None,
    )
    if once is None:
        return ["no auto-update decision function calls apply_runtime_update"]
    guard = _first_call_line(once, "_runtime_loaded_here")
    apply_ = _first_call_line(once, "apply_runtime_update")
    if guard is None:
        out.append("auto_update_once never calls _runtime_loaded_here")
    elif apply_ is not None and guard > apply_:
        out.append("auto_update_once applies before it checks the loaded predicate")
    finish = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef) and n.name == "_finish"), None,
    )
    kws = set()
    if finish is not None:
        for n in ast.walk(finish):
            if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "to_thread":
                kws |= {k.arg for k in n.keywords}
    if "defer_if_loaded" not in kws:
        out.append("_finish does not pass defer_if_loaded to update_runtime")
    return out


def test_the_deferral_guard_is_wired_in_both_places():
    assert deferral_guard_problems(_runner_tree()) == []


def test_the_deferral_guard_pin_has_teeth():
    from _pin_harness import parse_source

    good = parse_source(
        "async def auto_update_once(app):\n"
        "    if _runtime_loaded_here():\n        return 'deferred'\n"
        "    return await apply_runtime_update(app)\n"
        "async def _finish(app):\n"
        "    await asyncio.to_thread(update_runtime, defer_if_loaded=True)\n"
    )
    assert deferral_guard_problems(good) == []
    no_guard = parse_source(
        "async def auto_update_once(app):\n    return await apply_runtime_update(app)\n"
        "async def _finish(app):\n    await asyncio.to_thread(update_runtime, defer_if_loaded=True)\n"
    )
    late = parse_source(
        "async def auto_update_once(app):\n"
        "    x = await apply_runtime_update(app)\n"
        "    if _runtime_loaded_here():\n        return 'deferred'\n"
        "async def _finish(app):\n    await asyncio.to_thread(update_runtime, defer_if_loaded=True)\n"
    )
    no_kw = parse_source(
        "async def auto_update_once(app):\n"
        "    if _runtime_loaded_here():\n        return 'deferred'\n"
        "    return await apply_runtime_update(app)\n"
        "async def _finish(app):\n    await asyncio.to_thread(update_runtime)\n"
    )
    for bad in (no_guard, late, no_kw):
        assert deferral_guard_problems(bad) != []
    # keep the harness import honest (enclosing_fn is part of the shared toolbox)
    assert enclosing_fn is not None and assert_pin_has_teeth is not None
