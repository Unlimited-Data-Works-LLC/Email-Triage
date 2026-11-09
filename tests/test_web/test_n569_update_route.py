"""Punch 569 D3 — ``POST /config/ai-backends/embedding-update`` through the real app.

The route is the ONE action behind the [Update embedding runtime] button. The
pins here are the ones a unit test of ``update_runtime`` cannot see: the admin
tier, CSRF, and the N-543 witness-first audit shape (an INTENT row committed
BEFORE anything changes; the update refused, visibly, if it cannot be written;
an OUTCOME row naming the restart when one is needed).
"""

from __future__ import annotations

import sqlite3
import time

import pytest

from _portal_loop import _one_portal_loop

from email_triage import embedding_bits as eb
from email_triage.web.auth import SESSION_COOKIE_NAME

ROUTE = "/config/ai-backends/embedding-update"


def _rows(db, outcome: str | None = None) -> list[tuple[str, str]]:
    sql = "SELECT outcome, detail FROM auth_events WHERE event_type = ?"
    params: list = ["embedding_runtime_update"]
    if outcome is not None:
        sql += " AND outcome = ?"
        params.append(outcome)
    return [tuple(r) for r in db.execute(sql + " ORDER BY id", params).fetchall()]


def _wait_for_row(db, outcome: str, timeout: float = 10.0) -> None:
    """Wait for the background update's OUTCOME row. Call inside
    ``_one_portal_loop`` (tests/_portal_loop.py, punch 577): the loop that runs
    the route's fire-and-forget ``_run`` must outlive the response, as
    uvicorn's single loop does in production, or the task is cancelled when the
    per-request portal closes and the row never lands. The row is the liveness
    signal (a cancelled task also reads as done)."""
    from email_triage.web.db_writelock import get_write_lock

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with get_write_lock():  # the app writes this connection off-thread
            if _rows(db, outcome):
                return
        time.sleep(0.02)
    raise AssertionError(f"no {outcome!r} embedding_runtime_update row within {timeout}s")


@pytest.fixture
def no_runtime(tmp_path, monkeypatch):
    monkeypatch.setattr(eb, "DEFAULT_RUNTIME_DEPS", str(tmp_path / "rdeps"))
    eb.invalidate_runtime_ready_cache()


def test_the_update_route_is_admin_only(client, user_cookies, no_runtime):
    client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
    resp = client.post(ROUTE)
    assert resp.status_code == 403, resp.status_code


def test_the_update_route_denies_anonymous(client, no_runtime):
    resp = client.post(ROUTE, follow_redirects=False)
    assert resp.status_code in (303, 401, 403), resp.status_code


def test_the_update_route_requires_a_csrf_token(raw_client, admin_cookies, no_runtime, monkeypatch):
    entered: list[bool] = []
    from email_triage.web import embedding_update_runner as ei
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: entered.append(True))
    raw_client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    resp = raw_client.post(ROUTE, follow_redirects=False)
    assert resp.status_code == 403, resp.status_code
    assert not entered


def test_the_intent_row_is_durable_before_the_update_runs(
    app, client, db, admin_cookies, no_runtime, monkeypatch,
):
    from email_triage.web import embedding_update_runner as ei

    calls: list[tuple[str, str]] = []
    real_emit = ei.record_auth_event

    def spy_emit(conn, **kw):
        calls.append(("audit", kw.get("outcome", "")))
        return real_emit(conn, **kw)

    def fake_update(**kw):
        calls.append(("update", ""))
        assert _rows(db, "attempt"), "the intent row must be durable first"
        return eb.UpdateResult(status="updated", to_set_version=2,
                               restart_required=True, loaded_modules=["torch"])

    monkeypatch.setattr(ei, "record_auth_event", spy_emit)
    monkeypatch.setattr(ei, "update_runtime", fake_update)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    with _one_portal_loop(client):
        resp = client.post(ROUTE, headers={"HX-Request": "true"})
        assert resp.status_code == 200, resp.text
        _wait_for_row(db, "success")
    assert calls[:2] == [("audit", "attempt"), ("update", "")], calls
    success = _rows(db, "success")
    assert success, _rows(db)
    assert eb.RESTART_MESSAGE in success[-1][1], (
        "D4: the audit row must say exactly how to load the new runtime"
    )


def test_a_failed_update_is_recorded_as_a_failure(
    app, client, db, admin_cookies, no_runtime, monkeypatch,
):
    from email_triage.web import embedding_update_runner as ei
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: eb.UpdateResult(
        status="failed", error_class="HashMismatch",
    ))
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    with _one_portal_loop(client):
        client.post(ROUTE, headers={"HX-Request": "true"})
        _wait_for_row(db, "failure")
    failures = _rows(db, "failure")
    assert failures and "HashMismatch" in failures[-1][1]
    assert "previous set is unchanged" in failures[-1][1]


@pytest.mark.parametrize("htmx", [True, False], ids=["htmx", "plain"])
@pytest.mark.audit_failure_expected(
    match='embedding_install_audit event=embedding_runtime_update outcome=attempt',
    count=1,
)
def test_a_failed_intent_write_refuses_the_update(
    client, db, admin_cookies, no_runtime, monkeypatch, htmx,
):
    from email_triage.web import embedding_update_runner as ei

    real_emit = ei.record_auth_event
    entered: list[bool] = []

    def failing_intent(conn, **kw):
        if kw.get("outcome") == "attempt":
            raise sqlite3.OperationalError("disk I/O error")
        return real_emit(conn, **kw)

    monkeypatch.setattr(ei, "record_auth_event", failing_intent)
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: entered.append(True))
    before = eb.get_install_status(db)["status"]
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    headers = {"HX-Request": "true"} if htmx else {}
    resp = client.post(ROUTE, headers=headers, follow_redirects=False)
    assert not entered
    assert eb.get_install_status(db)["status"] == before
    flat = " ".join(resp.text.split())
    assert "Nothing was changed: the audit record of this update could not be written" in flat
    assert "disk I/O error" not in resp.text
    if htmx:
        assert resp.status_code == 200
        assert 'id="embedding-install-card"' in resp.text
    else:
        assert resp.status_code == 503
        assert "Update refused" in resp.text


def test_an_update_in_flight_refuses_a_second(
    client, db, admin_cookies, no_runtime, monkeypatch,
):
    from email_triage.web import embedding_update_runner as ei
    entered: list[bool] = []
    monkeypatch.setattr(ei, "update_runtime", lambda **kw: entered.append(True))
    eb._update_state(db, status="downloading")
    db.commit()
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    resp = client.post(ROUTE, headers={"HX-Request": "true"})
    assert not entered
    assert "already in progress" in " ".join(resp.text.split())
    assert _rows(db, "failure")


def test_an_update_in_flight_refuses_an_install(
    client, db, admin_cookies, no_runtime, monkeypatch,
):
    """The row's in-flight status is released by the install step BEFORE the
    swap, so the install routes also ask ``update_in_progress``."""
    from email_triage.web.routers.ui import embedding_install as ei
    spawned: list[bool] = []

    async def fake_install(**kw):
        spawned.append(True)

    monkeypatch.setattr(ei, "install_auto", fake_install)
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    assert eb._update_lock.acquire(blocking=False)
    try:
        client.post(
            "/config/ai-backends/embedding-install", headers={"HX-Request": "true"},
        )
    finally:
        eb._update_lock.release()
    assert not spawned
    rows = db.execute(
        "SELECT detail FROM auth_events WHERE event_type = ?",
        ("embedding_install_start",),
    ).fetchall()
    assert any("already in flight" in r[0] for r in rows)


def test_an_update_in_flight_refuses_a_sideload(
    client, db, admin_cookies, no_runtime, monkeypatch, tmp_path,
):
    """The sideload route has its own copy of the in-flight check (mutant M16b
    survived until this arm existed)."""
    from email_triage.web.routers.ui import embedding_install as ei
    spawned: list[bool] = []

    async def fake_sideload(**kw):
        spawned.append(True)

    monkeypatch.setattr(ei, "install_sideload", fake_sideload)
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    assert eb._update_lock.acquire(blocking=False)
    try:
        client.post(
            "/config/ai-backends/embedding-sideload",
            data={"source_dir": str(bundle)},
            headers={"HX-Request": "true"},
        )
    finally:
        eb._update_lock.release()
    assert not spawned
    rows = db.execute(
        "SELECT detail FROM auth_events WHERE event_type = ?",
        ("embedding_install_start",),
    ).fetchall()
    assert any("already in flight" in r[0] for r in rows), rows
