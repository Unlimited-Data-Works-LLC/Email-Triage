"""N-539 / N-540 — the witnessed writes, measured through the real routes and
the funnels (PD-17: the rendered view, not only the model).

N-539 (punch 544): a watch-group save or delete that touches a NON-OWNER HIPAA
account writes one ``access_log`` row per such account, in the same transaction
as the watch rows. The route filters non-owner HIPAA accounts out of the TICKED
set, so through the route the reachable case is an UNBIND: a group already
bound to such an account loses that row on edit or delete. The bind case (only
reachable through the funnel itself) is covered at the funnel, and pins that
``save_new``'s row shape is unchanged.

N-540 (punch 545): a ``config_save`` that changes the ``runtime_settings`` blob
writes one ``runtime_settings_changed`` auth event carrying the changed key
NAMES only, in the same transaction as the blob.

Every failure arm has a healthy-chain positive control beside it, so "nothing
changed" cannot pass because the request never reached the write.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from email_triage import triage_logging
from email_triage.db import audit as _audit
from email_triage.web.db import get_setting, invalidate_setting_cache, set_setting
from email_triage.web.email_watches import (
    EmailWatch, WatchActions, WatchFilter, new_watch_group_id, upsert_watch,
)

_KEY = "runtime_settings"
_KEY_BYTES = b"\x02" * 32


@pytest.fixture()
def chain(db):
    """A provisioned chain key, HIPAA mode off; restores both module globals."""
    prev_mode = triage_logging._hipaa_mode
    _audit._clear_hmac_keys_for_test()
    _audit._set_hmac_key_for_test(_KEY_BYTES, 1)
    triage_logging._hipaa_mode = False
    invalidate_setting_cache(_KEY)
    try:
        yield db
    finally:
        triage_logging._hipaa_mode = prev_mode
        _audit._clear_hmac_keys_for_test()
        invalidate_setting_cache(_KEY)


def _break_chain() -> None:
    """The rotation window: version 2 is current and its key is absent, so
    ``_chain_insert`` fails closed (Directive 12)."""
    _audit._HMAC_CURRENT_VERSION = 2
    assert _audit._get_hmac_key(2) is None, "probe setup: version 2 key present"


def _gap_helpers(db) -> list[str]:
    return [r[0] for r in db.execute("SELECT helper_name FROM audit_gap_events")]


# ---------------------------------------------------------------------------
# N-540 — config_save
# ---------------------------------------------------------------------------


def _settings_rows(db) -> list[dict]:
    return [
        json.loads(r[0]) for r in db.execute(
            "SELECT detail FROM auth_events WHERE event_type = "
            "'runtime_settings_changed' ORDER BY id"
        )
    ]


def _post_config(client, cookies, *, dry_run: bool):
    data = {"log_level": "INFO"}
    if dry_run:
        data["dry_run"] = "1"
    return client.post("/config/save", data=data, cookies=cookies,
                       follow_redirects=False)


def test_config_save_witnesses_a_changed_blob(client, chain, admin_cookies, admin_user):
    db = chain
    set_setting(db, _KEY, {"dry_run": False, "log_level": "INFO", "hipaa": False})

    resp = _post_config(client, admin_cookies, dry_run=True)

    assert resp.status_code < 400, resp.text
    invalidate_setting_cache(_KEY)
    assert get_setting(db, _KEY)["dry_run"] is True
    rows = _settings_rows(db)
    assert len(rows) == 1, rows
    assert "dry_run" in rows[0]["changed_keys"]
    assert rows[0]["settings_key"] == _KEY
    assert "true" not in json.dumps(rows[0]).lower(), (
        "N-540: the detail must carry key NAMES only, never values"
    )
    actor = db.execute(
        "SELECT user_id FROM auth_events WHERE event_type = "
        "'runtime_settings_changed'"
    ).fetchone()[0]
    assert actor == admin_user["id"]
    # PD-17 — the page that shows the saved settings still renders.
    assert client.get("/config", cookies=admin_cookies).status_code == 200


def test_config_save_with_no_change_writes_no_row(client, chain, admin_cookies):
    db = chain
    set_setting(db, _KEY, {"dry_run": False, "log_level": "INFO", "hipaa": False})
    assert _post_config(client, admin_cookies, dry_run=True).status_code < 400
    first = len(_settings_rows(db))

    assert _post_config(client, admin_cookies, dry_run=True).status_code < 400

    assert first == 1
    assert len(_settings_rows(db)) == first, "an unchanged blob was witnessed"


def test_config_save_failed_witness_leaves_the_blob_unchanged(
    client, chain, admin_cookies,
):
    db = chain
    set_setting(db, _KEY, {"dry_run": False, "log_level": "INFO", "hipaa": False})
    _break_chain()

    resp = _post_config(client, admin_cookies, dry_run=True)

    assert resp.status_code >= 500, (
        f"expected the fail-closed chain to surface as a 5xx, got {resp.status_code}"
    )
    invalidate_setting_cache(_KEY)
    assert get_setting(db, _KEY)["dry_run"] is False, (
        "N-540: dry_run committed although its witness could not be written"
    )
    assert _settings_rows(db) == []
    assert "record_runtime_settings_change" in _gap_helpers(db)


def test_settings_funnel_rolls_back_when_the_witness_raises(chain, monkeypatch):
    """Failure injection at the funnel, chain healthy: the witness raising must
    take the settings row with it."""
    db = chain
    set_setting(db, _KEY, {"dry_run": False})

    def _boom(*a, **k):
        raise RuntimeError("injected witness failure")

    monkeypatch.setattr(_audit, "record_auth_event_txn", _boom)
    with pytest.raises(RuntimeError, match="injected"):
        _audit.record_runtime_settings_change(
            db, settings_key=_KEY, new_runtime={"dry_run": True},
            actor_user_id=None, actor_email="x@example.com",
        )
    invalidate_setting_cache(_KEY)
    assert get_setting(db, _KEY) == {"dry_run": False}


def test_changed_keys_names_presence_and_first_save():
    f = _audit.runtime_settings_changed_keys
    assert f(None, {"b": 1, "a": 2}) == ["a", "b"]
    assert f({"a": 1, "b": 2}, {"a": 1, "b": 3}) == ["b"]
    assert f({"a": 1, "gone": 1}, {"a": 1, "new": 1}) == ["gone", "new"]
    assert f({"a": 1}, {"a": 1}) == []


# ---------------------------------------------------------------------------
# N-539 — watch-group save / edit / delete
# ---------------------------------------------------------------------------


def _account(db, owner_id: int, name: str, *, hipaa: bool) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
        "hipaa, is_active, created_at, updated_at) VALUES (?, ?, 'imap', '{}', ?, 1, ?, ?)",
        (owner_id, name, 1 if hipaa else 0, now, now),
    )
    db.commit()
    return cur.lastrowid


def _seed_group(db, creator_id: int, account_ids: list[int]) -> str:
    wgi = new_watch_group_id()
    for acct in account_ids:
        upsert_watch(db, EmailWatch(
            name="N-539 group", enabled=True, account_id=acct,
            filter=WatchFilter(from_addr="boss@"), actions=WatchActions(),
            watch_group_id=wgi, created_by_user_id=creator_id,
        ))
    return f"gid:{wgi}"


def _watch_rows(db, outcome: str) -> list[tuple]:
    return [
        tuple(r) for r in db.execute(
            "SELECT actor_user_id, account_id, route, detail FROM access_log "
            "WHERE outcome = ? ORDER BY id", (outcome,),
        )
    ]


@pytest.fixture()
def unbind_case(chain, regular_user, admin_user):
    """The actor's own account, another user's HIPAA account and another
    user's NON-HIPAA account in one group. An edit keeping only ``own`` (or a
    delete) removes the other two; only ``phi`` is owed a row. ``plain`` is the
    arm that makes the HIPAA half of the gate observable (panel B2 DA-1)."""
    db = chain
    own = _account(db, regular_user["id"], "own", hipaa=False)
    phi = _account(db, admin_user["id"], "phi", hipaa=True)
    plain = _account(db, admin_user["id"], "plain", hipaa=False)
    gid = _seed_group(db, regular_user["id"], [own, phi, plain])
    return db, own, phi, plain, gid


def _post_edit(client, cookies, gid: str, account_ids: list[int]):
    return client.post(
        f"/profile/watches/{gid}/save", cookies=cookies,
        data={"name": "N-539 group", "enabled": "1",
              "account_ids": [str(a) for a in account_ids],
              "from_addr": "boss@", "escalate_enabled": "1"},
        follow_redirects=False,
    )


def _rows_on(db, account_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM email_watches WHERE account_id = ?", (account_id,),
    ).fetchone()[0]


def test_edit_that_unbinds_a_non_owner_hipaa_account_is_witnessed(
    client, unbind_case, user_cookies, regular_user,
):
    db, own, phi, plain, gid = unbind_case

    resp = _post_edit(client, user_cookies, gid, [own])

    assert resp.status_code == 303, resp.text
    assert _rows_on(db, phi) == 0, "the edit did not unbind the HIPAA account"
    assert _rows_on(db, plain) == 0, "the edit did not unbind the plain account"
    rows = _watch_rows(db, "watch_save")
    assert len(rows) == 1, f"only the HIPAA account is owed a row: {rows}"
    actor, acct, route, detail = rows[0]
    assert (actor, acct) == (regular_user["id"], phi)
    assert route == "/profile/watches/{group_id}/save"
    assert json.loads(detail) == {"group_id": gid, "unbound": True}
    # PD-17 — the redirect target renders.
    assert client.get(resp.headers["location"], cookies=user_cookies).status_code == 200


def test_edit_that_touches_only_owned_accounts_writes_no_row(
    client, chain, user_cookies, regular_user,
):
    db = chain
    a = _account(db, regular_user["id"], "a", hipaa=False)
    b = _account(db, regular_user["id"], "b-own-phi", hipaa=True)
    gid = _seed_group(db, regular_user["id"], [a, b])

    assert _post_edit(client, user_cookies, gid, [a]).status_code == 303
    assert _watch_rows(db, "watch_save") == [], "owner self-access is exempt (PD#14)"


def test_edit_failed_witness_leaves_the_watch_rows_unchanged(
    client, unbind_case, user_cookies,
):
    db, own, phi, _plain, gid = unbind_case
    _break_chain()

    resp = _post_edit(client, user_cookies, gid, [own])

    assert resp.status_code >= 500, f"got {resp.status_code}; the emit did not fail"
    assert _rows_on(db, phi) == 1, (
        "N-539: the HIPAA account's watch row was deleted although its "
        "access-event witness could not be written"
    )
    assert _watch_rows(db, "watch_save") == []
    assert "record_watch_group_save" in _gap_helpers(db)


def test_delete_witnesses_each_non_owner_hipaa_account(
    client, unbind_case, user_cookies, regular_user,
):
    db, own, phi, plain, gid = unbind_case

    resp = client.post(f"/profile/watches/{gid}/delete", cookies=user_cookies,
                       follow_redirects=False)

    assert resp.status_code == 303, resp.text
    assert _rows_on(db, own) == 0 and _rows_on(db, phi) == 0 and _rows_on(db, plain) == 0
    rows = _watch_rows(db, "watch_delete")
    assert [(r[0], r[1]) for r in rows] == [(regular_user["id"], phi)], (
        "only the non-owner HIPAA account is owed a row (not own, not plain)")
    assert rows[0][2] == "/profile/watches/{group_id}/delete"
    assert json.loads(rows[0][3]) == {"group_id": gid, "unbound": True}
    assert client.get("/profile/watches", cookies=user_cookies).status_code == 200


def test_delete_failed_witness_deletes_nothing(client, unbind_case, user_cookies):
    db, own, phi, _plain, gid = unbind_case
    _break_chain()

    resp = client.post(f"/profile/watches/{gid}/delete", cookies=user_cookies,
                       follow_redirects=False)

    assert resp.status_code >= 500, f"got {resp.status_code}; the emit did not fail"
    assert _rows_on(db, own) == 1 and _rows_on(db, phi) == 1
    assert "record_watch_group_delete" in _gap_helpers(db)


def test_save_funnel_bind_row_keeps_the_save_new_shape(chain, regular_user, admin_user):
    """The bind case, at the funnel (the route never ticks a non-owner HIPAA
    account). The row is byte-for-byte what save_new wrote before N-539."""
    db = chain
    phi = _account(db, admin_user["id"], "phi", hipaa=True)
    plain = _account(db, admin_user["id"], "plain", hipaa=False)

    gid, created, deleted = _audit.record_watch_group_save(
        db, actor_user_id=regular_user["id"], group_id=None, name="n",
        enabled=True, filter_=WatchFilter(from_addr="x@"), actions=WatchActions(),
        target_account_ids=[phi, plain], route="/profile/watches/new/save",
    )

    assert len(created) == 2 and deleted == []
    rows = db.execute(
        "SELECT method, route, account_id, message_id, status_code, outcome, detail "
        "FROM access_log WHERE outcome = 'watch_save'"
    ).fetchall()
    assert [tuple(r) for r in rows] == [
        ("POST", "/profile/watches/new/save", phi, None, 200, "watch_save",
         f'{{"group_id":"{gid}"}}'),
    ]


def test_save_funnel_rolls_back_the_rows_when_the_witness_raises(
    chain, regular_user, admin_user, monkeypatch,
):
    db = chain
    phi = _account(db, admin_user["id"], "phi", hipaa=True)

    def _boom(*a, **k):
        raise RuntimeError("injected witness failure")

    monkeypatch.setattr(_audit, "record_access_event_txn", _boom)
    with pytest.raises(RuntimeError, match="injected"):
        _audit.record_watch_group_save(
            db, actor_user_id=regular_user["id"], group_id=None, name="n",
            enabled=True, filter_=WatchFilter(), actions=WatchActions(),
            target_account_ids=[phi], route="/profile/watches/new/save",
        )
    assert _rows_on(db, phi) == 0, "N-539: the watch row survived its failed witness"


def test_legacy_group_delete_records_the_creator_not_the_watch_name(
    client, chain, user_cookies, regular_user, admin_user,
):
    """hipaa-sme panel B2 F2: a legacy key is legacy:<creator>:<watch name>;
    the name is free text that can carry a patient name and access_log is
    chain-hashed and retained, so the row records legacy:<creator id> only."""
    db = chain
    own = _account(db, regular_user["id"], "own", hipaa=False)
    phi = _account(db, admin_user["id"], "phi", hipaa=True)
    for acct in (own, phi):
        upsert_watch(db, EmailWatch(
            name="PatientSmithWatch", enabled=True, account_id=acct,
            filter=WatchFilter(from_addr="boss@"), actions=WatchActions(),
            watch_group_id=None, created_by_user_id=regular_user["id"],
        ))
    legacy = f"legacy:{regular_user['id']}:PatientSmithWatch"

    resp = client.post(f"/profile/watches/{legacy}/delete", cookies=user_cookies,
                       follow_redirects=False)

    assert resp.status_code == 303, resp.text
    rows = _watch_rows(db, "watch_delete")
    assert [(r[0], r[1]) for r in rows] == [(regular_user["id"], phi)], rows
    assert json.loads(rows[0][3]) == {
        "group_id": f"legacy:{regular_user['id']}", "unbound": True}
    assert all("PatientSmith" not in (r[2] + r[3]) for r in rows), rows


def test_watch_group_audit_key():
    k = _audit._watch_group_audit_key
    assert k("gid:abc123") == "gid:abc123"
    assert k("legacy:7:Dr Smith: oncology") == "legacy:7"
    assert k("legacy:none:w-123") == "legacy:none"
