"""N-564 (punch F5) — agent-API watch scope + fire-time creator gate (PD-9).

Every arm of db-b2's probe on main 542da8bc is a test here, plus the in-scope
control arms that prove the rig can PASS. Principals: U (caller, ``user`` role,
holds the API key) owns A; V (victim) owns B (non-HIPAA) and C (``hipaa=True``).

Before the fix (main 542da8bc): the body ``account_id`` and the ``watch_id`` were
never intersected with the caller's manageable set, API-created watches stored
``created_by_user_id=None``, and ``watch_runner`` fired any matched watch with no
check that its creator may manage the account. After: the effective account is
the PATH account, cross-account watch_ids read as 404, the key holder is the
creator, and a watch fires only when its creator may manage the account.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone

import pytest

from _portal_loop import _one_portal_loop
from email_triage.web import email_watches as ew


def _now():
    return datetime.now(timezone.utc).isoformat()


def _make_user(db, email, role="user"):
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (email, email.split("@")[0], role, _now()),
    )
    db.commit()
    return {"id": cur.lastrowid, "email": email, "role": role}


def _make_account(db, user_id, *, hipaa=False, name="acct"):
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, 'imap', ?, ?, ?, ?)",
        (user_id, name,
         json.dumps({"host": "mail.example.invalid", "username": "u@example.com"}),
         1 if hipaa else 0, _now(), _now()),
    )
    db.commit()
    return cur.lastrowid


def _row(db, watch_id):
    return db.execute(
        "SELECT watch_id, account_id, name, created_by_user_id "
        "FROM email_watches WHERE watch_id = ?", (watch_id,),
    ).fetchone()


def _seed_watch(db, *, account_id, creator, name="seed", enabled=True):
    # A VALID watch (one action), so a PATCH probe that reaches the write is
    # not stopped by validation first: on main a foreign PATCH must show the
    # write itself, not a 400 (pattern: prove the input is in the set).
    w = ew.EmailWatch(
        name=name, enabled=enabled, account_id=account_id,
        created_by_user_id=creator,
        filter=ew.WatchFilter(from_addr="boss@"),
        actions=ew.WatchActions(escalate=ew.EscalateAction(enabled=True)),
    )
    ew.upsert_watch(db, w)
    return w.watch_id


_BODY = {
    "name": "w",
    "filter": {"from_addr": "boss@"},
    "actions": {"escalate": {"enabled": True}},
}


@pytest.fixture
def rig(db):
    from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
    u = _make_user(db, "u@test.com")
    v = _make_user(db, "v@test.com")
    a = _make_account(db, u["id"], name="a-of-u")
    b = _make_account(db, v["id"], name="b-of-v")
    c = _make_account(db, v["id"], hipaa=True, name="c-of-v-hipaa")
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), name="u-key", user_id=u["id"], actor_user_id=u["id"])
    return {"u": u, "v": v, "A": a, "B": b, "C": c,
            "h": {"Authorization": f"Bearer {raw}"}}


# ---------------------------------------------------------------------------
# Control arms: prove the path gate works and the in-scope create passes.
# ---------------------------------------------------------------------------


class TestControl:
    def test_path_gate_refuses_other_users_account(self, client, rig):
        for acct in (rig["B"], rig["C"]):
            r = client.post(f"/api/v1/accounts/{acct}/watches",
                            json=dict(_BODY), headers=rig["h"])
            assert r.status_code == 404, r.text

    def test_in_scope_create_binds_path_account_and_stamps_key_holder(
        self, client, db, rig,
    ):
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                        json=dict(_BODY), headers=rig["h"])
        assert r.status_code == 200, r.text
        row = _row(db, r.json()["watch_id"])
        assert row[1] == rig["A"]
        assert row[3] == rig["u"]["id"], "API-created watch must record the key holder"

    def test_explicit_body_account_equal_to_path_is_accepted(self, client, db, rig):
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                        json={**_BODY, "account_id": rig["A"]}, headers=rig["h"])
        assert r.status_code == 200, r.text
        assert _row(db, r.json()["watch_id"])[1] == rig["A"]


# ---------------------------------------------------------------------------
# Probe (a): create through the body account_id.
# ---------------------------------------------------------------------------


class TestCreateBodyAccount:
    @pytest.mark.parametrize("target", ["B", "C"])
    def test_body_account_other_than_path_is_refused(self, client, db, rig, target):
        before = db.execute("SELECT COUNT(*) FROM email_watches").fetchone()[0]
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                        json={**_BODY, "account_id": rig[target]}, headers=rig["h"])
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "account_id_must_match_path"
        after = db.execute("SELECT COUNT(*) FROM email_watches").fetchone()[0]
        assert after == before, "refused create must not write"

    def test_body_account_null_all_accounts_is_refused(self, client, db, rig):
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                        json={**_BODY, "account_id": None}, headers=rig["h"])
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "account_id_must_match_path"
        n = db.execute(
            "SELECT COUNT(*) FROM email_watches WHERE account_id IS NULL"
        ).fetchone()[0]
        assert n == 0

    def test_refusal_does_not_depend_on_target_existence(self, client, rig):
        """No existence oracle: a live foreign id and a never-issued id refuse alike."""
        r_live = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                             json={**_BODY, "account_id": rig["B"]}, headers=rig["h"])
        r_dead = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                             json={**_BODY, "account_id": 987654}, headers=rig["h"])
        assert (r_live.status_code, r_live.json()) == (r_dead.status_code, r_dead.json())

    def test_client_cannot_forge_creator_or_group(self, client, db, rig):
        r = client.post(
            f"/api/v1/accounts/{rig['A']}/watches",
            json={**_BODY, "created_by_user_id": rig["v"]["id"],
                  "watch_group_id": "victim-group"},
            headers=rig["h"],
        )
        assert r.status_code == 200, r.text
        wid = r.json()["watch_id"]
        assert _row(db, wid)[3] == rig["u"]["id"]
        assert ew.get_watch(db, wid).watch_group_id is None


# ---------------------------------------------------------------------------
# Probe (b): update / delete / test-fire act on any watch_id.
# ---------------------------------------------------------------------------


class TestForeignWatchId:
    def test_patch_other_users_watch_is_404_and_unchanged(self, client, db, rig):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"], name="v-own")
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"name": "pwned"}, headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _row(db, wid)[2] == "v-own"

    def test_delete_other_users_watch_is_404_and_kept(self, client, db, rig):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        r = client.delete(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                          headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _row(db, wid) is not None

    def test_test_fire_other_users_watch_is_404(self, client, db, rig):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches/{wid}/test-fire",
                        json={}, headers=rig["h"])
        assert r.status_code == 404, r.text

    def test_foreign_and_unknown_watch_ids_look_identical(self, client, db, rig):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        r_foreign = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                                 json={"name": "x"}, headers=rig["h"])
        r_unknown = client.patch(f"/api/v1/accounts/{rig['A']}/watches/watch_nope",
                                 json={"name": "x"}, headers=rig["h"])
        assert (r_foreign.status_code, r_foreign.json()) == (
            r_unknown.status_code, r_unknown.json())

    def test_all_accounts_legacy_row_is_not_editable_via_api(self, client, db, rig):
        wid = _seed_watch(db, account_id=None, creator=rig["u"]["id"])
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"name": "x"}, headers=rig["h"])
        assert r.status_code == 404, r.text

    def test_patch_own_watch_cannot_rebind_to_hipaa_account(self, client, db, rig):
        wid = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                          json=dict(_BODY), headers=rig["h"]).json()["watch_id"]
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"account_id": rig["C"]}, headers=rig["h"])
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "account_id_must_match_path"
        assert _row(db, wid)[1] == rig["A"]

    def test_patch_own_watch_cannot_forge_creator(self, client, db, rig):
        wid = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                          json=dict(_BODY), headers=rig["h"]).json()["watch_id"]
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"created_by_user_id": rig["v"]["id"], "name": "n2"},
                         headers=rig["h"])
        assert r.status_code == 200, r.text
        assert _row(db, wid)[2:] == ("n2", rig["u"]["id"])

    def test_in_scope_patch_and_delete_still_work(self, client, db, rig):
        wid = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                          json=dict(_BODY), headers=rig["h"]).json()["watch_id"]
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"name": "renamed"}, headers=rig["h"])
        assert r.status_code == 200 and _row(db, wid)[2] == "renamed"
        r = client.delete(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                          headers=rig["h"])
        assert r.status_code == 200 and _row(db, wid) is None


# ---------------------------------------------------------------------------
# PD-9 read side: the list must not leak other users' all-accounts watches.
# ---------------------------------------------------------------------------


class TestList:
    def test_list_hides_other_users_all_accounts_watch(self, client, db, rig):
        foreign = _seed_watch(db, account_id=None, creator=rig["v"]["id"], name="v-all")
        orphan = _seed_watch(db, account_id=None, creator=None, name="orphan-all")
        own = _seed_watch(db, account_id=None, creator=rig["u"]["id"], name="u-all")
        r = client.get(f"/api/v1/accounts/{rig['A']}/watches", headers=rig["h"])
        assert r.status_code == 200, r.text
        ids = {w["watch_id"] for w in r.json()["watches"]}
        assert foreign not in ids and orphan not in ids
        assert own in ids


# ---------------------------------------------------------------------------
# Probe (c): fire-time creator gate in watch_runner.
# ---------------------------------------------------------------------------


def _acct(db, aid):
    from email_triage.web.db import get_email_account
    return get_email_account(db, aid)


class TestFireTimeGate:
    def test_resolver_drops_watch_whose_creator_cannot_manage_account(self, db, rig):
        from email_triage.web.watch_runner import resolve_watches_for_account
        injected = _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        orphan = _seed_watch(db, account_id=rig["B"], creator=None)
        owners = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        ids = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["B"]))}
        assert injected not in ids, "creator U cannot manage B"
        assert orphan not in ids, "NULL creator must fail closed"
        assert owners in ids, "owner's own watch must still fire (control)"

    def test_resolver_drops_null_creator_on_hipaa_account(self, db, rig):
        from email_triage.web.watch_runner import resolve_watches_for_account
        orphan = _seed_watch(db, account_id=rig["C"], creator=None)
        owners = _seed_watch(db, account_id=rig["C"], creator=rig["v"]["id"])
        ids = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["C"]))}
        assert orphan not in ids and owners in ids

    def test_all_accounts_watch_fires_only_where_creator_may_manage(self, db, rig):
        from email_triage.web.watch_runner import resolve_watches_for_account
        u_all = _seed_watch(db, account_id=None, creator=rig["u"]["id"])
        on_a = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["A"]))}
        on_b = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["B"]))}
        assert u_all in on_a
        assert u_all not in on_b

    def test_delegate_created_watch_fires_until_delegation_revoked(self, db, rig):
        from email_triage.db.accounts import add_account_delegate
        from email_triage.web.watch_runner import resolve_watches_for_account
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        ids = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["B"]))}
        assert wid in ids
        db.execute("DELETE FROM account_delegates WHERE account_id = ? AND user_id = ?",
                   (rig["B"], rig["u"]["id"]))
        db.commit()
        ids = {w.watch_id for w in resolve_watches_for_account(db, _acct(db, rig["B"]))}
        assert wid not in ids

    def test_fire_one_watch_refuses_out_of_scope_creator(self, app, db, rig):
        from email_triage.web import watch_runner
        w = ew.get_watch(db, _seed_watch(db, account_id=rig["B"], creator=None))
        with pytest.raises(watch_runner.WatchScopeRefused):
            asyncio.run(watch_runner.fire_one_watch(
                db=db, config=app.state.config, secrets=app.state.secrets,
                watch=w, account=_acct(db, rig["B"]),
                sender="boss@example.com", subject="s",
            ))


# ---------------------------------------------------------------------------
# Re-claim: a UI save by the account owner stamps a NULL creator.
# ---------------------------------------------------------------------------


def _group_save(db, *, actor, group_id, name, targets):
    """A UI group save through the N-539 funnel, the only caller of
    ``save_watch_group_txn``."""
    from email_triage.db.audit import record_watch_group_save
    return record_watch_group_save(
        db, actor_user_id=actor, group_id=group_id, name=name, enabled=True,
        filter_=ew.WatchFilter(from_addr="boss@"), actions=ew.WatchActions(),
        target_account_ids=targets, route="/profile/watches/{group_id}/save",
    )


class TestReclaim:
    def test_ui_group_save_stamps_null_creator_but_keeps_a_real_one(self, db, rig):
        orphan = _seed_watch(db, account_id=rig["A"], creator=None, name="legacy")
        gid = f"legacy:none:{orphan}"
        assert ew.get_watch_group(db, gid, rig["u"]["id"]) is not None
        _group_save(db, actor=rig["u"]["id"], group_id=gid, name="legacy",
                    targets=[rig["A"]])
        assert _row(db, orphan)[3] == rig["u"]["id"]
        # A row that already has a creator keeps it on re-save.
        other = _make_user(db, "o@test.com")
        kept = _seed_watch(db, account_id=rig["A"], creator=other["id"], name="kept")
        g = next(g for g in ew.list_watch_groups_for_user(db, rig["u"]["id"])
                 if kept in g["watch_ids"])
        _group_save(db, actor=rig["u"]["id"], group_id=g["group_id"], name="kept",
                    targets=[rig["A"]])
        assert _row(db, kept)[3] == other["id"]

    def test_reclaim_never_stamps_a_creator_outside_the_account(
        self, db, rig, monkeypatch,
    ):
        """The stamp is gated at the write (hipaa-sme panel B2 landing L-4). The
        group query shows a NULL-creator row only to the account's owner today,
        so this widens it on purpose: if it ever lists such a row to a user who
        cannot manage the account, the save still updates the row but leaves
        the creator NULL, so the watch neither fires nor joins that user's
        listing."""
        orphan = _seed_watch(db, account_id=rig["B"], creator=None, name="v-legacy")
        gid = f"legacy:none:{orphan}"
        assert ew.get_watch_group(db, gid, rig["u"]["id"]) is None, (
            "probe premise: the real query hides V's row from U")
        widened = {"group_id": gid, "watch_group_id": None,
                   "account_ids": [rig["B"]], "watch_ids": [orphan]}
        monkeypatch.setattr(ew, "get_watch_group", lambda db, g, u: widened)
        _group_save(db, actor=rig["u"]["id"], group_id=gid, name="renamed",
                    targets=[rig["B"]])
        assert _row(db, orphan)[2:] == ("renamed", None), (
            "the save must still apply, and must not hand V's row to U")


# ---------------------------------------------------------------------------
# PD-9 at the WRITE: _upsert_watch_on_account, independent of the route checks
# (a second layer must not be the only thing a test sees).
# ---------------------------------------------------------------------------


def _api_watch(account_id, creator, watch_id="", name="api"):
    return ew.EmailWatch(
        watch_id=watch_id, name=name, enabled=True, account_id=account_id,
        created_by_user_id=creator, filter=ew.WatchFilter(from_addr="boss@"),
    )


def _count(db):
    return db.execute("SELECT COUNT(*) FROM email_watches").fetchone()[0]


class TestWriteActuator:
    def test_refuses_a_watch_bound_to_another_account(self, db, rig):
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        w = _api_watch(rig["B"], rig["u"]["id"])
        assert _upsert_watch_on_account(db, w, rig["u"]["id"], rig["A"]) is None
        assert _count(db) == 0

    def test_refuses_a_caller_who_cannot_manage_the_account(self, db, rig):
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        w = _api_watch(rig["B"], rig["u"]["id"])
        assert _upsert_watch_on_account(db, w, rig["u"]["id"], rig["B"]) is None
        assert _count(db) == 0

    def test_refuses_to_overwrite_a_row_stored_on_another_account(self, db, rig):
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"], name="v-own")
        w = _api_watch(rig["A"], rig["u"]["id"], watch_id=wid, name="pwned")
        assert _upsert_watch_on_account(db, w, rig["u"]["id"], rig["A"]) is None
        assert _row(db, wid)[1:3] == (rig["B"], "v-own")

    def test_writes_for_the_owner_and_for_a_delegate(self, db, rig):
        from email_triage.db.accounts import add_account_delegate
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        saved = _upsert_watch_on_account(
            db, _api_watch(rig["A"], rig["u"]["id"]), rig["u"]["id"], rig["A"])
        assert saved is not None and _row(db, saved.watch_id)[1] == rig["A"]
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        saved = _upsert_watch_on_account(
            db, _api_watch(rig["B"], rig["u"]["id"]), rig["u"]["id"], rig["B"])
        assert saved is not None and _row(db, saved.watch_id)[1] == rig["B"]

    def test_patch_holds_when_the_route_read_forgets_the_account(
        self, client, db, rig, monkeypatch,
    ):
        """The route's own bound read is replaced by the unscoped lookup; the
        write still refuses the foreign row."""
        from email_triage.web.routers import agent_api
        monkeypatch.setattr(agent_api, "_get_watch_on_account",
                            lambda db, wid, aid, uid: ew.get_watch(db, wid))
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"], name="v-own")
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json={"name": "pwned"}, headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _row(db, wid)[1:3] == (rig["B"], "v-own")

    def test_refuses_a_hipaa_account_even_for_its_owner(self, db, rig):
        """hipaa-sme B9 / db-sme F3: the API's HIPAA hard-off holds at the
        write itself, not only in the route."""
        from email_triage.db.accounts import add_account_delegate
        from email_triage.web.routers.agent_api import (
            _get_watch_on_account, _upsert_watch_on_account,
        )
        w = _api_watch(rig["C"], rig["v"]["id"])
        assert _upsert_watch_on_account(db, w, rig["v"]["id"], rig["C"]) is None
        add_account_delegate(db, rig["C"], rig["u"]["id"], granted_by=rig["v"]["id"])
        w = _api_watch(rig["C"], rig["u"]["id"])
        assert _upsert_watch_on_account(db, w, rig["u"]["id"], rig["C"]) is None
        assert _count(db) == 0
        wid = _seed_watch(db, account_id=rig["C"], creator=rig["v"]["id"])
        assert _get_watch_on_account(db, wid, rig["C"], rig["v"]["id"]) is None

    def test_refuses_a_disabled_caller(self, db, rig):
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (rig["u"]["id"],))
        db.commit()
        w = _api_watch(rig["A"], rig["u"]["id"])
        assert _upsert_watch_on_account(db, w, rig["u"]["id"], rig["A"]) is None
        assert _count(db) == 0

    def test_update_refuses_a_row_deleted_since_the_read(self, db, rig):
        """db-sme F6: a DELETE between the PATCH read and its write must not
        resurrect the row without its HMAC secret."""
        from email_triage.web.routers.agent_api import _upsert_watch_on_account
        w = _api_watch(rig["A"], rig["u"]["id"], watch_id="watch_gone")
        assert _upsert_watch_on_account(
            db, w, rig["u"]["id"], rig["A"], update=True) is None
        assert _row(db, "watch_gone") is None

    def test_get_watch_on_account_checks_the_requester_in_its_hop(self, db, rig):
        """db-sme F2 / DA B2: a path that names V's account resolves nothing
        for U, whatever the route did."""
        from email_triage.web.routers.agent_api import _get_watch_on_account
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        assert _get_watch_on_account(db, wid, rig["B"], rig["u"]["id"]) is None
        assert _get_watch_on_account(db, wid, rig["B"], rig["v"]["id"]) is not None


# ---------------------------------------------------------------------------
# A route that forgets its own scope (DA M15 / db-sme P4): every arm must
# still refuse at its actuator. The route layer is tested on its own below,
# so neither layer is the only thing a test sees.
# ---------------------------------------------------------------------------


@pytest.fixture
def route_scope_forgotten(monkeypatch):
    from email_triage.web.routers import agent_api
    monkeypatch.setattr(agent_api, "_scope_to_user", lambda db, user, acct: True)


def _seed_hooked(db, *, account_id, creator, url, name="seed"):
    w = ew.EmailWatch(
        name=name, enabled=True, account_id=account_id, created_by_user_id=creator,
        filter=ew.WatchFilter(from_addr="boss@"),
        actions=ew.WatchActions(
            escalate=ew.EscalateAction(enabled=True),
            webhook=ew.WebhookAction(enabled=bool(url), url=url),
        ),
    )
    ew.upsert_watch(db, w)
    return w.watch_id


def _key_for(db, user_id, name):
    from email_triage.web.auth import generate_api_key, hash_api_key, store_api_key
    raw = generate_api_key()
    store_api_key(db, hash_api_key(raw), name=name, user_id=user_id, actor_user_id=user_id)
    return {"Authorization": f"Bearer {raw}"}


class TestRouteScopeForgotten:
    def test_route_scope_alone_refuses_a_foreign_account(self, db, rig):
        """The route layer by itself (M15 turns it off)."""
        from email_triage.web.db import get_email_account
        from email_triage.web.routers.agent_api import _scope_to_user
        assert _scope_to_user(db, rig["u"], get_email_account(db, rig["B"])) is False
        assert _scope_to_user(db, rig["u"], get_email_account(db, rig["A"])) is True

    def test_create(self, client, db, rig, route_scope_forgotten):
        r = client.post(f"/api/v1/accounts/{rig['B']}/watches",
                        json=dict(_BODY), headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _count(db) == 0

    def test_patch(self, client, db, rig, route_scope_forgotten):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"], name="v-own")
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"name": "pwned"}, headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _row(db, wid)[2] == "v-own"

    def test_delete(self, client, db, rig, route_scope_forgotten):
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        r = client.delete(f"/api/v1/accounts/{rig['B']}/watches/{wid}", headers=rig["h"])
        assert r.status_code == 404, r.text
        assert _row(db, wid) is not None

    def test_test_fire(self, client, db, rig, route_scope_forgotten, monkeypatch):
        sent = _capture_sends(monkeypatch)
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        r = client.post(f"/api/v1/accounts/{rig['B']}/watches/{wid}/test-fire",
                        json={}, headers=rig["h"])
        assert r.status_code == 404, r.text
        assert sent == {"escalate": [], "webhook": []}

    def test_list(self, client, db, rig, route_scope_forgotten):
        _seed_hooked(db, account_id=rig["B"], creator=rig["v"]["id"],
                     url="http://192.168.1.77/v-hook")
        r = client.get(f"/api/v1/accounts/{rig['B']}/watches", headers=rig["h"])
        assert r.status_code == 404, r.text
        assert "v-hook" not in r.text


# ---------------------------------------------------------------------------
# PATCH rules at the write actuator: no API re-claim (hipaa-sme B7 / DA B1);
# only the creator or the owner changes a webhook (hipaa-sme A7 / DA F1).
# ---------------------------------------------------------------------------


class TestPatchRules:
    def test_patch_to_an_unattributed_row_is_409_and_writes_nothing(self, client, db, rig):
        planted = _seed_hooked(db, account_id=rig["B"], creator=None,
                               url="http://192.168.1.66/attacker-hook", name="looks-legit")
        hv = _key_for(db, rig["v"]["id"], "v-key")
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{planted}",
                         json={"name": "renamed"}, headers=hv)
        assert r.status_code == 409, r.text
        assert r.json()["detail"]["error"] == "watch_unattributed"
        assert _row(db, planted)[2:] == ("looks-legit", None), (
            "a refused PATCH must neither rename nor re-claim the row")

    def test_delegate_cannot_point_the_owners_webhook_at_itself(self, client, db, rig):
        from email_triage.db.accounts import add_account_delegate
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        wid = _seed_hooked(db, account_id=rig["B"], creator=rig["v"]["id"],
                           url="http://192.168.1.10/v-hook")
        r = client.patch(
            f"/api/v1/accounts/{rig['B']}/watches/{wid}",
            json={"actions": {"escalate": {"enabled": True},
                              "webhook": {"enabled": True,
                                          "url": "http://192.168.1.66/u-hook"}}},
            headers=rig["h"])
        assert r.status_code == 403, r.text
        assert r.json()["detail"]["error"] == "not_watch_creator"
        assert ew.get_watch(db, wid).actions.webhook.url == "http://192.168.1.10/v-hook"

    def test_delegate_may_change_a_non_webhook_field(self, client, db, rig):
        from email_triage.db.accounts import add_account_delegate
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        wid = _seed_hooked(db, account_id=rig["B"], creator=rig["v"]["id"],
                           url="http://192.168.1.10/v-hook")
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"name": "renamed"}, headers=rig["h"])
        assert r.status_code == 200, r.text
        assert ew.get_watch(db, wid).actions.webhook.url == "http://192.168.1.10/v-hook"

    def test_owner_and_creator_may_change_the_webhook(self, client, db, rig):
        from email_triage.db.accounts import add_account_delegate
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        hv = _key_for(db, rig["v"]["id"], "v-key")
        body = {"actions": {"escalate": {"enabled": True},
                            "webhook": {"enabled": True, "url": "http://192.168.1.11/new"}}}
        owners = _seed_hooked(db, account_id=rig["B"], creator=rig["u"]["id"],
                              url="http://192.168.1.10/old")
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{owners}",
                         json=body, headers=hv)
        assert r.status_code == 200, r.text
        mine = _seed_hooked(db, account_id=rig["B"], creator=rig["u"]["id"],
                            url="http://192.168.1.10/old")
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{mine}",
                         json=body, headers=rig["h"])
        assert r.status_code == 200, r.text
        assert ew.get_watch(db, mine).actions.webhook.url == "http://192.168.1.11/new"


# ---------------------------------------------------------------------------
# A disabled creator manages nothing (hipaa-sme B1 / db-sme F4).
# ---------------------------------------------------------------------------


class TestDisabledCreator:
    def test_disabled_delegates_watch_is_refused_and_restored_on_re_enable(
        self, app, db, rig,
    ):
        from email_triage.db.accounts import add_account_delegate
        from email_triage.web import watch_runner
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        resolve = watch_runner.resolve_watches_for_account
        assert wid in {w.watch_id for w in resolve(db, _acct(db, rig["B"]))}
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (rig["u"]["id"],))
        db.commit()
        assert wid not in {w.watch_id for w in resolve(db, _acct(db, rig["B"]))}
        with pytest.raises(watch_runner.WatchScopeRefused):
            asyncio.run(watch_runner.fire_one_watch(
                db=db, config=app.state.config, secrets=app.state.secrets,
                watch=ew.get_watch(db, wid), account=_acct(db, rig["B"]),
                sender="boss@example.com", subject="s",
            ))
        rows = _refusal_rows(db, wid)
        assert rows and json.loads(rows[0][2])["reason"] == "creator_disabled"
        db.execute("UPDATE users SET disabled = 0 WHERE id = ?", (rig["u"]["id"],))
        db.commit()
        assert wid in {w.watch_id for w in resolve(db, _acct(db, rig["B"]))}


# ---------------------------------------------------------------------------
# Slice 2: escalate recipient, refusal audit, every path refuses, operator +
# owner visibility, access_log names the bound account.
# ---------------------------------------------------------------------------


def _seed_escalating_watch(db, *, account_id, creator, notify=""):
    w = ew.EmailWatch(
        name="esc", enabled=True, account_id=account_id, created_by_user_id=creator,
        filter=ew.WatchFilter(from_addr="boss@"),
        actions=ew.WatchActions(
            escalate=ew.EscalateAction(enabled=True, notify_email=notify),
            webhook=ew.WebhookAction(enabled=True, url="http://192.168.1.10:8080/hook"),
        ),
    )
    ew.upsert_watch(db, w)
    return w.watch_id


def _capture_sends(monkeypatch):
    from email_triage.web import watch_runner
    sent = {"escalate": [], "webhook": []}

    async def _esc(**kw):
        sent["escalate"].append(kw["notify_email"])
        return {"ok": True, "to": kw["notify_email"], "mode": "standard"}

    async def _hook(**kw):
        sent["webhook"].append(kw["url"])
        return {"url": kw["url"], "status": 200, "ok": True}

    monkeypatch.setattr(watch_runner, "_send_escalate", _esc)
    monkeypatch.setattr(watch_runner, "_post_webhook", _hook)
    return sent


class TestEscalateRecipient:
    def test_per_watch_override_is_not_a_recipient(self, app, db, rig, monkeypatch):
        from email_triage.web import watch_runner
        db.execute("UPDATE users SET notify_email = ? WHERE id = ?",
                   ("u-alerts@test.com", rig["u"]["id"]))
        db.commit()
        sent = _capture_sends(monkeypatch)
        w = ew.get_watch(db, _seed_escalating_watch(
            db, account_id=rig["A"], creator=rig["u"]["id"], notify="evil@attacker.example"))
        asyncio.run(watch_runner.fire_one_watch(
            db=db, config=app.state.config, secrets=app.state.secrets,
            watch=w, account=_acct(db, rig["A"]),
            sender="boss@example.com", subject="s",
        ))
        assert sent["escalate"] == ["u-alerts@test.com"]

    def test_api_refuses_a_per_watch_recipient_and_stores_nothing(self, client, db, rig):
        """DA F4 (PD-8): refused loudly, not silently dropped with a 200."""
        body = {**_BODY, "actions": {"escalate": {
            "enabled": True, "notify_email": "evil@attacker.example"}}}
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches", json=body, headers=rig["h"])
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "notify_email_not_settable"
        assert _count(db) == 0
        wid = client.post(f"/api/v1/accounts/{rig['A']}/watches",
                          json=dict(_BODY), headers=rig["h"]).json()["watch_id"]
        r = client.patch(f"/api/v1/accounts/{rig['A']}/watches/{wid}",
                         json=body, headers=rig["h"])
        assert r.status_code == 400, r.text
        assert r.json()["detail"]["error"] == "notify_email_not_settable"
        assert ew.get_watch(db, wid).actions.escalate.notify_email == ""

    def test_api_never_shows_a_legacy_per_watch_recipient(self, client, db, rig):
        _seed_escalating_watch(db, account_id=rig["A"], creator=rig["u"]["id"],
                               notify="legacy@old.example")
        r = client.get(f"/api/v1/accounts/{rig['A']}/watches", headers=rig["h"])
        assert r.status_code == 200, r.text
        assert "legacy@old.example" not in r.text
        assert r.json()["watches"][0]["actions"]["escalate"]["notify_email"] == ""

    def test_hipaa_escalate_sends_first_name_and_category_only(self, monkeypatch):
        from types import SimpleNamespace
        from email_triage.web import smtp_send, watch_runner
        seen = {}

        def _fake_send(**kw):
            seen.update(kw)

        monkeypatch.setattr(smtp_send, "send_simple_smtp_email", _fake_send)
        smtp = SimpleNamespace(host="smtp.example", port=25, username="",
                               from_addr="t@example.com", use_tls=False, from_name="T")
        res = asyncio.run(watch_runner._send_escalate(
            config=SimpleNamespace(smtp=smtp), secrets=None,
            notify_email="owner@example.com",
            sender='"Dr. Jane Roe" <jane.roe@clinic.example>',
            subject="Biopsy result for MRN 12345", category="medical", hipaa=True,
        ))
        assert res["mode"] == "hipaa"
        assert seen["subject"] == "URGENT [medical]: New email from Jane"
        assert seen["body"] == "Open your inbox to review."
        for leak in ("Roe", "jane.roe", "clinic", "Biopsy", "12345"):
            assert leak not in seen["subject"] + seen["body"]


def _refusal_rows(db, wid):
    return db.execute(
        "SELECT account_id, message_id, detail, actor_user_id FROM access_log "
        "WHERE route = ? AND outcome = 'watch_fire_refused_scope'",
        (f"/internal/watches/{wid}/fire",),
    ).fetchall()


class TestNoPathFiresAnUnattributedWatch:
    def test_message_path_refuses_and_audits_once(self, app, db, rig, monkeypatch):
        from email_triage.web import watch_runner
        sent = _capture_sends(monkeypatch)
        wid = _seed_escalating_watch(db, account_id=rig["A"], creator=None)
        for _ in range(3):
            out = asyncio.run(watch_runner.fire_watches_for_message(
                db=db, config=app.state.config, secrets=app.state.secrets,
                account=_acct(db, rig["A"]), sender="boss@example.com",
                subject="s", message_id="m-1",
            ))
            assert out == []
        assert sent == {"escalate": [], "webhook": []}
        rows = _refusal_rows(db, wid)
        assert len(rows) == 1, "one audit row per watch per day, not per fire"
        acct_id, msg_id, detail, actor = rows[0]
        d = json.loads(detail)
        assert acct_id == rig["A"] and msg_id is None and actor is None
        assert set(d) == {"watch_id", "account_id", "creator", "reason"}
        assert d["creator"] is None and d["reason"] == "creator_unattributed"
        assert "esc" not in detail, "no watch name in the audit detail"

    def test_direct_fire_refuses_without_sending(self, app, db, rig, monkeypatch):
        from email_triage.web import watch_runner
        sent = _capture_sends(monkeypatch)
        w = ew.get_watch(db, _seed_escalating_watch(db, account_id=rig["A"], creator=None))
        with pytest.raises(watch_runner.WatchScopeRefused):
            asyncio.run(watch_runner.fire_one_watch(
                db=db, config=app.state.config, secrets=app.state.secrets,
                watch=w, account=_acct(db, rig["A"]), sender="boss@x", subject="s"))
        assert sent == {"escalate": [], "webhook": []}
        assert len(_refusal_rows(db, w.watch_id)) == 1

    def test_api_test_fire_refuses_with_409(self, client, db, rig, monkeypatch):
        sent = _capture_sends(monkeypatch)
        wid = _seed_escalating_watch(db, account_id=rig["A"], creator=None)
        r = client.post(f"/api/v1/accounts/{rig['A']}/watches/{wid}/test-fire",
                        json={}, headers=rig["h"])
        assert r.status_code == 409, r.text
        assert sent == {"escalate": [], "webhook": []}


class TestRefusalLogVolume:
    def test_warning_only_when_the_audit_row_is_written(self, db, rig, monkeypatch):
        """hipaa-sme B8 / db-sme F5: repeat refusals log at DEBUG (not
        persisted to the chained log_entries), not WARNING."""
        from email_triage.web import watch_runner
        calls = {"warning": 0, "debug": 0}
        monkeypatch.setattr(watch_runner.log, "warning",
                            lambda *a, **k: calls.__setitem__("warning", calls["warning"] + 1))
        monkeypatch.setattr(watch_runner.log, "debug",
                            lambda *a, **k: calls.__setitem__("debug", calls["debug"] + 1))
        wid = _seed_watch(db, account_id=rig["A"], creator=None)
        for _ in range(3):
            watch_runner.resolve_watches_for_account(db, _acct(db, rig["A"]))
        assert len(_refusal_rows(db, wid)) == 1
        assert calls == {"warning": 1, "debug": 2}, calls

    def test_one_audit_row_per_account_for_an_all_accounts_row(self, db, rig):
        """hipaa-sme A3: a refused all-accounts row names every account."""
        from email_triage.web import watch_runner
        wid = _seed_watch(db, account_id=None, creator=None)
        for aid in (rig["A"], rig["B"], rig["A"]):
            watch_runner.resolve_watches_for_account(db, _acct(db, aid))
        assert sorted(r[0] for r in _refusal_rows(db, wid)) == sorted([rig["A"], rig["B"]])


class TestOperatorAlert:
    def test_probe_counts_every_refused_account_bound_watch(self, db, rig):
        from email_triage.db.accounts import add_account_delegate
        from email_triage.web.admin_alerts import (
            EVENT_REGISTRY, _assemble_watch_unattributed_alert,
        )
        evt = EVENT_REGISTRY["watch_unattributed"]
        assert evt.probe_db_fn(db) == (False, {
            "count": 0, "unattributed": 0, "reason": "watches_not_firing"})
        _seed_watch(db, account_id=rig["A"], creator=None, name="secret-name")
        _seed_watch(db, account_id=rig["A"], creator=None, enabled=False)
        add_account_delegate(db, rig["B"], rig["u"]["id"], granted_by=rig["v"]["id"])
        _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        db.execute("DELETE FROM account_delegates WHERE account_id = ? AND user_id = ?",
                   (rig["B"], rig["u"]["id"]))
        db.commit()
        active, ctx = evt.probe_db_fn(db)
        assert active and (ctx["count"], ctx["unattributed"]) == (2, 1)
        html, text = _assemble_watch_unattributed_alert(ctx)
        assert "2 enabled watch" in text and "saves the watch" in text
        assert "creates it again" in text
        assert "secret-name" not in html + text

    def test_all_accounts_unattributed_rows_are_not_counted_and_are_kept(self, db, rig):
        """DA F3: no owner can re-save an all-accounts row, so it must not hold
        the alert open; it is kept (its webhook URL is lookback evidence)."""
        from email_triage.web.admin_alerts import EVENT_REGISTRY
        z = _seed_hooked(db, account_id=None, creator=None, url="http://192.168.1.66/z")
        assert EVENT_REGISTRY["watch_unattributed"].probe_db_fn(db)[0] is False
        assert _row(db, z) is not None

    def test_the_real_event_reaches_send_through_the_state_machine(self, db, rig):
        """DA F5-test: drive the registered event itself, so the
        probe_reads_db branch of the state machine is exercised."""
        from datetime import datetime, timezone
        from email_triage.web import admin_alerts
        from email_triage.web.db import delete_setting
        try:
            delete_setting(db, admin_alerts._settings_key("watch_unattributed"))
        except Exception:
            pass
        _seed_watch(db, account_id=rig["A"], creator=None)
        action, ctx = admin_alerts._decide_action_and_stamp_pre(
            admin_alerts.WATCH_UNATTRIBUTED_EVENT, object(), db,
            datetime.now(timezone.utc),
        )
        assert action == admin_alerts._ACTION_SEND_PENDING, action
        assert ctx["count"] == 1


class TestOwnerView:
    def _owner_rig(self, db, regular_user):
        db.execute("UPDATE users SET notify_email = ? WHERE id = ?",
                   ("me-alerts@test.com", regular_user["id"]))
        db.commit()
        aid = _make_account(db, regular_user["id"], name="mine")
        wid = _seed_escalating_watch(db, account_id=aid, creator=None,
                                     notify="evil@attacker.example")
        return aid, wid

    def test_watch_list_says_not_firing(self, client, db, regular_user,
                                        user_cookies, strict_undefined_templates):
        self._owner_rig(db, regular_user)
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert "Not firing" in r.text and "save to reactivate" in r.text
        assert "/admin" not in r.text.split("Not firing")[1][:200]

    def test_edit_form_shows_effective_recipient_and_webhook(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        _aid, wid = self._owner_rig(db, regular_user)
        r = client.get(f"/profile/watches/legacy:none:{wid}/edit", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert "Alerts go to:" in r.text and "me-alerts@test.com" in r.text
        assert "evil@attacker.example" not in r.text
        assert "http://192.168.1.10:8080/hook" in r.text

    def test_edit_form_hides_the_recipient_of_an_account_the_user_cannot_manage(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        """PD-9 read side. A group lists rows the user CREATED, including one on
        an account they no longer manage (a revoked delegation); the fallback
        recipient there is that account owner's own profile address."""
        owner = _make_user(db, "owner@test.com")
        db.execute("UPDATE users SET notify_email = ? WHERE id = ?",
                   ("owner-private@test.com", owner["id"]))
        db.commit()
        theirs = _make_account(db, owner["id"], name="theirs")
        wid = _seed_escalating_watch(db, account_id=theirs, creator=regular_user["id"])
        g = next(g for g in ew.list_watch_groups_for_user(db, regular_user["id"])
                 if wid in g["watch_ids"])
        r = client.get(f"/profile/watches/{g['group_id']}/edit", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert "No notification address is set yet" in r.text, (
            "probe premise: the edit form rendered its recipient line")
        assert "owner-private@test.com" not in r.text

    def test_edit_form_opens_and_names_the_webhook_of_an_unattributed_watch(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        """hipaa-sme B7(b) / DA B1: a save re-claims it, so the webhook is
        shown open and named first (a collapsed field is not shown)."""
        _aid, wid = self._owner_rig(db, regular_user)
        r = client.get(f"/profile/watches/legacy:none:{wid}/edit", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert "<details open" in r.text
        warn = r.text.split('class="watch-reclaim-warning"')[1][:600]
        assert "no recorded owner" in warn and "http://192.168.1.10:8080/hook" in warn

    def test_edit_form_keeps_the_webhook_collapsed_for_an_attributed_watch(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        aid = _make_account(db, regular_user["id"], name="mine")
        wid = _seed_escalating_watch(db, account_id=aid, creator=regular_user["id"])
        g = next(g for g in ew.list_watch_groups_for_user(db, regular_user["id"])
                 if wid in g["watch_ids"])
        r = client.get(f"/profile/watches/{g['group_id']}/edit", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert "<details open" not in r.text
        assert "watch-reclaim-warning" not in r.text

    def test_list_says_not_firing_for_a_revoked_or_disabled_creator(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        """PD-18 (hipaa-sme B1 extension / DA F2): every refusal reason shows."""
        from email_triage.db.accounts import add_account_delegate
        aid = _make_account(db, regular_user["id"], name="mine")
        gone = _make_user(db, "gone@test.com")
        off = _make_user(db, "off@test.com")
        for who in (gone, off):
            add_account_delegate(db, aid, who["id"], granted_by=regular_user["id"])
        w_gone = _seed_watch(db, account_id=aid, creator=gone["id"], name="by-gone")
        w_off = _seed_watch(db, account_id=aid, creator=off["id"], name="by-off")
        r = client.get("/profile/watches", cookies=user_cookies)
        assert "Not firing" not in r.text, "control: both delegates still have access"
        db.execute("DELETE FROM account_delegates WHERE account_id = ? AND user_id = ?",
                   (aid, gone["id"]))
        db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (off["id"],))
        db.commit()
        groups = {g["watch_ids"][0]: g for g in
                  ew.list_watch_groups_for_user(db, regular_user["id"])}
        assert groups[w_gone]["not_firing"] and groups[w_off]["not_firing"]
        assert not groups[w_gone]["unattributed"]
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        assert r.text.count("can no longer use this mailbox") == 2


def _audit_rows(db, route, method="POST"):
    return db.execute(
        "SELECT COUNT(*) FROM access_log WHERE method = ? AND route = ?", (method, route),
    ).fetchone()[0]


def _drain_audit(db, route, before, method="POST"):
    """The access-audit middleware writes fire-and-forget; wait (bounded) for
    this request's access_log row to land. Row-count is the liveness signal:
    a task cancelled before its INSERT leaves ``_audit_pending`` looking
    drained (punch 577). Call inside ``_one_portal_loop`` so the loop that
    drives the write outlives the response."""
    import time as _time
    deadline = _time.monotonic() + 5.0
    while _time.monotonic() < deadline:
        if _audit_rows(db, route, method) > before:
            return
        _time.sleep(0.02)
    raise AssertionError("access-audit row did not land within 5s")


class TestAccessLogNamesBoundAccount:
    @pytest.mark.parametrize("body_account", [None, "B"])
    def test_an_accepted_api_write_is_audited_under_the_account_it_binds(
        self, app, client, db, rig, body_account,
    ):
        """db-b2: on main the access_log row named the PATH account A while a
        body account_id bound the watch to B. Invariant: any accepted write is
        audited under the account the watch is bound to; a cross-account bind
        is refused and binds nothing."""
        body = dict(_BODY)
        if body_account:
            body["account_id"] = rig[body_account]
        route = f"/api/v1/accounts/{rig['A']}/watches"
        before = _audit_rows(db, route)
        with _one_portal_loop(client):
            r = client.post(route, json=body, headers=rig["h"])
            _drain_audit(db, route, before)
        if r.status_code != 200:
            assert body_account is not None, r.text
            n = db.execute("SELECT COUNT(*) FROM email_watches WHERE account_id = ?",
                           (rig[body_account],)).fetchone()[0]
            assert n == 0
            return
        bound = _row(db, r.json()["watch_id"])[1]
        row = db.execute(
            "SELECT account_id FROM access_log WHERE method = 'POST' AND route = ? "
            "ORDER BY id DESC LIMIT 1",
            (f"/api/v1/accounts/{rig['A']}/watches",),
        ).fetchone()
        assert row is not None, "the middleware wrote no access_log row"
        assert row[0] == bound, f"audit names account {row[0]}, watch bound to {bound}"


# ---------------------------------------------------------------------------
# Punch 578 (hipaa-sme F5 A2, PD-14): on a HIPAA-effective account a watch
# fires only when its creator is the account owner. Fail-closed, in the one
# gate (watch_runner.watch_fire_refusal), so every fire path inherits it.
# ---------------------------------------------------------------------------


def _delegate(db, account_id, user_id, owner_id):
    from email_triage.db.accounts import add_account_delegate
    add_account_delegate(db, account_id, user_id, granted_by=owner_id)


def _set_account_hipaa(db, account_id, on):
    db.execute("UPDATE email_accounts SET hipaa = ? WHERE id = ?",
               (1 if on else 0, account_id))
    db.commit()


def _fires_on(db, aid):
    from email_triage.web.watch_runner import resolve_watches_for_account
    return {w.watch_id for w in resolve_watches_for_account(db, _acct(db, aid))}


class TestHipaaOwnerOnly:
    def test_delegate_watch_on_a_hipaa_account_is_refused_owner_watch_fires(
        self, app, db, rig, monkeypatch,
    ):
        from email_triage.web import watch_runner
        sent = _capture_sends(monkeypatch)
        _delegate(db, rig["C"], rig["u"]["id"], rig["v"]["id"])
        theirs = _seed_escalating_watch(db, account_id=rig["C"], creator=rig["u"]["id"])
        owners = _seed_escalating_watch(db, account_id=rig["C"], creator=rig["v"]["id"])
        ids = _fires_on(db, rig["C"])
        assert owners in ids, "control: the owner's own watch still fires"
        assert theirs not in ids, "a delegate's watch must not fire on a HIPAA account"
        rows = _refusal_rows(db, theirs)
        assert len(rows) == 1
        d = json.loads(rows[0][2])
        assert d["reason"] == "creator_not_owner_hipaa" and rows[0][1] is None
        with pytest.raises(watch_runner.WatchScopeRefused):
            asyncio.run(watch_runner.fire_one_watch(
                db=db, config=app.state.config, secrets=app.state.secrets,
                watch=ew.get_watch(db, theirs), account=_acct(db, rig["C"]),
                sender="boss@example.com", subject="s"))
        assert sent == {"escalate": [], "webhook": []}

    def test_message_path_sends_nothing_for_a_delegate_watch(
        self, app, db, rig, monkeypatch,
    ):
        from email_triage.web import watch_runner
        sent = _capture_sends(monkeypatch)
        _delegate(db, rig["C"], rig["u"]["id"], rig["v"]["id"])
        _seed_escalating_watch(db, account_id=rig["C"], creator=rig["u"]["id"])
        asyncio.run(watch_runner.fire_watches_for_message(
            db=db, config=app.state.config, secrets=app.state.secrets,
            account=_acct(db, rig["C"]), sender="boss@example.com",
            subject="s", message_id="m-578"))
        assert sent == {"escalate": [], "webhook": []}

    def test_a_flip_to_hipaa_refuses_and_a_flip_back_restores(self, db, rig):
        """The account turned HIPAA after the delegate created the watch: the
        A2 state. PD-18: the clear edge is the same predicate."""
        _delegate(db, rig["B"], rig["u"]["id"], rig["v"]["id"])
        wid = _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        assert wid in _fires_on(db, rig["B"])
        _set_account_hipaa(db, rig["B"], True)
        assert wid not in _fires_on(db, rig["B"])
        _set_account_hipaa(db, rig["B"], False)
        assert wid in _fires_on(db, rig["B"])

    def test_the_system_flag_alone_makes_the_account_hipaa_effective(
        self, db, rig, monkeypatch,
    ):
        from email_triage import triage_logging
        _delegate(db, rig["B"], rig["u"]["id"], rig["v"]["id"])
        theirs = _seed_watch(db, account_id=rig["B"], creator=rig["u"]["id"])
        owners = _seed_watch(db, account_id=rig["B"], creator=rig["v"]["id"])
        monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
        ids = _fires_on(db, rig["B"])
        assert owners in ids and theirs not in ids

    def test_a_partial_account_dict_cannot_open_the_gate(self, db, rig):
        """The owner and the per-account flag come from the stored row, so a
        caller passing only ``{"id": …}`` (the display path) or a stale
        non-HIPAA dict still gets the refusal."""
        from email_triage.web.watch_runner import watch_fire_refusal, watch_row_fires
        _delegate(db, rig["C"], rig["u"]["id"], rig["v"]["id"])
        w = ew.get_watch(db, _seed_watch(db, account_id=rig["C"], creator=rig["u"]["id"]))
        stale = dict(_acct(db, rig["C"]), hipaa=0, user_id=rig["u"]["id"])
        assert watch_fire_refusal(db, w, {"id": rig["C"]}) == "creator_not_owner_hipaa"
        assert watch_fire_refusal(db, w, stale) == "creator_not_owner_hipaa"
        assert watch_row_fires(db, w) is False

    def test_a_new_reason_the_same_day_gets_its_own_row(self, db, rig):
        """One audit row per watch per account per reason per UTC day."""
        wid = _seed_watch(db, account_id=rig["C"], creator=rig["u"]["id"])
        for _ in range(2):
            _fires_on(db, rig["C"])
        _delegate(db, rig["C"], rig["u"]["id"], rig["v"]["id"])
        for _ in range(2):
            _fires_on(db, rig["C"])
        reasons = [json.loads(r[2])["reason"] for r in _refusal_rows(db, wid)]
        assert sorted(reasons) == ["creator_not_owner_hipaa", "creator_out_of_scope"]

    def test_the_admin_alert_counts_it(self, db, rig):
        from email_triage.web.email_watches import count_not_firing_watches
        _delegate(db, rig["C"], rig["u"]["id"], rig["v"]["id"])
        _seed_watch(db, account_id=rig["C"], creator=rig["u"]["id"])
        _seed_watch(db, account_id=rig["C"], creator=rig["v"]["id"])
        assert count_not_firing_watches(db) == (1, 0)

    def test_owner_list_names_the_reason_and_clears_it(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
    ):
        aid = _make_account(db, regular_user["id"], hipaa=True, name="clinic")
        helper = _make_user(db, "helper@test.com")
        _delegate(db, aid, helper["id"], regular_user["id"])
        wid = _seed_watch(db, account_id=aid, creator=helper["id"], name="by-helper")
        g = next(g for g in ew.list_watch_groups_for_user(db, regular_user["id"])
                 if wid in g["watch_ids"])
        assert g["not_firing"] and g["not_firing_reasons"] == ["creator_not_owner_hipaa"]
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        line = r.text.split('class="watch-not-firing"')[1][:400]
        assert "only watches its owner set up run on it" in line
        assert "can no longer use this mailbox" not in line and "/admin" not in line
        _set_account_hipaa(db, aid, False)
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200 and "Not firing" not in r.text


# ---------------------------------------------------------------------------
# Punch 579 (hipaa-sme F5 Q3): an error response's fixed slug rides into the
# access_log row's detail; outcome keeps its status mapping.
# ---------------------------------------------------------------------------


def _api_rows(db, method, route):
    return [tuple(r) for r in db.execute(
        "SELECT outcome, detail, status_code FROM access_log "
        "WHERE method = ? AND route = ? ORDER BY id", (method, route),
    ).fetchall()]


class TestErrorSlugInAccessLog:
    """Each request and the wait for its access_log row run on ONE held loop,
    as the punch-577 tests above do (``_one_portal_loop`` + the row-count
    ``_drain_audit``): the middleware write is fire-and-forget, and a
    per-request portal loop would cancel it."""

    @pytest.mark.parametrize("strict", [False, True], ids=["production", "strict"])
    def test_a_refused_cross_account_bind_is_findable(
        self, client, db, rig, monkeypatch, strict,
    ):
        """Both emitter arms through the real middleware: production
        (fire-and-forget, driven by the held loop) and strict (awaited)."""
        if strict:
            monkeypatch.setenv("EMAIL_TRIAGE_AUDIT_STRICT", "1")
        else:
            monkeypatch.delenv("EMAIL_TRIAGE_AUDIT_STRICT", raising=False)
        route = f"/api/v1/accounts/{rig['A']}/watches"
        before = _audit_rows(db, route, "POST")
        with _one_portal_loop(client):
            r = client.post(route, json={**_BODY, "account_id": rig["B"]}, headers=rig["h"])
            _drain_audit(db, route, before, "POST")
        assert r.status_code == 400 and r.json()["detail"]["error"] == "account_id_must_match_path"
        rows = _api_rows(db, "POST", route)
        assert len(rows) == 1, rows
        outcome, detail, status = rows[0]
        assert (outcome, status) == ("error", 400), "outcome mapping is unchanged"
        assert json.loads(detail) == {"error": "account_id_must_match_path"}

    def test_a_200_row_is_unchanged(self, client, db, rig):
        route = f"/api/v1/accounts/{rig['A']}/watches"
        before = _audit_rows(db, route, "POST")
        with _one_portal_loop(client):
            r = client.post(route, json=dict(_BODY), headers=rig["h"])
            _drain_audit(db, route, before, "POST")
        assert r.status_code == 200, r.text
        assert _api_rows(db, "POST", route) == [("ok", None, 200)]

    def test_a_free_text_error_records_no_detail(self, client, db, rig):
        route = f"/api/v1/accounts/{rig['A']}/watches/watch_nope"
        before = _audit_rows(db, route, "PATCH")
        with _one_portal_loop(client):
            r = client.patch(route, json={"name": "x"}, headers=rig["h"])
            _drain_audit(db, route, before, "PATCH")
        assert r.status_code == 404 and r.json()["detail"] == "watch not found"
        assert _api_rows(db, "PATCH", route) == [("not_found", None, 404)]

    def test_a_slug_404_keeps_not_found_and_carries_the_slug(self, client, db, rig):
        route = f"/api/v1/accounts/{rig['B']}/watches"
        before = _audit_rows(db, route, "GET")
        with _one_portal_loop(client):
            r = client.get(route, headers=rig["h"])
            _drain_audit(db, route, before, "GET")
        assert r.status_code == 404, r.text
        rows = _api_rows(db, "GET", route)
        assert len(rows) == 1 and rows[0][0] == "not_found"
        assert json.loads(rows[0][1]) == {"error": "account_not_found"}

    def test_a_success_response_never_carries_a_stashed_slug(self, app, client, db, rig):
        route = f"/api/v1/accounts/{rig['A']}/zz-579-probe"

        from starlette.responses import JSONResponse

        async def _probe(request):
            request.state.error_slug = "account_not_found"
            return JSONResponse({"ok": True})

        app.add_route(route, _probe, methods=["GET"])
        before = _audit_rows(db, route, "GET")
        try:
            with _one_portal_loop(client):
                r = client.get(route, headers=rig["h"])
                _drain_audit(db, route, before, "GET")
        finally:
            app.router.routes[:] = [
                x for x in app.router.routes if getattr(x, "path", "") != route]
        assert r.status_code == 200
        assert _api_rows(db, "GET", route) == [("ok", None, 200)]

    @pytest.mark.parametrize("slug, detail", [
        ("account_id_must_match_path", {"error": "account_id_must_match_path"}),
        ("jane.roe@clinic.example", None),
        (None, None),
    ])
    def test_the_production_write_carries_the_slug(self, db, rig, monkeypatch, slug, detail):
        from types import SimpleNamespace
        from email_triage.web.access_audit import _audit_write
        monkeypatch.delenv("EMAIL_TRIAGE_AUDIT_STRICT", raising=False)
        route = f"/api/v1/accounts/{rig['A']}/watches/prod-{len(str(slug))}"
        # _audit_write is awaited here (no fire-and-forget task), so its row
        # has landed when asyncio.run returns.
        asyncio.run(_audit_write(
            db=db, app_state=SimpleNamespace(), actor_user_id=None, method="POST",
            path=route, status_code=400, request_id=None, error_slug=slug))
        rows = _api_rows(db, "POST", route)
        assert len(rows) == 1 and rows[0][0] == "error"
        assert (json.loads(rows[0][1]) if rows[0][1] else None) == detail

    def test_only_a_member_of_the_closed_set_is_recorded(self):
        from email_triage.web.access_audit import _error_detail
        from email_triage.web.error_surface import audited_error_slug
        assert audited_error_slug("account_id_must_match_path") == "account_id_must_match_path"
        assert audited_error_slug({"error": "not_watch_creator", "message": "m"}) == "not_watch_creator"
        for value in ("watch not found", "user_not_in_the_set", "batch_too_large: 9 > cap 5",
                      {"error": "jane.roe@clinic.example"}, None, 7):
            assert audited_error_slug(value) is None, value
        assert _error_detail("jane.roe@clinic.example") is None


# ---------------------------------------------------------------------------
# Punch 580 (DA F5 fold-check): PATCH merges each ``actions`` half on its own.
# ---------------------------------------------------------------------------


_HOOK = "http://192.168.1.10/v-hook"


def _actions(db, wid):
    return ew.get_watch(db, wid).actions


class TestPatchMergesActionHalves:
    def _rig(self, db, rig):
        _delegate(db, rig["B"], rig["u"]["id"], rig["v"]["id"])
        wid = _seed_hooked(db, account_id=rig["B"], creator=rig["v"]["id"], url=_HOOK)
        return wid, _key_for(db, rig["v"]["id"], "v-key")

    @pytest.mark.parametrize("who", ["owner", "delegate"])
    def test_an_escalate_only_edit_keeps_the_webhook(self, client, db, rig, who):
        wid, hv = self._rig(db, rig)
        headers = hv if who == "owner" else rig["h"]
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"actions": {"escalate": {"channels": ["email"]}}},
                         headers=headers)
        assert r.status_code == 200, r.text
        a = _actions(db, wid)
        assert a.escalate.channels == ["email"] and a.escalate.enabled is True
        assert (a.webhook.url, a.webhook.enabled) == (_HOOK, True)

    def test_an_owner_webhook_only_edit_keeps_the_escalate_half(self, client, db, rig):
        wid, hv = self._rig(db, rig)
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"actions": {"webhook": {"url": "http://192.168.1.11/new"}}},
                         headers=hv)
        assert r.status_code == 200, r.text
        a = _actions(db, wid)
        assert (a.webhook.url, a.webhook.enabled) == ("http://192.168.1.11/new", True)
        assert a.escalate.enabled is True and a.escalate.channels == ["sms"]

    def test_a_delegate_webhook_edit_is_still_403(self, client, db, rig):
        wid, _hv = self._rig(db, rig)
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"actions": {"webhook": {"url": "http://192.168.1.66/u"}}},
                         headers=rig["h"])
        assert r.status_code == 403 and r.json()["detail"]["error"] == "not_watch_creator"
        assert _actions(db, wid).webhook.url == _HOOK

    def test_a_named_half_overlays_key_by_key(self, client, db, rig):
        wid, hv = self._rig(db, rig)
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"actions": {"webhook": {"enabled": False}}}, headers=hv)
        assert r.status_code == 200, r.text
        assert (_actions(db, wid).webhook.url, _actions(db, wid).webhook.enabled) == (_HOOK, False)

    @pytest.mark.parametrize("actions", [None, [], {"webhook": None}, {"escalate": "on"}])
    def test_a_non_object_part_is_refused_not_read_as_clear(self, client, db, rig, actions):
        wid, hv = self._rig(db, rig)
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"actions": actions}, headers=hv)
        assert r.status_code == 400 and r.json()["detail"]["error"] == "validation_errors"
        # The merge's own refusal, not validate()'s "no action" error that a
        # wiped actions object would also produce.
        assert any("must be an object" in e for e in r.json()["detail"]["errors"]), r.text
        assert _actions(db, wid).webhook.url == _HOOK

    def test_the_merge_skips_server_owned_fields(self):
        from email_triage.web.routers.agent_api import _merge_watch_patch
        stored = ew.to_dict(ew.EmailWatch(watch_id="w1", created_by_user_id=5, name="n"))
        merged, errors = _merge_watch_patch(
            stored, {"created_by_user_id": 9, "watch_id": "w2", "name": "m"})
        assert errors == [] and (merged["created_by_user_id"], merged["watch_id"],
                                 merged["name"]) == (5, "w1", "m")


# ---------------------------------------------------------------------------
# Panel B4 folds: F580-1 (filter merges one level deep), F580-2 (an unknown
# name is refused), F578-3 (an all-accounts row that fires nowhere says so).
# ---------------------------------------------------------------------------


def _seed_filtered(db, *, account_id, creator):
    w = ew.EmailWatch(
        name="filtered", enabled=True, account_id=account_id, created_by_user_id=creator,
        filter=ew.WatchFilter(from_domain="clinic.example", subject_contains="invoice"),
        actions=ew.WatchActions(escalate=ew.EscalateAction(enabled=True)),
    )
    ew.upsert_watch(db, w)
    return w.watch_id


class TestPatchMergesFilterAndRefusesUnknownNames:
    @pytest.mark.parametrize("who", ["owner", "delegate"])
    def test_a_subject_edit_keeps_the_stored_sender_criteria(self, client, db, rig, who):
        """F580-1: on 1a007bcd a subject-only PATCH erased from_domain, so the
        watch matched every sender (its webhook and alert then fired on mail
        it was never meant for)."""
        _delegate(db, rig["B"], rig["u"]["id"], rig["v"]["id"])
        wid = _seed_filtered(db, account_id=rig["B"], creator=rig["v"]["id"])
        headers = _key_for(db, rig["v"]["id"], "v-key") if who == "owner" else rig["h"]
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json={"filter": {"subject_contains": "receipt"}}, headers=headers)
        assert r.status_code == 200, r.text
        f = ew.get_watch(db, wid).filter
        assert (f.from_domain, f.subject_contains) == ("clinic.example", "receipt")

    @pytest.mark.parametrize("body", [
        {"actions": {"webhok": {"url": "http://192.168.1.66/x"}}},
        {"actions": {"webhook": {"urll": "http://192.168.1.66/x"}}},
        {"filter": {"subjet": "receipt"}},
        {"filter": "receipt"},
    ])
    def test_an_unknown_name_is_refused_not_dropped(self, client, db, rig, body):
        """F580-2 (PD-8): a typo was dropped and answered 200 as if applied."""
        wid = _seed_filtered(db, account_id=rig["B"], creator=rig["v"]["id"])
        before = ew.to_dict(ew.get_watch(db, wid))
        r = client.patch(f"/api/v1/accounts/{rig['B']}/watches/{wid}",
                         json=body, headers=_key_for(db, rig["v"]["id"], "v-key"))
        assert r.status_code == 400 and r.json()["detail"]["error"] == "validation_errors"
        assert ew.to_dict(ew.get_watch(db, wid)) == before


class TestAllAccountsRowUnderHipaa:
    def test_a_row_whose_every_account_is_hipaa_shows_not_firing(
        self, db, rig, monkeypatch,
    ):
        """F578-3: the resolver leaves all-accounts rows out on a HIPAA
        account, so under the system flag such a row fires nowhere; the
        display said it fired."""
        from email_triage import triage_logging
        from email_triage.web.watch_runner import watch_row_refusal
        w = ew.get_watch(db, _seed_watch(db, account_id=None, creator=rig["u"]["id"]))
        assert watch_row_refusal(db, w) is None, "control: U manages non-HIPAA A"
        assert w.watch_id in _fires_on(db, rig["A"])
        monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
        assert w.watch_id not in _fires_on(db, rig["A"])
        assert watch_row_refusal(db, w) == "all_accounts_hipaa"

    def test_a_creator_who_manages_only_hipaa_accounts(self, db, rig):
        from email_triage.web.watch_runner import watch_row_refusal
        only = _make_user(db, "only-hipaa@test.com")
        _make_account(db, only["id"], hipaa=True, name="only-c")
        w = ew.get_watch(db, _seed_watch(db, account_id=None, creator=only["id"]))
        assert watch_row_refusal(db, w) == "all_accounts_hipaa"
        nobody = _make_user(db, "nobody@test.com")
        w2 = ew.get_watch(db, _seed_watch(db, account_id=None, creator=nobody["id"]))
        assert watch_row_refusal(db, w2) == "creator_out_of_scope"

    def test_owner_list_names_it(
        self, client, db, regular_user, user_cookies, strict_undefined_templates,
        monkeypatch,
    ):
        from email_triage import triage_logging
        _make_account(db, regular_user["id"], name="mine")
        _seed_watch(db, account_id=None, creator=regular_user["id"], name="everywhere")
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200 and "Not firing" not in r.text, "control"
        monkeypatch.setattr(triage_logging, "_hipaa_mode", True)
        r = client.get("/profile/watches", cookies=user_cookies)
        assert r.status_code == 200, r.text[:500]
        line = r.text.split('class="watch-not-firing"')[1][:400]
        assert "set for all mailboxes" in line
        assert "can no longer use this mailbox" not in line
