"""Punch 689: an API-key revocation commits with its chained witness, or not at all.

``web/auth.py::delete_api_key`` used to commit the DELETE, then write the
``api_key_revoked`` row through a swallowing ``safe_audit_write``: a failed audit
write left a revoked key with no chained witness (fail OPEN on the record,
§164.312(b)). Now the DELETE and ``record_api_key_event_txn`` share one
transaction, the revocation edge of ``store_api_key`` (punch 627). At runtime:

(a) the witness exists after the revoke, bound to the key, its owner and the source;
(b) a failed witness leaves the key in place AND still authenticating, one
    ``audit_gap_events`` row, and raises ``ApiKeyRevokeError``;
(c) the delete and the witness run inside ONE open transaction;
(d) a refused delete is not a lost witness (no gap row); an autocommit connection
    is refused before the delete; a missing key is a no-op;
(e) the API answers 503, the UI 503 and the CLI exits 1, each saying the key was
    NOT revoked.

The static half is the REVOKE arm of ``tests/test_session_epoch_on_revoke_pin.py``
(``api_keys`` in ``_REVOKE_EVENTS``; ``test_revoke_arm_covers_api_keys_with_teeth``).
"""
from __future__ import annotations

import sqlite3

import pytest

import email_triage.db.audit as audit_mod
from email_triage.web.auth import (
    ApiKeyRevokeError,
    delete_api_key,
    generate_api_key,
    hash_api_key,
    store_api_key,
    verify_api_key,
)
from test_cli_audit import _hipaa_config_file, _parse  # noqa: F401  (fixture + parser, reused)

_WITNESS_DOWN = "audit storage exploded"


def _boom(*_a, **_kw):
    raise RuntimeError(_WITNESS_DOWN)


def _gaps(db, helper: str | None = None) -> int:
    if helper is None:
        return db.execute("SELECT COUNT(*) FROM audit_gap_events").fetchone()[0]
    return db.execute(
        "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = ?", (helper,)
    ).fetchone()[0]


def _revocations(db, key_id: int):
    return db.execute(
        "SELECT * FROM api_key_events WHERE key_id = ? AND event = 'api_key_revoked'",
        (key_id,),
    ).fetchall()


def _key_exists(db, key_id: int) -> bool:
    return db.execute("SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone() is not None


def _mint(db, admin_user, name: str = "doomed") -> tuple[int, str]:
    raw = generate_api_key()
    key_id = store_api_key(
        db, hash_api_key(raw), name, admin_user["id"],
        actor_user_id=admin_user["id"], actor_email=admin_user["email"], source="ui",
    )
    return key_id, raw


class TestDeleteApiKeyFunnel:
    def test_the_witness_binds_the_key_its_owner_and_the_source(self, db, admin_user):
        key_id, raw = _mint(db, admin_user)
        assert delete_api_key(
            db, key_id, actor_user_id=admin_user["id"],
            actor_email=admin_user["email"], source="api") is True
        (row,) = _revocations(db, key_id)
        assert row["actor_user_id"] == admin_user["id"]
        assert row["target_user_id"] == admin_user["id"]
        assert row["name"] == "doomed"
        assert row["source"] == "api"
        assert row["actor_email"] == admin_user["email"]  # punch 710
        assert not _key_exists(db, key_id)
        assert verify_api_key(db, raw) is None
        assert raw not in " ".join(str(v) for v in tuple(row))

    def test_a_sessionless_actor_is_recorded_and_the_chain_still_verifies(
            self, db, admin_user):
        """Punch 710: a CLI grant/revoke has no actor_user_id; the actor column
        carries its principal, and the stored-not-hashed column leaves the
        api_key_events chain verifying."""
        from email_triage.db.audit import list_api_key_events, verify_audit_chain
        key_id = store_api_key(
            db, hash_api_key(generate_api_key()), "cli-key", admin_user["id"],
            actor_user_id=None, actor_email="cli:triage", source="cli")
        assert delete_api_key(
            db, key_id, actor_user_id=None, actor_email="cli:triage", source="cli")
        rows = db.execute(
            "SELECT event, actor_user_id, actor_email FROM api_key_events "
            "WHERE key_id = ? ORDER BY id", (key_id,)).fetchall()
        assert [tuple(r) for r in rows] == [
            ("api_key_created", None, "cli:triage"), ("api_key_revoked", None, "cli:triage")]
        listed = [e for e in list_api_key_events(db) if e["key_id"] == key_id]
        assert {e["actor_email"] for e in listed} == {"cli:triage"}
        assert verify_audit_chain(db, "api_key_events")["intact"] is True

    def test_a_pre_v54_row_still_shows_the_joined_actor(self, db, admin_user):
        """Punch 710: a row written before the column (stored NULL, actor_user_id
        set) keeps showing the actor's address from the users join."""
        from email_triage.db.audit import list_api_key_events
        key_id = store_api_key(
            db, hash_api_key(generate_api_key()), "old-key", admin_user["id"],
            actor_user_id=admin_user["id"], actor_email=admin_user["email"], source="ui")
        db.execute("UPDATE api_key_events SET actor_email = NULL WHERE key_id = ?", (key_id,))
        db.commit()
        (ev,) = [e for e in list_api_key_events(db) if e["key_id"] == key_id]
        assert ev["actor_email"] == admin_user["email"]

    def test_the_hashed_actor_wins_the_display_and_a_differing_copy_shows_beside_it(
            self, db, admin_user):
        """Panel AB MUST (C2-display): a write to the unhashed ``actor_email`` must
        not replace the WHO resolved from the hashed ``actor_user_id``."""
        from email_triage.db.audit import list_api_key_events, verify_audit_chain
        from email_triage.web.daily_health import _api_key_actor_display
        key_id = store_api_key(
            db, hash_api_key(generate_api_key()), "web-key", admin_user["id"],
            actor_user_id=admin_user["id"], actor_email=admin_user["email"], source="ui")
        db.execute("UPDATE api_key_events SET actor_email = 'mallory@x.invalid' "
                   "WHERE key_id = ?", (key_id,))
        db.commit()
        (ev,) = [e for e in list_api_key_events(db) if e["key_id"] == key_id]
        assert ev["actor_email"] == admin_user["email"]
        assert ev["recorded_actor_email"] == "mallory@x.invalid"
        assert _api_key_actor_display(ev) == (
            f"{admin_user['email']} (recorded as mallory@x.invalid)")
        assert verify_audit_chain(db, "api_key_events")["intact"] is True

    def test_a_grant_with_no_actor_is_refused_and_leaves_a_gap(self, db, admin_user):
        """Panel AB MUST-C1 (ab-da R3-1 shape): a GRANT naming no actor is refused at
        the top of the emitter, so the key is never stored and the gap row lands."""
        from email_triage.web.auth import ApiKeyGrantError
        keys = db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
        gaps = _gaps(db)
        with pytest.raises(ApiKeyGrantError, match="unattributed grant"):
            store_api_key(
                db, hash_api_key(generate_api_key()), "nobody", admin_user["id"],
                actor_user_id=None, actor_email=None, source="cli")
        assert db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0] == keys
        assert db.execute(
            "SELECT COUNT(*) FROM api_key_events WHERE name = 'nobody'").fetchone()[0] == 0
        assert _gaps(db) == gaps + 1
        assert not db.in_transaction

    def test_a_revoke_with_no_actor_proceeds_with_a_sentinel_and_an_alarm(
            self, db, admin_user):
        """A REVOKE is never refused for a missing label (that leaves the key live):
        the row records ``unattributed:<source>`` and an auth_events alarm row lands
        in the same commit."""
        from email_triage.db.audit import verify_audit_chain
        key_id, raw = _mint(db, admin_user)
        assert delete_api_key(
            db, key_id, actor_user_id=None, actor_email=None, source="cli") is True
        assert not _key_exists(db, key_id)
        assert verify_api_key(db, raw) is None
        (row,) = _revocations(db, key_id)
        assert row["actor_user_id"] is None
        assert row["actor_email"] == "unattributed:cli"
        (alarm,) = db.execute(
            "SELECT email, outcome, detail FROM auth_events "
            "WHERE event_type = 'api_key_revoke_unattributed'").fetchall()
        assert alarm["email"] == "unattributed:cli" and alarm["outcome"] == "alarm"
        assert f"#{key_id}" in alarm["detail"]
        assert not db.in_transaction
        assert verify_audit_chain(db, "api_key_events")["intact"] is True
        assert verify_audit_chain(db, "auth_events")["intact"] is True

    def test_a_failed_witness_keeps_the_key_live_and_leaves_one_gap(
            self, db, admin_user, monkeypatch):
        key_id, raw = _mint(db, admin_user)
        gaps = _gaps(db, "delete_api_key")
        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
        with pytest.raises(ApiKeyRevokeError, match=_WITNESS_DOWN):
            delete_api_key(db, key_id, actor_user_id=admin_user["id"], source="ui")
        assert _key_exists(db, key_id), "the delete committed without its witness"
        assert verify_api_key(db, raw) is not None
        assert _revocations(db, key_id) == []
        assert _gaps(db, "delete_api_key") == gaps + 1
        assert not db.in_transaction

    def test_the_delete_and_the_witness_share_one_open_transaction(
            self, db, admin_user, monkeypatch):
        key_id, _raw = _mint(db, admin_user)
        seen: dict = {}

        def probe(conn, **_kw):
            seen["in_txn"] = conn.in_transaction
            seen["row_gone"] = conn.execute(
                "SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone() is None
            raise RuntimeError(_WITNESS_DOWN)

        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", probe)
        with pytest.raises(ApiKeyRevokeError):
            delete_api_key(db, key_id, source="ui")
        assert seen == {"in_txn": True, "row_gone": True}, seen
        assert _key_exists(db, key_id)

    def test_a_refused_delete_is_not_a_lost_witness(self, db, admin_user):
        key_id, _raw = _mint(db, admin_user)
        db.execute(
            "CREATE TEMP TRIGGER refuse_key_delete BEFORE DELETE ON api_keys "
            "BEGIN SELECT RAISE(ABORT, 'refused by test'); END")
        try:
            gaps = _gaps(db)
            with pytest.raises(ApiKeyRevokeError, match="refused by test"):
                delete_api_key(db, key_id, source="ui")
            assert _gaps(db) == gaps
            assert _key_exists(db, key_id)
            assert _revocations(db, key_id) == []
        finally:
            db.execute("DROP TRIGGER IF EXISTS refuse_key_delete")

    def test_an_autocommit_connection_is_refused_before_the_delete(self, db, admin_user):
        key_id, _raw = _mint(db, admin_user)
        db.commit()
        prior = db.isolation_level
        db.isolation_level = None
        try:
            with pytest.raises(RuntimeError, match="autocommit"):
                delete_api_key(db, key_id, source="ui")
        finally:
            db.isolation_level = prior
        assert _key_exists(db, key_id)
        assert _revocations(db, key_id) == []

    def test_a_missing_key_is_a_no_op(self, db, admin_user):
        gaps = _gaps(db)
        assert delete_api_key(db, 987654, source="ui") is False
        assert _revocations(db, 987654) == []
        assert _gaps(db) == gaps
        assert not db.in_transaction


def test_the_api_answers_503_and_the_key_stays(
        client, db, admin_user, admin_cookies, monkeypatch):
    key_id, raw = _mint(db, admin_user, name="api-doomed")
    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
    r = client.delete(f"/api/keys/{key_id}", cookies=admin_cookies)
    assert r.status_code == 503, r.text
    assert "not revoked" in r.text and "still active" in r.text
    # Panel AA MUST-A3: the copy names both failure points and the containment.
    assert "the delete or its audit record could not be written" in r.text
    assert "disable the owning user" in r.text and "stop the service" in r.text
    assert _key_exists(db, key_id)
    assert verify_api_key(db, raw) is not None


def test_the_ui_answers_503_and_the_key_stays(
        csrf_client, db, admin_user, admin_cookies, monkeypatch):
    key_id, raw = _mint(db, admin_user, name="ui-doomed")
    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
    r = csrf_client.delete(f"/accounts/api-keys/{key_id}", cookies=admin_cookies)
    assert r.status_code == 503, r.text
    assert "not revoked" in r.text and "still active" in r.text
    assert "the delete or its audit record could not be written" in r.text
    assert "disable the owning user" in r.text and "stop the service" in r.text
    assert _key_exists(db, key_id)
    assert verify_api_key(db, raw) is not None


def test_the_ui_create_answers_503_and_never_renders_a_key(
        csrf_client, db, admin_user, admin_cookies, monkeypatch):
    """Punch 706: the UI create route (grant edge) had no ApiKeyGrantError
    handler, so a failed witness was a bare 500. Now: 503, no key, no token."""
    monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
    r = csrf_client.post(
        "/accounts/api-keys", data={"name": "ui-create-down"},
        cookies=admin_cookies, follow_redirects=False)
    assert r.status_code == 503, r.text
    assert "nothing was granted" in r.text
    assert "the key or its audit record could not be written" in r.text
    assert "et_" not in r.text
    assert db.execute(
        "SELECT COUNT(*) FROM api_keys WHERE name = 'ui-create-down'").fetchone()[0] == 0


class TestCliFailsClosed:
    @staticmethod
    def _read(db_path, sql, params=()):
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    @staticmethod
    def _run(yaml_path, *argv):
        from email_triage.cli import cmd_apikey, cmd_user
        cmd = cmd_user if argv[0] == "user" else cmd_apikey
        return cmd(_parse(["--config", str(yaml_path), *argv]))

    def _seed_key(self, yaml_path, db_path, capsys) -> int:
        assert self._run(yaml_path, "user", "create", "--email", "keyholder@example.com") == 0
        assert self._run(yaml_path, "apikey", "create", "--user", "keyholder@example.com",
                         "--name", "cli-doomed") == 0
        capsys.readouterr()
        (row,) = self._read(db_path, "SELECT id FROM api_keys WHERE name = 'cli-doomed'")
        return row["id"]

    def test_apikey_delete_is_witnessed(self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        assert self._run(yaml_path, "apikey", "delete", str(key_id)) == 0
        assert f"API key {key_id} deleted." in capsys.readouterr().out
        (ev,) = self._read(
            db_path, "SELECT * FROM api_key_events WHERE event = 'api_key_revoked'")
        assert ev["key_id"] == key_id and ev["source"] == "cli"
        # Punch 710: both CLI witnesses carry the kernel principal as the actor.
        actors = self._read(db_path, "SELECT actor_email FROM api_key_events")
        assert actors and all(r["actor_email"].startswith("cli:") for r in actors)

    def test_apikey_delete_exits_nonzero_and_keeps_the_key_when_the_witness_fails(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
        with pytest.raises(SystemExit) as ei:
            self._run(yaml_path, "apikey", "delete", str(key_id))
        assert ei.value.code == 1
        out = capsys.readouterr()
        assert "NOT revoked" in out.err and "deleted." not in out.out
        assert "disable the owning user in the web UI" in out.err
        assert "stop the service" in out.err
        assert self._read(db_path, "SELECT id FROM api_keys WHERE id = ?", (key_id,))
        assert self._read(
            db_path, "SELECT id FROM api_key_events WHERE event = 'api_key_revoked'") == []
