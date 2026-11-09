"""Punch 709: the emergency revoke when the HMAC audit chain is broken.

Operator decision 2026-11-02 8:13 PM. ``delete_api_key`` and ``set_user_disabled``
share one transaction with their chained witness and fail closed, so with the
chain broken (here: no HMAC key provisioned, the commonest real cause) a compromised
key could not be stopped in the app. Each now takes an explicit ``emergency_reason``.
At runtime:

(a) broken chain + the flag: the key is deleted (the user disabled), no witness row
    exists, ONE PHI-free ``audit_gap_events`` row names actor, target, reason and the
    chain that lost its witness, the ``/health`` marker is set, and a later chain
    verify reports the row as a known gap (intact), not tamper;
(b) broken chain WITHOUT the flag: still refuses (the key stays live), no emergency row;
(c) healthy chain WITH the flag: the normal witnessed path, zero emergency rows, no marker;
(d) a failed DELETE is not a broken chain: it never reaches the emergency path;
(e) a reason outside the vocabulary, or a re-enable, is refused before any write;
(f) the marker clears only through ``clear_emergency_revoke`` and only once repaired;
(g) only an ENABLED admin, or the host CLI (no user id, ``source="cli"``), may pass the
    flag: anyone else is refused BEFORE any write, on a broken chain and a healthy one
    (standing DA ruling 2026-11-03, the PD-9 graft from class P4);
(h) the clear leaves ONE chained ``emergency_revoke_cleared`` row naming who cleared it,
    and when that row cannot be written the marker stays (PD-18, PD-3 graft).

The static half is ``tests/test_709_emergency_revoke_pin.py``.
"""
from __future__ import annotations

import json

import pytest

import email_triage.db.audit as audit_mod
from email_triage.db.audit import (
    EmergencyRevokeRefused,
    clear_emergency_revoke,
    emergency_revoke_pending,
    set_user_disabled,
    verify_gap_chain,
)
from email_triage.web.auth import (
    ApiKeyRevokeError,
    delete_api_key,
    generate_api_key,
    hash_api_key,
    store_api_key,
    verify_api_key,
)

REASON = "credential_compromised"


@pytest.fixture(autouse=True)
def _marker_dir(tmp_path, monkeypatch):
    """The shared ``db`` fixture is in-memory (no file to sit beside), so the
    marker location is pointed at a tmp dir; ``TestMarkerPath`` covers the real
    ``PRAGMA database_list`` resolution against a file database."""
    monkeypatch.setattr(
        audit_mod, "_emergency_marker_path",
        lambda conn: tmp_path / audit_mod.EMERGENCY_REVOKE_MARKER,
    )


def _break_chain(monkeypatch) -> None:
    """No HMAC key provisioned: ``_apply_chain_hmac`` raises, so ``_chain_insert``
    refuses. The gap writer's own recovery degrades to keyless sha256."""
    monkeypatch.setattr(audit_mod, "_get_current_hmac_version", lambda: None)


def _mint(db, admin_user) -> tuple[int, str]:
    raw = generate_api_key()
    key_id = store_api_key(
        db, hash_api_key(raw), "doomed", admin_user["id"],
        actor_user_id=admin_user["id"], actor_email=admin_user["email"], source="ui",
    )
    return key_id, raw


def _emergency_rows(db):
    return db.execute(
        "SELECT * FROM audit_gap_events WHERE helper_name = 'emergency_revoke'"
    ).fetchall()


def _revocations(db, key_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM api_key_events WHERE key_id = ? AND event = 'api_key_revoked'",
        (key_id,),
    ).fetchone()[0]


def _status_events(db, user_id: int) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM user_status_events WHERE target_user_id = ?", (user_id,),
    ).fetchone()[0]


def _make_user(db, email: str = "victim@example.invalid", role: str = "user",
               disabled: int = 0) -> int:
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at, disabled) VALUES (?, 'V', ?, "
        "'2026-11-02T00:00:00+00:00', ?)", (email, role, disabled))
    db.commit()
    return cur.lastrowid


def _gap_rows(db):
    return db.execute("SELECT helper_name, exc_type FROM audit_gap_events").fetchall()


def _cleared_rows(db):
    return db.execute(
        "SELECT * FROM audit_gap_events WHERE helper_name = 'emergency_revoke_cleared'"
    ).fetchall()


def _denied_actor(db, who: str) -> tuple[int | None, str]:
    """(actor_user_id, source) for each caller the emergency path must refuse."""
    if who == "plain user":
        return _make_user(db, "plain@example.invalid"), "ui"
    if who == "disabled admin":
        return _make_user(db, "gone@example.invalid", role="admin", disabled=1), "ui"
    if who == "unknown id":
        return 987654, "ui"
    return None, "ui"  # no user id, and not the host CLI


_DENIED = ["plain user", "disabled admin", "unknown id", "no user, not the CLI"]


class TestEmergencyRevokeApiKey:
    def test_broken_chain_with_the_flag_revokes_and_leaves_one_alarmed_gap_row(
            self, db, admin_user, monkeypatch, caplog):
        key_id, raw = _mint(db, admin_user)
        _break_chain(monkeypatch)
        assert delete_api_key(
            db, key_id, actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            source="ui", emergency_reason=REASON) is True
        assert db.execute("SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone() is None
        assert verify_api_key(db, raw) is None
        assert _revocations(db, key_id) == 0  # the chained record is the thing given up
        (row,) = _emergency_rows(db)
        assert row["exc_msg"] == (
            f"emergency_revoke kind=api_key table=api_key_events target_id={key_id} "
            f"actor=user:{admin_user['id']} reason={REASON} witness_failure=RuntimeError")
        assert row["original_args_redacted"] == "{}"
        assert admin_user["email"] not in " ".join(str(v) for v in tuple(row))
        assert emergency_revoke_pending(db) is True

    def test_the_gap_row_is_a_known_gap_not_tamper_once_the_key_is_back(
            self, db, admin_user, monkeypatch):
        key_id, _raw = _mint(db, admin_user)
        with monkeypatch.context() as m:
            _break_chain(m)
            delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                           actor_email=admin_user["email"], emergency_reason=REASON)
        result = verify_gap_chain(db)
        assert result["intact"] is True
        assert result["keyless_count"] == 1  # the recovery path's keyless row, counted

    def test_broken_chain_without_the_flag_still_refuses(
            self, db, admin_user, monkeypatch):
        key_id, raw = _mint(db, admin_user)
        _break_chain(monkeypatch)
        with pytest.raises(ApiKeyRevokeError):
            delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                           actor_email=admin_user["email"], source="ui")
        assert verify_api_key(db, raw) is not None  # the key is still live
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False

    def test_healthy_chain_with_the_flag_takes_the_normal_path_and_writes_no_gap_row(
            self, db, admin_user):
        key_id, _raw = _mint(db, admin_user)
        assert delete_api_key(
            db, key_id, actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            source="ui", emergency_reason=REASON) is True
        assert _revocations(db, key_id) == 1  # the witness exists
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False

    def test_a_failed_delete_is_not_a_broken_chain(self, db, admin_user, monkeypatch):
        key_id, raw = _mint(db, admin_user)
        db.execute(
            "CREATE TRIGGER no_delete BEFORE DELETE ON api_keys "
            "BEGIN SELECT RAISE(ABORT, 'delete refused'); END")
        db.commit()
        _break_chain(monkeypatch)
        with pytest.raises(ApiKeyRevokeError, match="delete refused"):
            delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                           actor_email=admin_user["email"], emergency_reason=REASON)
        assert verify_api_key(db, raw) is not None
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False

    def test_a_reason_outside_the_vocabulary_is_refused_before_any_write(
            self, db, admin_user):
        key_id, raw = _mint(db, admin_user)
        with pytest.raises(EmergencyRevokeRefused):
            delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                           actor_email=admin_user["email"],
                           emergency_reason="it was Jane Doe, 555-0100")
        assert verify_api_key(db, raw) is not None
        assert _emergency_rows(db) == []


class TestEmergencyDisableUser:
    def test_broken_chain_with_the_flag_disables_and_leaves_one_gap_row(
            self, db, admin_user, monkeypatch):
        uid = _make_user(db)
        epoch = db.execute("SELECT session_epoch FROM users WHERE id = ?", (uid,)).fetchone()[0]
        _break_chain(monkeypatch)
        assert set_user_disabled(
            db, uid, True, admin_user["id"], "ignored free text",
            emergency_reason=REASON) is True
        row = db.execute(
            "SELECT disabled, session_epoch FROM users WHERE id = ?", (uid,)).fetchone()
        assert row["disabled"] == 1
        assert row["session_epoch"] == epoch + 1  # live sessions die with it
        assert _status_events(db, uid) == 0
        (gap,) = _emergency_rows(db)
        assert gap["exc_msg"] == (
            f"emergency_revoke kind=user table=user_status_events target_id={uid} "
            f"actor=user:{admin_user['id']} reason={REASON} witness_failure=RuntimeError")
        assert "ignored free text" not in " ".join(str(v) for v in tuple(gap))
        assert emergency_revoke_pending(db) is True

    def test_broken_chain_without_the_flag_still_refuses(self, db, admin_user, monkeypatch):
        uid = _make_user(db)
        _break_chain(monkeypatch)
        with pytest.raises(RuntimeError):
            set_user_disabled(db, uid, True, admin_user["id"], "")
        assert db.execute("SELECT disabled FROM users WHERE id = ?", (uid,)).fetchone()[0] == 0
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False

    def test_healthy_chain_with_the_flag_takes_the_normal_path(self, db, admin_user):
        uid = _make_user(db)
        assert set_user_disabled(
            db, uid, True, admin_user["id"], "", emergency_reason=REASON) is True
        assert _status_events(db, uid) == 1
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False

    def test_the_emergency_path_only_disables(self, db, admin_user):
        uid = _make_user(db)
        with pytest.raises(EmergencyRevokeRefused):
            set_user_disabled(db, uid, False, admin_user["id"], "", emergency_reason=REASON)
        with pytest.raises(EmergencyRevokeRefused):
            set_user_disabled(db, uid, True, admin_user["id"], "", emergency_reason="x")


class TestEmergencyActorGate:
    """(g) PD-9 at the actuator: class P4's denial tests, grafted. The refusal is P2's
    ``EmergencyRevokeRefused`` raised before any write (P4 raised ``ApiKeyRevokeError``
    from inside the witness-failure handler, so on a HEALTHY chain a non-admin's flagged
    call still revoked: the ``healthy`` leg pins that difference)."""

    @pytest.mark.parametrize("chain", ["broken", "healthy"])
    @pytest.mark.parametrize("who", _DENIED)
    def test_the_api_key_path_refuses_anyone_else_before_any_write(
            self, db, admin_user, monkeypatch, who, chain):
        key_id, _raw = _mint(db, admin_user)
        actor, source = _denied_actor(db, who)
        if chain == "broken":
            _break_chain(monkeypatch)
        before = db.total_changes
        with pytest.raises(EmergencyRevokeRefused):
            delete_api_key(db, key_id, actor_user_id=actor, actor_email="x@example.invalid",
                           source=source, emergency_reason=REASON)
        # Lead ruling 2026-11-03: on this edge NOTHING lands.
        assert db.total_changes == before, "a refused emergency revoke wrote a row"
        assert db.execute("SELECT 1 FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        assert _revocations(db, key_id) == 0
        assert _gap_rows(db) == []  # no gap row of any kind
        assert emergency_revoke_pending(db) is False

    def test_the_host_cli_with_no_user_may_revoke_a_key(self, db, admin_user, monkeypatch):
        key_id, _raw = _mint(db, admin_user)
        _break_chain(monkeypatch)
        assert delete_api_key(db, key_id, actor_user_id=None, actor_email="cli:root",
                              source="cli", emergency_reason=REASON) is True
        (row,) = _emergency_rows(db)
        assert "actor=cli " in row["exc_msg"]

    @pytest.mark.parametrize("chain", ["broken", "healthy"])
    @pytest.mark.parametrize("who", _DENIED)
    def test_the_user_disable_path_refuses_anyone_else_before_any_write(
            self, db, monkeypatch, who, chain):
        uid = _make_user(db)
        epoch = db.execute("SELECT session_epoch FROM users WHERE id = ?", (uid,)).fetchone()[0]
        actor, _source = _denied_actor(db, who)
        if chain == "broken":
            _break_chain(monkeypatch)
        free_text = "called Jane Doe at 555-0100"
        before = db.total_changes
        with pytest.raises(EmergencyRevokeRefused):  # the default source is not the CLI
            set_user_disabled(db, uid, True, actor, free_text, emergency_reason=REASON)
        row = db.execute(
            "SELECT disabled, session_epoch FROM users WHERE id = ?", (uid,)).fetchone()
        assert row["disabled"] == 0 and row["session_epoch"] == epoch
        assert _status_events(db, uid) == 0
        assert _emergency_rows(db) == []
        assert emergency_revoke_pending(db) is False
        # Lead ruling 2026-11-03 (panel question 11): what DOES land is exactly ONE row,
        # db_write's sentinel gap row, as for every refusal raised inside this @audit_emitter
        # (P2's bad-reason and re-enable refusals leave the same row). Ids only, no PHI.
        assert db.total_changes == before + 1, "the refusal wrote more than its one gap row"
        (gap,) = db.execute("SELECT * FROM audit_gap_events").fetchall()
        assert (gap["helper_name"], gap["exc_type"]) == (
            "set_user_disabled", "EmergencyRevokeRefused")
        assert gap["exc_msg"] == "the emergency path needs an enabled admin or the host CLI"
        assert json.loads(gap["original_args_redacted"]) == {
            "target_user_id": uid, "disabled": True, "actor_user_id": actor}
        stored = " ".join(str(v) for v in tuple(gap))
        for phi in (free_text, "Jane Doe", "555-0100", "victim@example.invalid",
                    "plain@example.invalid", "gone@example.invalid"):
            assert phi not in stored, phi

    def test_the_host_cli_may_stop_an_account(self, db, monkeypatch):
        uid = _make_user(db)
        _break_chain(monkeypatch)
        assert set_user_disabled(
            db, uid, True, None, "", emergency_reason=REASON,
            cli_principal="root", source="cli") is True
        (gap,) = _emergency_rows(db)
        assert "actor=cli:root " in gap["exc_msg"]


def _revoke_then_repair(db, admin_user, monkeypatch) -> None:
    """An emergency revoke under a broken chain; the HMAC key is back on return."""
    key_id, _raw = _mint(db, admin_user)
    with monkeypatch.context() as m:
        _break_chain(m)
        delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                       actor_email=admin_user["email"], emergency_reason=REASON)
    assert emergency_revoke_pending(db) is True


class TestMarkerPath:
    def test_the_marker_sits_beside_the_database_file(self, tmp_path, monkeypatch):
        import sqlite3
        monkeypatch.undo()  # drop the autouse redirect: use the real resolver
        conn = sqlite3.connect(str(tmp_path / "triage.db"))
        try:
            assert audit_mod._emergency_marker_path(conn) == (
                tmp_path / audit_mod.EMERGENCY_REVOKE_MARKER)
        finally:
            conn.close()

    def test_an_in_memory_database_has_no_marker_and_reads_not_pending(self):
        import sqlite3
        conn = sqlite3.connect(":memory:")
        try:
            assert audit_mod.emergency_revoke_pending(conn) is False
        finally:
            conn.close()


class TestClearEdge:
    def test_the_flag_clears_only_once_the_chain_is_repaired(
            self, db, admin_user, monkeypatch):
        who = {"actor_user_id": admin_user["id"], "source": "ui"}
        key_id, _raw = _mint(db, admin_user)
        with monkeypatch.context() as m:
            _break_chain(m)
            delete_api_key(db, key_id, actor_user_id=admin_user["id"],
                           actor_email=admin_user["email"], emergency_reason=REASON)
            blocked = clear_emergency_revoke(db, **who)
            assert blocked["cleared"] is False
            assert "no HMAC key provisioned" in blocked["blockers"]
            assert emergency_revoke_pending(db) is True
            assert _cleared_rows(db) == []  # a refused clear records nothing
        done = clear_emergency_revoke(db, **who)  # the key is back
        assert done == {"cleared": True, "blockers": []}
        assert emergency_revoke_pending(db) is False
        assert clear_emergency_revoke(db, **who)["cleared"] is False  # nothing left
        assert len(_cleared_rows(db)) == 1

    def test_the_clear_is_one_chained_row_naming_who_cleared_it(
            self, db, admin_user, monkeypatch):
        _revoke_then_repair(db, admin_user, monkeypatch)
        assert clear_emergency_revoke(db, actor_user_id=admin_user["id"], source="ui")["cleared"] is True
        (row,) = _cleared_rows(db)
        assert row["exc_msg"] == f"emergency_revoke_cleared actor=user:{admin_user['id']}"
        assert row["exc_type"] == "AuditEmergencyRevokeCleared"
        assert row["ts"]  # when
        assert row["master_key_version"] is not None  # HMAC-keyed, not the keyless fallback
        assert admin_user["email"] not in " ".join(str(v) for v in tuple(row))
        assert verify_gap_chain(db)["intact"] is True
        edges = [r[0] for r in db.execute(
            "SELECT helper_name FROM audit_gap_events "
            "WHERE helper_name LIKE 'emergency_revoke%' ORDER BY id")]
        assert edges == ["emergency_revoke", "emergency_revoke_cleared"]

    def test_an_unwritable_cleared_row_keeps_the_marker(self, db, admin_user, monkeypatch):
        _revoke_then_repair(db, admin_user, monkeypatch)
        real = audit_mod._write_audit_gap_event

        def refuse_the_clear_row(conn, **kw):
            if kw["helper_name"] == "emergency_revoke_cleared":
                raise RuntimeError("gap table unwritable")
            return real(conn, **kw)

        monkeypatch.setattr(audit_mod, "_write_audit_gap_event", refuse_the_clear_row)
        assert clear_emergency_revoke(db, actor_user_id=None, source="cli") == {
            "cleared": False,
            "blockers": ["the emergency_revoke_cleared row could not be written"]}
        assert emergency_revoke_pending(db) is True  # the alarm stays
        assert _cleared_rows(db) == []

    def test_a_principal_that_is_not_a_plain_id_never_reaches_the_row(
            self, db, admin_user, monkeypatch):
        _revoke_then_repair(db, admin_user, monkeypatch)
        assert clear_emergency_revoke(
            db, actor_user_id=None, source="cli", cli_principal="Jane Doe, 555-0100",
        )["cleared"] is True
        (row,) = _cleared_rows(db)
        assert row["exc_msg"] == "emergency_revoke_cleared actor=cli"
        assert "Jane" not in " ".join(str(v) for v in tuple(row))

    @pytest.mark.parametrize("who", _DENIED)
    def test_the_clear_refuses_anyone_else_before_any_read_or_write(
            self, db, admin_user, monkeypatch, who):
        """Cycle P DA P709g S1 (PD-9): the clear has the revoke's actor gate, first."""
        _revoke_then_repair(db, admin_user, monkeypatch)
        actor, source = _denied_actor(db, who)
        before = db.total_changes
        with pytest.raises(EmergencyRevokeRefused):
            clear_emergency_revoke(db, actor_user_id=actor, source=source)
        assert db.total_changes == before
        assert emergency_revoke_pending(db) is True
        assert _cleared_rows(db) == []


class TestActorLabelIsBuiltInTheFunnel:
    """Cycle P hipaa S2: the gap row's actor cannot contradict the id the gate checked."""

    def test_an_admin_with_a_cli_principal_is_recorded_as_the_admin(
            self, db, admin_user, monkeypatch):
        key_id, _raw = _mint(db, admin_user)
        _break_chain(monkeypatch)
        assert delete_api_key(db, key_id, actor_user_id=admin_user["id"], source="ui",
                              emergency_reason=REASON, cli_principal="root") is True
        (row,) = _emergency_rows(db)
        assert f" actor=user:{admin_user['id']} " in row["exc_msg"]
        assert "cli" not in row["exc_msg"]

    def test_the_user_path_records_the_checked_admin_too(self, db, admin_user, monkeypatch):
        uid = _make_user(db)
        _break_chain(monkeypatch)
        assert set_user_disabled(db, uid, True, admin_user["id"], "", emergency_reason=REASON,
                                 cli_principal="root", source="ui") is True
        (row,) = _emergency_rows(db)
        assert f" actor=user:{admin_user['id']} " in row["exc_msg"]

    def test_no_edge_accepts_a_caller_built_label(self, db, admin_user):
        uid = _make_user(db)
        with pytest.raises(TypeError):
            set_user_disabled(db, uid, True, admin_user["id"], "", emergency_reason=REASON,
                              emergency_actor_label="cli:root")
        with pytest.raises(TypeError):
            clear_emergency_revoke(db, actor="cli")


class TestStorageRolledBackItself:
    """Cycle P hipaa S3: SQLite ends the transaction by itself on SQLITE_FULL / IOERR /
    NOMEM. The emergency retry must not then fail on its own ROLLBACK and lose the
    disable on exactly a damaged-storage chain."""

    def test_the_emergency_disable_survives_an_auto_rollback(self, db, admin_user, monkeypatch):
        uid = _make_user(db)
        real = audit_mod._chain_insert

        def storage_failed(conn, table, row, *a, **kw):
            if table == "user_status_events":
                conn.rollback()  # what SQLite did by itself on the I/O error
                raise RuntimeError("disk I/O error")
            return real(conn, table, row, *a, **kw)

        monkeypatch.setattr(audit_mod, "_chain_insert", storage_failed)
        assert set_user_disabled(db, uid, True, admin_user["id"], "",
                                 emergency_reason=REASON, source="ui") is True
        assert db.execute("SELECT disabled FROM users WHERE id = ?", (uid,)).fetchone()[0] == 1
        (row,) = _emergency_rows(db)
        assert "witness_failure=RuntimeError" in row["exc_msg"]


class TestKnownGapsInTheVerify:
    """Cycle P hipaa Q3: the verify reports emergency-revoke gaps BESIDE ``intact``."""

    def test_each_witness_table_counts_its_own_gaps_and_stays_intact(
            self, db, admin_user, monkeypatch):
        from email_triage.db.audit import known_emergency_revoke_gaps, verify_all_audit_chains
        assert known_emergency_revoke_gaps(db) == {"api_key_events": 0, "user_status_events": 0}
        _revoke_then_repair(db, admin_user, monkeypatch)
        assert known_emergency_revoke_gaps(db) == {"api_key_events": 1, "user_status_events": 0}
        chains = verify_all_audit_chains(db)
        assert chains["api_key_events"]["intact"] is True  # integrity, unchanged
        assert chains["api_key_events"]["known_emergency_gap_count"] == 1
        assert chains["user_status_events"]["known_emergency_gap_count"] == 0
