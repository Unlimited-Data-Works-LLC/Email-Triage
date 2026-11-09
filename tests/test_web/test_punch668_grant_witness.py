"""Punch 668 (register N-611 class): user and recovery-credential grants are witnessed.

Five writers granted access with no chained audit row: the API, UI and CLI user
create (one funnel now, ``record_user_creation``), the break-glass operator
token (``issue_operator_recovery_token``) and the recovery-code set
(``issue_recovery_codes``). Per writer, at runtime:

(a) the witness row exists after the write, in the SAME transaction, with the
    NEW id as subject (``user_id`` is the new / target user; ``key_id`` is the
    new operator-key row);
(b) a forced witness failure leaves NO grant row and no returned secret, and
    leaves one ``audit_gap_events`` row (a refused insert leaves none);
(c) the event carries no secret material (no token, no code, no hash of either);
(d) the two ``web/mfa.py`` writers refuse, BEFORE any insert, a missing / blank
    actor and an autocommit connection (panel R: no unattributed or unatomic
    grant row), ``record_user_creation`` refuses a blank actor the same way
    (panel R2; its refusal leaves one gap row, being an ``@audit_emitter``), and a duplicate user create leaves a ``denied:duplicate_email``
    row on every path (API, UI, CLI), not only on a race.

The static half is ``tests/test_session_epoch_on_revoke_pin.py`` (Properties 0-2
over the discovered grant tables).
"""
from __future__ import annotations

import contextlib
import inspect
import re
import sqlite3

import pytest

import email_triage.db.audit as audit_mod
from email_triage.db.audit import (
    USER_DUPLICATE,
    GrantRefused,
    record_user_creation,
    verify_audit_chain,
)
from email_triage.web.mfa import (
    RecoveryIssueError,
    _hash_code,
    issue_operator_recovery_token,
    issue_recovery_codes,
)
from test_cli_audit import _hipaa_config_file, _parse  # noqa: F401  (fixture + parser, reused)

_WITNESS_DOWN = "audit storage exploded"


def _boom(*_a, **_kw):
    raise RuntimeError(_WITNESS_DOWN)


def _events(db, event_type: str):
    return db.execute(
        "SELECT * FROM auth_events WHERE event_type = ? ORDER BY id", (event_type,)
    ).fetchall()


def _gaps(db, helper: str) -> int:
    return db.execute(
        "SELECT COUNT(*) FROM audit_gap_events WHERE helper_name = ?", (helper,)
    ).fetchone()[0]


def _scalar(db, sql: str, params=()) -> int:
    return db.execute(sql, params).fetchone()[0]


@contextlib.contextmanager
def _sql_trace(db):
    """Yield the list of every SQL statement the connection runs inside the block.
    "Refused BEFORE any insert" is measured with this, not inferred from a row
    count: a guard moved after the INSERT still leaves 0 rows when the writer's
    rollback undoes it (panel R2, DA SHOULD-3 mutation T2)."""
    statements: list[str] = []
    db.set_trace_callback(statements.append)
    try:
        yield statements
    finally:
        db.set_trace_callback(None)


def _inserts_into(statements: list[str], table: str) -> list[str]:
    rx = re.compile(rf"\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+{table}\b", re.IGNORECASE)
    return [s for s in statements if rx.search(s)]


def _audit_text(db) -> str:
    """Every ``auth_events`` and ``audit_gap_events`` row, as one string."""
    rows = [tuple(r) for r in db.execute("SELECT * FROM auth_events")]
    rows += [tuple(r) for r in db.execute("SELECT * FROM audit_gap_events")]
    return "\n".join(map(str, rows))


def _probe_witness(conn_probe_sql: str, seen: dict):
    """A witness that records whether the grant row is already visible inside an
    OPEN transaction when the witness runs, then fails."""
    def probe(conn, **_kw):
        seen["in_txn"] = conn.in_transaction
        seen["row_visible"] = conn.execute(conn_probe_sql).fetchone() is not None
        raise RuntimeError(_WITNESS_DOWN)
    return probe


# ---------------------------------------------------------------------------
# users: record_user_creation (API, UI and CLI share it)
# ---------------------------------------------------------------------------

class TestUserCreationFunnel:
    def _create(self, db, admin_user, email="newbie@example.com", role="power_user"):
        return record_user_creation(
            db, email=email, name="Newbie", role=role, notify_email="n@example.org",
            actor_user_id=admin_user["id"], actor_email=admin_user["email"],
            ip="10.0.0.9", source="api",
        )

    def test_the_witness_binds_the_new_user_and_the_actor(self, db, admin_user):
        new_id = self._create(db, admin_user)
        assert isinstance(new_id, int)
        (row,) = _events(db, "user_created")
        assert row["user_id"] == new_id
        assert row["email"] == admin_user["email"]
        assert row["outcome"] == "success"
        assert row["ip"] == "10.0.0.9"
        assert row["detail"] == f"role=power_user source=api actor_user_id={admin_user['id']}"
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE id = ?", (new_id,)) == 1
        # The new user's address, name and notify address are not in the event.
        text = _audit_text(db)
        for private in ("newbie@example.com", "Newbie", "n@example.org"):
            assert private not in text.replace(admin_user["email"], "")
        assert verify_audit_chain(db, "auth_events")["intact"]

    def test_a_failed_witness_leaves_no_user_and_one_gap(self, db, admin_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        gaps = _gaps(db, "record_user_creation")
        with pytest.raises(RuntimeError, match=_WITNESS_DOWN):
            self._create(db, admin_user)
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'newbie@example.com'") == 0
        assert _gaps(db, "record_user_creation") == gaps + 1

    def test_the_insert_and_the_witness_share_one_open_transaction(
            self, db, admin_user, monkeypatch):
        seen: dict = {}
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _probe_witness(
            "SELECT 1 FROM users WHERE email = 'newbie@example.com'", seen))
        with pytest.raises(RuntimeError, match=_WITNESS_DOWN):
            self._create(db, admin_user)
        assert seen == {"in_txn": True, "row_visible": True}, seen
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'newbie@example.com'") == 0

    def test_a_racing_duplicate_is_a_witnessed_refusal_without_a_gap(self, db, admin_user):
        assert isinstance(self._create(db, admin_user), int)
        gaps = _gaps(db, "record_user_creation")
        got = self._create(db, admin_user)
        assert got is USER_DUPLICATE and isinstance(got, GrantRefused)
        (_ok, denied) = _events(db, "user_created")
        assert denied["outcome"] == "denied:duplicate_email"
        assert denied["user_id"] is None
        assert _gaps(db, "record_user_creation") == gaps
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'newbie@example.com'") == 1

    @pytest.mark.parametrize("actor", ["", "   ", None])
    def test_a_blank_actor_is_refused_before_the_insert(self, db, admin_user, actor):
        """The root grant refuses an unattributed row like the two ``web/mfa.py``
        writers do (panel R2). The routes pass ``actor.get("email") or ""``, so a blank
        reaches THIS funnel and is refused here, as an ``@audit_emitter`` raise: it
        leaves exactly one ``audit_gap_events`` row (an unattributed attempt stays
        visible), unlike the mfa guard, which raises outside an emitter."""
        users = _scalar(db, "SELECT COUNT(*) FROM users")
        gaps = _gaps(db, "record_user_creation")
        events = _scalar(db, "SELECT COUNT(*) FROM auth_events WHERE event_type = 'user_created'")
        with _sql_trace(db) as statements:
            with pytest.raises(ValueError, match="actor_email"):
                record_user_creation(
                    db, email="newbie@example.com", name="Newbie", role="user",
                    actor_user_id=admin_user["id"], actor_email=actor, source="api")
        # No ``INSERT INTO users`` was ever issued, so a rollback cannot be what hid
        # it (the gap row's own INSERT is a different table).
        assert _inserts_into(statements, "users") == [], statements
        assert _scalar(db, "SELECT COUNT(*) FROM users") == users
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'newbie@example.com'") == 0
        assert _scalar(
            db, "SELECT COUNT(*) FROM auth_events WHERE event_type = 'user_created'") == events
        assert _gaps(db, "record_user_creation") == gaps + 1


class TestUserRoutes:
    def test_the_api_witnesses_the_create(self, client, db, admin_user, admin_cookies):
        r = client.post("/api/users", json={"email": "viaapi@example.com", "name": "Api",
                                            "role": "user"}, cookies=admin_cookies)
        assert r.status_code == 201, r.text
        new_id = r.json()["id"]
        (row,) = _events(db, "user_created")
        assert row["user_id"] == new_id
        assert row["email"] == admin_user["email"]
        assert row["detail"] == f"role=user source=api actor_user_id={admin_user['id']}"
        # The witness records WHERE the grant came from (a lost ip is a lost
        # attribution, DA mutation M12).
        assert row["ip"], row["ip"]
        assert "viaapi@example.com" not in _audit_text(db)
        # The response reports the STORED row's stamp, not a second clock read.
        stored = db.execute("SELECT created_at FROM users WHERE id = ?", (new_id,)).fetchone()
        assert r.json()["created_at"] == stored["created_at"]

    def test_the_api_creates_nothing_when_the_witness_fails(
            self, client, db, admin_user, admin_cookies, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        r = client.post("/api/users", json={"email": "viaapi@example.com", "name": "Api",
                                            "role": "user"}, cookies=admin_cookies)
        assert r.status_code == 500, r.text
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'viaapi@example.com'") == 0
        assert _gaps(db, "record_user_creation") == 1

    def test_the_ui_witnesses_the_create(self, csrf_client, db, admin_user, admin_cookies):
        r = csrf_client.post(
            "/users/create",
            data={"email": "viaui@example.com", "name": "Ui", "role": "user",
                  "notify_email": ""},
            cookies=admin_cookies, follow_redirects=False)
        assert r.status_code == 303, r.text
        new_id = _scalar(db, "SELECT id FROM users WHERE email = 'viaui@example.com'")
        (row,) = _events(db, "user_created")
        assert row["user_id"] == new_id
        assert row["email"] == admin_user["email"]
        # The typed actor id is part of WHO (DA mutation M9: UI actor_user_id=None).
        assert row["detail"] == f"role=user source=ui actor_user_id={admin_user['id']}"

    def test_a_duplicate_create_through_the_api_is_a_witnessed_refusal(
            self, client, db, admin_user, admin_cookies):
        body = {"email": "viaapi@example.com", "name": "Api", "role": "user"}
        assert client.post("/api/users", json=body, cookies=admin_cookies).status_code == 201
        gaps = _gaps(db, "record_user_creation")
        r = client.post("/api/users", json=body, cookies=admin_cookies)
        assert r.status_code == 409, r.text
        (_ok, denied) = _events(db, "user_created")
        assert denied["outcome"] == "denied:duplicate_email"
        assert denied["email"] == admin_user["email"] and denied["user_id"] is None
        assert denied["detail"] == f"role=user source=api actor_user_id={admin_user['id']}"
        assert _gaps(db, "record_user_creation") == gaps
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'viaapi@example.com'") == 1
        assert "viaapi@example.com" not in _audit_text(db)

    def test_a_duplicate_create_through_the_ui_is_a_witnessed_refusal(
            self, csrf_client, db, admin_user, admin_cookies):
        data = {"email": "viaui@example.com", "name": "Ui", "role": "user", "notify_email": ""}
        first = csrf_client.post("/users/create", data=data, cookies=admin_cookies,
                                 follow_redirects=False)
        assert first.status_code == 303, first.text
        r = csrf_client.post("/users/create", data=data, cookies=admin_cookies,
                             follow_redirects=False)
        assert r.status_code == 409 and "already exists" in r.text, r.text
        (_ok, denied) = _events(db, "user_created")
        assert denied["outcome"] == "denied:duplicate_email"
        assert denied["email"] == admin_user["email"] and denied["user_id"] is None
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'viaui@example.com'") == 1

    def test_a_duplicate_of_a_removed_user_keeps_its_message_and_is_witnessed(
            self, csrf_client, db, admin_user, admin_cookies):
        data = {"email": "viaui@example.com", "name": "Ui", "role": "user", "notify_email": ""}
        assert csrf_client.post("/users/create", data=data, cookies=admin_cookies,
                                follow_redirects=False).status_code == 303
        db.execute("UPDATE users SET disabled = 1 WHERE email = 'viaui@example.com'")
        db.commit()
        r = csrf_client.post("/users/create", data=data, cookies=admin_cookies,
                             follow_redirects=False)
        assert r.status_code == 409 and "removed (disabled)" in r.text, r.text
        (_ok, denied) = _events(db, "user_created")
        assert denied["outcome"] == "denied:duplicate_email"

    def test_the_ui_creates_nothing_when_the_witness_fails(
            self, csrf_client, db, admin_user, admin_cookies, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        r = csrf_client.post(
            "/users/create",
            data={"email": "viaui@example.com", "name": "Ui", "role": "user",
                  "notify_email": ""},
            cookies=admin_cookies, follow_redirects=False)
        assert r.status_code == 500, r.text
        assert _scalar(db, "SELECT COUNT(*) FROM users WHERE email = 'viaui@example.com'") == 0
        assert _gaps(db, "record_user_creation") == 1


# ---------------------------------------------------------------------------
# recovery codes + the break-glass operator token (web/mfa.py)
# ---------------------------------------------------------------------------

class TestRecoveryCodeIssue:
    def test_the_witness_binds_the_target_user_and_the_count(self, db, admin_user):
        codes = issue_recovery_codes(
            db, user_id=admin_user["id"], count=3, actor_email="cli:tester", source="cli")
        assert len(codes) == 3
        (row,) = _events(db, "recovery_codes_issued")
        assert row["user_id"] == admin_user["id"]
        assert row["key_id"] is None
        assert row["email"] == "cli:tester"
        assert row["detail"] == "count=3 source=cli"
        assert _scalar(db, "SELECT COUNT(*) FROM recovery_codes") == 3
        # (c) no code and no hash of a code is in any audit row.
        text = _audit_text(db)
        for code in codes:
            assert code not in text and _hash_code(code) not in text
        assert verify_audit_chain(db, "auth_events")["intact"]

    def test_a_failed_witness_issues_nothing(self, db, admin_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RecoveryIssueError, match=_WITNESS_DOWN) as ei:
            issue_recovery_codes(db, user_id=admin_user["id"], count=3, actor_email="cli:tester")
        assert _scalar(db, "SELECT COUNT(*) FROM recovery_codes") == 0
        assert _gaps(db, "issue_recovery_codes") == 1
        assert not re.search(r"[0-9a-f]{12}", str(ei.value))

    def test_the_codes_and_the_witness_share_one_open_transaction(
            self, db, admin_user, monkeypatch):
        seen: dict = {}
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _probe_witness(
            "SELECT 1 FROM recovery_codes", seen))
        with pytest.raises(RecoveryIssueError):
            issue_recovery_codes(db, user_id=admin_user["id"], count=2, actor_email="cli:tester")
        assert seen == {"in_txn": True, "row_visible": True}, seen
        assert _scalar(db, "SELECT COUNT(*) FROM recovery_codes") == 0

    def test_actor_email_is_a_required_keyword(self, db, admin_user):
        p = inspect.signature(issue_recovery_codes).parameters["actor_email"]
        assert p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty
        with pytest.raises(TypeError, match="actor_email"):
            issue_recovery_codes(db, user_id=admin_user["id"])

    @pytest.mark.parametrize("actor", ["", "   ", None])
    def test_a_blank_actor_is_refused_before_any_insert(self, db, admin_user, actor):
        events = _scalar(db, "SELECT COUNT(*) FROM auth_events")
        with _sql_trace(db) as statements:
            with pytest.raises(ValueError, match="actor_email"):
                issue_recovery_codes(db, user_id=admin_user["id"], actor_email=actor)
        assert _inserts_into(statements, "recovery_codes") == [], statements
        assert _scalar(db, "SELECT COUNT(*) FROM recovery_codes") == 0
        assert _scalar(db, "SELECT COUNT(*) FROM auth_events") == events
        assert _gaps(db, "issue_recovery_codes") == 0

    def test_an_autocommit_connection_is_refused_before_any_insert(self, db, admin_user):
        db.commit()
        events = _scalar(db, "SELECT COUNT(*) FROM auth_events")
        prior = db.isolation_level
        db.isolation_level = None
        try:
            with pytest.raises(RecoveryIssueError, match="autocommit"):
                issue_recovery_codes(db, user_id=admin_user["id"], actor_email="cli:tester")
        finally:
            db.isolation_level = prior
        assert _scalar(db, "SELECT COUNT(*) FROM recovery_codes") == 0
        assert _scalar(db, "SELECT COUNT(*) FROM auth_events") == events

    def test_a_refused_insert_is_not_a_lost_witness(self, db, admin_user):
        db.execute(
            "CREATE TEMP TRIGGER refuse_codes BEFORE INSERT ON recovery_codes "
            "BEGIN SELECT RAISE(ABORT, 'refused by test'); END")
        try:
            with pytest.raises(RecoveryIssueError, match="refused by test"):
                issue_recovery_codes(db, user_id=admin_user["id"], count=2, actor_email="cli:tester")
            assert _gaps(db, "issue_recovery_codes") == 0
            assert _events(db, "recovery_codes_issued") == []
        finally:
            db.execute("DROP TRIGGER IF EXISTS refuse_codes")


class TestOperatorRecoveryTokenIssue:
    def test_the_witness_binds_the_new_key_and_the_target_user(self, db, admin_user):
        token = issue_operator_recovery_token(
            db, target_user_id=admin_user["id"], operator_user_id=None,
            ttl_secs=3600, actor_email="cli:tester", source="cli")
        key_id = _scalar(db, "SELECT id FROM operator_recovery_keys")
        (row,) = _events(db, "operator_recovery_key_issued")
        assert row["key_id"] == key_id
        assert row["user_id"] == admin_user["id"]
        assert row["email"] == "cli:tester"
        assert row["detail"] == "operator_user_id=None ttl_secs=3600 source=cli"
        # (c) neither the token nor its hash is in any audit row.
        text = _audit_text(db)
        assert token not in text and _hash_code(token) not in text
        assert verify_audit_chain(db, "auth_events")["intact"]

    def test_a_failed_witness_issues_no_token(self, db, admin_user, monkeypatch):
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(RecoveryIssueError, match=_WITNESS_DOWN) as ei:
            issue_operator_recovery_token(
                db, target_user_id=admin_user["id"], operator_user_id=None, actor_email="cli:tester")
        assert _scalar(db, "SELECT COUNT(*) FROM operator_recovery_keys") == 0
        assert _gaps(db, "issue_operator_recovery_token") == 1
        assert not re.search(r"[0-9a-f]{32}", str(ei.value))

    def test_the_key_and_the_witness_share_one_open_transaction(
            self, db, admin_user, monkeypatch):
        seen: dict = {}
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _probe_witness(
            "SELECT 1 FROM operator_recovery_keys", seen))
        with pytest.raises(RecoveryIssueError):
            issue_operator_recovery_token(
                db, target_user_id=admin_user["id"], operator_user_id=None, actor_email="cli:tester")
        assert seen == {"in_txn": True, "row_visible": True}, seen
        assert _scalar(db, "SELECT COUNT(*) FROM operator_recovery_keys") == 0

    def test_actor_email_is_a_required_keyword(self, db, admin_user):
        p = inspect.signature(issue_operator_recovery_token).parameters["actor_email"]
        assert p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty
        with pytest.raises(TypeError, match="actor_email"):
            issue_operator_recovery_token(
                db, target_user_id=admin_user["id"], operator_user_id=None)

    @pytest.mark.parametrize("actor", ["", "   ", None])
    def test_a_blank_actor_is_refused_before_any_insert(self, db, admin_user, actor):
        events = _scalar(db, "SELECT COUNT(*) FROM auth_events")
        with _sql_trace(db) as statements:
            with pytest.raises(ValueError, match="actor_email"):
                issue_operator_recovery_token(
                    db, target_user_id=admin_user["id"], operator_user_id=None, actor_email=actor)
        assert _inserts_into(statements, "operator_recovery_keys") == [], statements
        assert _scalar(db, "SELECT COUNT(*) FROM operator_recovery_keys") == 0
        assert _scalar(db, "SELECT COUNT(*) FROM auth_events") == events
        assert _gaps(db, "issue_operator_recovery_token") == 0

    def test_an_autocommit_connection_is_refused_before_any_insert(self, db, admin_user):
        db.commit()
        events = _scalar(db, "SELECT COUNT(*) FROM auth_events")
        prior = db.isolation_level
        db.isolation_level = None
        try:
            with pytest.raises(RecoveryIssueError, match="autocommit"):
                issue_operator_recovery_token(
                    db, target_user_id=admin_user["id"], operator_user_id=None,
                    actor_email="cli:tester")
        finally:
            db.isolation_level = prior
        assert _scalar(db, "SELECT COUNT(*) FROM operator_recovery_keys") == 0
        assert _scalar(db, "SELECT COUNT(*) FROM auth_events") == events

    def test_a_refused_insert_is_not_a_lost_witness(self, db, admin_user):
        db.execute(
            "CREATE TEMP TRIGGER refuse_keys BEFORE INSERT ON operator_recovery_keys "
            "BEGIN SELECT RAISE(ABORT, 'refused by test'); END")
        try:
            with pytest.raises(RecoveryIssueError, match="refused by test"):
                issue_operator_recovery_token(
                    db, target_user_id=admin_user["id"], operator_user_id=None, actor_email="cli:tester")
            assert _gaps(db, "issue_operator_recovery_token") == 0
            assert _events(db, "operator_recovery_key_issued") == []
        finally:
            db.execute("DROP TRIGGER IF EXISTS refuse_keys")


# ---------------------------------------------------------------------------
# CLI: exit non-zero and show no secret when the witness cannot be written
# ---------------------------------------------------------------------------

class TestCliFailsClosed:
    @staticmethod
    def _read(db_path, sql, params=()):
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def _run(self, yaml_path, *argv):
        from email_triage.cli import cmd_user
        return cmd_user(_parse(["--config", str(yaml_path), "user", *argv]))

    def test_user_create_is_witnessed(self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        assert self._run(yaml_path, "create", "--email", "cliuser@example.com",
                         "--name", "Cli", "--role", "admin") == 0
        capsys.readouterr()
        (u,) = self._read(db_path, "SELECT id FROM users WHERE email = 'cliuser@example.com'")
        (ev,) = self._read(db_path, "SELECT * FROM auth_events WHERE event_type = 'user_created'")
        assert ev["user_id"] == u["id"]
        assert ev["email"].startswith("cli:")
        assert ev["detail"] == "role=admin source=cli actor_user_id=None"

    def test_a_duplicate_user_create_is_a_witnessed_refusal(self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        argv = ("create", "--email", "cliuser@example.com")
        assert self._run(yaml_path, *argv) == 0
        assert self._run(yaml_path, *argv) == 1
        assert "already exists" in capsys.readouterr().out
        assert len(self._read(db_path, "SELECT id FROM users WHERE email = 'cliuser@example.com'")) == 1
        (_ok, denied) = self._read(
            db_path, "SELECT * FROM auth_events WHERE event_type = 'user_created' ORDER BY id")
        assert denied["outcome"] == "denied:duplicate_email"
        assert denied["email"].startswith("cli:") and denied["user_id"] is None

    def test_user_create_exits_nonzero_and_creates_nothing_when_the_witness_fails(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(SystemExit) as ei:
            self._run(yaml_path, "create", "--email", "cliuser@example.com")
        assert ei.value.code == 1
        out = capsys.readouterr()
        assert "User NOT created" in out.err and "User created" not in out.out
        assert self._read(db_path, "SELECT id FROM users WHERE email = 'cliuser@example.com'") == []

    def _seed_user(self, yaml_path, capsys):
        assert self._run(yaml_path, "create", "--email", "target@example.com") == 0
        capsys.readouterr()

    def test_enroll_mfa_is_witnessed_and_prints_the_codes_once(
            self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        self._seed_user(yaml_path, capsys)
        assert self._run(yaml_path, "enroll-mfa", "--email", "target@example.com",
                         "--count", "2") == 0
        out = capsys.readouterr().out
        codes = re.findall(r"^  ([0-9a-f]{12})$", out, re.M)
        assert len(codes) == 2, out
        (u,) = self._read(db_path, "SELECT id FROM users WHERE email = 'target@example.com'")
        (ev,) = self._read(db_path, "SELECT * FROM auth_events "
                                    "WHERE event_type = 'recovery_codes_issued'")
        assert ev["user_id"] == u["id"] and ev["detail"] == "count=2 source=cli"
        blob = str([tuple(r) for r in self._read(db_path, "SELECT * FROM auth_events")])
        assert all(c not in blob and _hash_code(c) not in blob for c in codes)

    def test_enroll_mfa_exits_nonzero_and_shows_no_code_when_the_witness_fails(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        self._seed_user(yaml_path, capsys)
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(SystemExit) as ei:
            self._run(yaml_path, "enroll-mfa", "--email", "target@example.com")
        assert ei.value.code == 1
        out = capsys.readouterr()
        assert "NOT issued" in out.err
        assert not re.search(r"[0-9a-f]{12}", out.out + out.err.replace("0x", ""))
        assert self._read(db_path, "SELECT id FROM recovery_codes") == []

    def test_reset_mfa_is_witnessed_and_prints_the_token_once(
            self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        self._seed_user(yaml_path, capsys)
        assert self._run(yaml_path, "reset-mfa", "--email", "target@example.com") == 0
        out = capsys.readouterr().out
        (token,) = re.findall(r"^  ([0-9a-f]{32})$", out, re.M)
        (k,) = self._read(db_path, "SELECT id, target_user_id FROM operator_recovery_keys")
        (ev,) = self._read(db_path, "SELECT * FROM auth_events "
                                    "WHERE event_type = 'operator_recovery_key_issued'")
        assert ev["key_id"] == k["id"] and ev["user_id"] == k["target_user_id"]
        blob = str([tuple(r) for r in self._read(db_path, "SELECT * FROM auth_events")])
        assert token not in blob and _hash_code(token) not in blob

    def test_reset_mfa_exits_nonzero_and_shows_no_token_when_the_witness_fails(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        self._seed_user(yaml_path, capsys)
        monkeypatch.setattr(audit_mod, "record_auth_event_txn", _boom)
        with pytest.raises(SystemExit) as ei:
            self._run(yaml_path, "reset-mfa", "--email", "target@example.com")
        assert ei.value.code == 1
        out = capsys.readouterr()
        assert "NOT issued" in out.err
        assert not re.search(r"[0-9a-f]{32}", out.out + out.err)
        assert self._read(db_path, "SELECT id FROM operator_recovery_keys") == []


# ---------------------------------------------------------------------------
# registration: there is no event-type registry; the funnel's redaction-map
# entry is the only registration a grant funnel carries (as record_dev_key_registration)
# ---------------------------------------------------------------------------

def test_the_user_creation_funnel_is_registered_like_the_dev_key_funnel():
    import inspect

    spec = audit_mod._AUDIT_EMITTER_REDACTION_MAP["record_user_creation"]
    params = set(inspect.signature(record_user_creation.__wrapped__).parameters) - {"conn"}
    assert spec["in"] | spec["out"] == params, (spec, params)
    assert not spec["in"] & spec["out"]
    # Free text and addressing identifiers are hash-only, never in the redacted payload.
    assert {"email", "name", "notify_email", "actor_email", "ip"} <= spec["out"]
    assert "record_dev_key_registration" in audit_mod._AUDIT_EMITTER_REDACTION_MAP


def test_the_three_new_events_are_the_ones_the_grant_pin_expects():
    import test_session_epoch_on_revoke_pin as pin

    assert pin._GRANT_EVENTS["users"][0] == "user_created"
    assert pin._GRANT_EVENTS["operator_recovery_keys"][0] == "operator_recovery_key_issued"
    assert pin._GRANT_EVENTS["recovery_codes"][0] == "recovery_codes_issued"
    modules = pin._src_modules()
    for table in ("users", "operator_recovery_keys", "recovery_codes"):
        cls = pin._grant_class(table)
        assert pin._insert_writers([t for _r, t in modules], table), table
        assert pin._unwitnessed_writers(modules, cls) == [], table
