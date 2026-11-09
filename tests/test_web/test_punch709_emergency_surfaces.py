"""Punch 709: the surfaces of the emergency revoke, run for real.

(a) ``/health/detail`` degrades (503) while the emergency marker is set and says why;
    it does not degrade without it. The handler runs, not a stub (style guide PD-17).
(b) The CLI: ``apikey delete --emergency --reason`` revokes through a broken witness against a
    FILE database, so the marker lands beside the database file (the real
    ``PRAGMA database_list`` resolution); ``--emergency`` and ``--reason`` must come together;
    ``user disable`` exists only as the emergency command; ``audit clear-emergency-flag`` clears
    the marker only once the chain is repaired, and leaves its chained
    ``emergency_revoke_cleared`` row naming the CLI actor.
"""
from __future__ import annotations

import sqlite3

import pytest

import email_triage.db.audit as audit_mod
from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
from test_cli_audit import _hipaa_config_file, _parse  # noqa: F401  (fixture + parser, reused)

REASON = "suspected_intrusion"


def _admin_cookie_pair():
    return (SESSION_COOKIE_NAME,
            create_session_token("test-session-secret-for-signing", "admin@test.com", "admin"))


class TestHealthSurface:
    def test_detail_degrades_while_the_marker_is_set(
            self, client, db, app, admin_user, tmp_path, monkeypatch):
        monkeypatch.setattr(
            audit_mod, "_emergency_marker_path",
            lambda conn: tmp_path / audit_mod.EMERGENCY_REVOKE_MARKER)
        client.cookies.set(*_admin_cookie_pair())
        clean = client.get("/health/detail").json()
        assert clean["emergency_revoke_pending"] is False
        (tmp_path / audit_mod.EMERGENCY_REVOKE_MARKER).write_text("x", encoding="utf-8")
        resp = client.get("/health/detail")
        body = resp.json()
        assert body["emergency_revoke_pending"] is True
        assert body["status"] == "degraded" and resp.status_code == 503


def _boom(*_a, **_kw):
    raise RuntimeError("audit storage exploded")


class TestCli:
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
        from email_triage.cli import _cmd_audit_dispatch, cmd_apikey, cmd_user
        cmd = {"user": cmd_user, "audit": _cmd_audit_dispatch}.get(argv[0], cmd_apikey)
        return cmd(_parse(["--config", str(yaml_path), *argv]))

    def _seed_key(self, yaml_path, db_path, capsys) -> int:
        assert self._run(yaml_path, "user", "create", "--email", "keyholder@example.com") == 0
        assert self._run(yaml_path, "apikey", "create", "--user", "keyholder@example.com",
                         "--name", "cli-doomed") == 0
        capsys.readouterr()
        (row,) = self._read(db_path, "SELECT id FROM api_keys WHERE name = 'cli-doomed'")
        return row["id"]

    def test_apikey_delete_emergency_revokes_through_a_broken_witness(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
        assert self._run(yaml_path, "apikey", "delete", str(key_id),
                         "--emergency", "--reason", REASON) == 0
        assert f"API key {key_id} deleted." in capsys.readouterr().out
        assert self._read(db_path, "SELECT id FROM api_keys WHERE id = ?", (key_id,)) == []
        assert self._read(
            db_path, "SELECT id FROM api_key_events WHERE event = 'api_key_revoked'") == []
        (gap,) = self._read(
            db_path, "SELECT exc_msg FROM audit_gap_events WHERE helper_name = 'emergency_revoke'")
        assert f"kind=api_key table=api_key_events target_id={key_id} actor=cli" in gap["exc_msg"]
        assert f"reason={REASON}" in gap["exc_msg"]
        assert (db_path.parent / audit_mod.EMERGENCY_REVOKE_MARKER).exists()

    def test_audit_verify_reports_the_known_gap_beside_the_verdict(
            self, _hipaa_config_file, capsys, monkeypatch):
        """Cycle P hipaa Q3: ``audit verify --all-chains`` names the emergency revoke as a
        known gap of ``api_key_events``, on its own line, --quiet included."""
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        with monkeypatch.context() as m:
            m.setattr(audit_mod, "record_api_key_event_txn", _boom)
            assert self._run(yaml_path, "apikey", "delete", str(key_id),
                             "--emergency", "--reason", REASON) == 0
        capsys.readouterr()
        self._run(yaml_path, "audit", "verify", "--all-chains")
        out = capsys.readouterr().out
        assert "audit verify: api_key_events: 1 known emergency-revoke gap(s)" in out, out
        assert "user_status_events: 0 known" not in out  # only a table with a gap is named
        self._run(yaml_path, "audit", "verify", "--all-chains", "--quiet")
        assert "KNOWN-GAPS api_key_events emergency_revoke=1" in capsys.readouterr().out

    def test_the_flag_and_its_reason_must_come_together(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        monkeypatch.setattr(audit_mod, "record_api_key_event_txn", _boom)
        for extra in (["--emergency"], ["--reason", REASON]):
            with pytest.raises(SystemExit) as ei:
                self._run(yaml_path, "apikey", "delete", str(key_id), *extra)
            assert ei.value.code == 2
        assert self._read(db_path, "SELECT id FROM api_keys WHERE id = ?", (key_id,))
        assert not (db_path.parent / audit_mod.EMERGENCY_REVOKE_MARKER).exists()

    def test_a_healthy_chain_with_the_flag_writes_no_gap_row_and_no_marker(
            self, _hipaa_config_file, capsys):
        yaml_path, db_path, _cfg = _hipaa_config_file
        key_id = self._seed_key(yaml_path, db_path, capsys)
        assert self._run(yaml_path, "apikey", "delete", str(key_id),
                         "--emergency", "--reason", REASON) == 0
        assert self._read(
            db_path, "SELECT id FROM audit_gap_events WHERE helper_name = 'emergency_revoke'") == []
        assert self._read(
            db_path, "SELECT id FROM api_key_events WHERE event = 'api_key_revoked'")
        assert not (db_path.parent / audit_mod.EMERGENCY_REVOKE_MARKER).exists()

    def test_user_disable_is_the_emergency_command_only(self, _hipaa_config_file):
        yaml_path, _db_path, _cfg = _hipaa_config_file
        with pytest.raises(SystemExit) as ei:
            _parse(["--config", str(yaml_path), "user", "disable", "--email", "a@example.com"])
        assert ei.value.code == 2

    @pytest.mark.audit_failure_expected(
        match="cli_admin_op:user", count=2,
        reason="the chain is broken on purpose: the CLI start and end rows cannot be written")
    def test_user_disable_emergency_disables_and_clear_waits_for_the_repair(
            self, _hipaa_config_file, capsys, monkeypatch):
        yaml_path, db_path, _cfg = _hipaa_config_file
        self._seed_key(yaml_path, db_path, capsys)
        marker = db_path.parent / audit_mod.EMERGENCY_REVOKE_MARKER
        with monkeypatch.context() as m:
            m.setattr(audit_mod, "_get_current_hmac_version", lambda: None)
            assert self._run(yaml_path, "user", "disable", "--email", "keyholder@example.com",
                             "--emergency", "--reason", REASON) == 0
            (u,) = self._read(db_path, "SELECT disabled FROM users WHERE email = ?",
                              ("keyholder@example.com",))
            assert u["disabled"] == 1 and marker.exists()
            assert self._run(yaml_path, "audit", "clear-emergency-flag") == 1  # still broken
            assert marker.exists()
        cleared_sql = ("SELECT exc_msg, master_key_version FROM audit_gap_events "
                       "WHERE helper_name = 'emergency_revoke_cleared'")
        assert self._read(db_path, cleared_sql) == []  # a refused clear records nothing
        capsys.readouterr()
        assert self._run(yaml_path, "audit", "clear-emergency-flag") == 0  # repaired
        assert not marker.exists()
        assert "flag cleared" in capsys.readouterr().out
        (row,) = self._read(db_path, cleared_sql)  # the clear is a chained row: who, and ts
        assert row["exc_msg"].startswith("emergency_revoke_cleared actor=cli")
        assert row["master_key_version"] is not None
