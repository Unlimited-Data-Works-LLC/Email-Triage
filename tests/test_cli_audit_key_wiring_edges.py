"""Edges of the punch 844 key-wiring fix, from the drive-647 SME panel.

* Break-glass (punch 709): ``user disable --emergency`` and ``apikey delete
  --emergency`` exist for a broken chain, so a key-wiring failure must not stop
  them (hipaa MUST-1). Every other verb still refuses.
* The N-157 start gate refuses when the key wiring itself fails, not only when
  the emit fails (hipaa SHOULD-2).
* ``audit reconcile`` opens its own connection; it must wire the keys before its
  divergence event, and never drop that event silently (db MUST-1 / DA MUST-2).
* A keyless N-467 gap row between keyed ones leaves the gap chain intact, so it
  cannot block ``clear_emergency_revoke`` (DA cross-examination).

The registry is cleared where the test stands for a fresh CLI process: the
autouse conftest key would otherwise hide the missing wiring.
"""
from __future__ import annotations

import argparse
import sqlite3

import pytest
from test_audit_reconciliation import _seed_account
from test_cli_audit import _hipaa_config_file, _parse  # noqa: F401 - fixture

import email_triage.cli as cli_mod
from email_triage.db import audit as A

REASON = "suspected_intrusion"


def _boom(*_a, **_kw):
    raise RuntimeError("secrets store damaged")


def _run(yaml_path, *argv):
    cmd = {"user": cli_mod.cmd_user, "apikey": cli_mod.cmd_apikey}[argv[0]]
    return cmd(_parse(["--config", str(yaml_path), *argv]))


def _q(db_path, sql):
    c = sqlite3.connect(str(db_path))
    try:
        return c.execute(sql).fetchall()
    finally:
        c.close()


@pytest.fixture()
def victim(_hipaa_config_file, capsys):
    yaml_path, db_path, _cfg = _hipaa_config_file
    assert _run(yaml_path, "user", "create", "--email", "victim@example.com") == 0
    assert _run(yaml_path, "apikey", "create", "--user", "victim@example.com", "--name", "doomed") == 0
    (kid,) = _q(db_path, "SELECT id FROM api_keys WHERE name = 'doomed'")[0]
    capsys.readouterr()
    return yaml_path, db_path, kid


def test_emergency_revokes_proceed_when_the_keys_cannot_be_wired(victim, capsys, monkeypatch):
    yaml_path, db_path, kid = victim
    monkeypatch.setattr(cli_mod, "_cli_wire_audit_keys", _boom)
    assert _run(yaml_path, "apikey", "delete", str(kid), "--emergency", "--reason", REASON) == 0
    assert _run(yaml_path, "user", "disable", "--email", "victim@example.com",
                "--emergency", "--reason", REASON) == 0
    assert _q(db_path, "SELECT id FROM api_keys WHERE name = 'doomed'") == []
    assert _q(db_path, "SELECT disabled FROM users WHERE email = 'victim@example.com'") == [(1,)]
    assert "proceeding with the EMERGENCY revoke" in capsys.readouterr().err


def test_a_plain_revoke_still_refuses_when_the_keys_cannot_be_wired(victim, monkeypatch):
    yaml_path, db_path, kid = victim
    monkeypatch.setattr(cli_mod, "_cli_wire_audit_keys", _boom)
    with pytest.raises(cli_mod.CliAuditGateClosed):
        _run(yaml_path, "apikey", "delete", str(kid))
    assert _q(db_path, "SELECT id FROM api_keys WHERE name = 'doomed'") == [(kid,)]


def test_the_start_gate_refuses_when_the_key_wiring_fails(_hipaa_config_file, monkeypatch):
    yaml_path, _db, _cfg = _hipaa_config_file
    monkeypatch.setattr(cli_mod, "_cli_wire_audit_keys", _boom)
    args = argparse.Namespace(config=str(yaml_path))
    with pytest.raises(cli_mod.CliAuditGateClosed, match="RuntimeError"):
        cli_mod._emit_cli_audit_event("probe", args, phase="start")
    # The explicit break-glass still passes, and the end phase stays fail-soft.
    cli_mod._emit_cli_audit_event("probe", argparse.Namespace(
        config=str(yaml_path), emergency=True), phase="start")
    cli_mod._emit_cli_audit_event("probe", args, phase="end", exit_code=0)


def test_reconcile_records_its_divergence_event_from_a_fresh_registry(
    _hipaa_config_file, capsys, monkeypatch,
):
    from email_triage.db import reconciliation as R

    yaml_path, db_path, _cfg = _hipaa_config_file
    report = R.ReconciliationReport(
        generated_at="2026-11-03T00:00:00+00:00", chain_verify_passed=True,
        chain_break_reason=None, chain_length=0, tables=[], divergence_count=1,
    )
    monkeypatch.setattr(R, "verify_phi_table_against_audit_log", lambda *_a, **_k: report)
    c = sqlite3.connect(str(db_path))  # the event anchors on a HIPAA-flagged account
    try:
        _seed_account(c, hipaa=True)
    finally:
        c.close()
    A._clear_hmac_keys_for_test()  # a fresh CLI process: nothing wired yet
    cli_mod.cmd_audit_reconcile(_parse(["--config", str(yaml_path), "audit", "reconcile"]))
    assert "NOT recorded" not in capsys.readouterr().err
    rows = _q(db_path, "SELECT operation FROM hipaa_access_events "
                       "WHERE operation = 'reconcile_divergence_detected'")
    assert rows == [("reconcile_divergence_detected",)]


def test_reconcile_says_so_when_the_event_cannot_be_recorded(
    _hipaa_config_file, capsys, monkeypatch,
):
    from email_triage.db import reconciliation as R

    yaml_path, _db, _cfg = _hipaa_config_file
    report = R.ReconciliationReport(
        generated_at="2026-11-03T00:00:00+00:00", chain_verify_passed=True,
        chain_break_reason=None, chain_length=0, tables=[], divergence_count=1,
    )
    monkeypatch.setattr(R, "verify_phi_table_against_audit_log", lambda *_a, **_k: report)
    monkeypatch.setattr(cli_mod, "_cli_wire_audit_keys", _boom)
    cli_mod.cmd_audit_reconcile(_parse(["--config", str(yaml_path), "audit", "reconcile"]))
    assert "the divergence audit event was NOT recorded (RuntimeError" in capsys.readouterr().err


def test_a_keyless_gap_row_between_keyed_rows_keeps_the_gap_chain_intact(tmp_path):
    from email_triage.web.db import init_db

    conn = init_db(tmp_path / "t.db")
    try:
        for name, keyed in (("seed", True), ("failed_mint", False), ("later", True)):
            A._clear_hmac_keys_for_test()
            if keyed:
                A._set_hmac_key_for_test(b"k" * 32)
            A._write_audit_gap_event(conn, helper_name=name, args=(), kwargs={},
                                     exc=RuntimeError(name))
            conn.commit()
        A._set_hmac_key_for_test(b"k" * 32)
        algs = [r[0] for r in conn.execute(
            f"SELECT hash_alg FROM {A.GAP_CHAIN_TABLE} ORDER BY id")]
        assert algs[1] == "sha256" and algs[0] == algs[2] != "sha256", algs
        gap = A.verify_gap_chain(conn)
        assert (gap["intact"], gap["break_count"], gap["keyless_count"],
                gap["downgrade_count"]) == (True, 0, 1, 0), gap
        assert all(r["intact"] for r in A.verify_all_audit_chains(conn).values())
    finally:
        conn.close()
