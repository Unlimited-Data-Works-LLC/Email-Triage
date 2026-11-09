"""A fresh CLI process must wire the audit-chain HMAC keys before it grants (punch 844).

Found 2026-11-03 when the operator-approved mint of cve-arc's monitor
credential failed on the deploy host: ``email-triage user create`` refused with
"H-02a ... no HMAC key has been provisioned". The CLI wired the keys only
inside ``_emit_cli_audit_event``, which is HIPAA-gated and fail-soft, so a
grant writer ran in a process with an empty key registry and failed closed.
Failing closed is right; never wiring the keys is the bug. The failed attempt
also wrote one secretless N-467 row into ``audit_gap_events``.

Each case runs the REAL CLI in a SUBPROCESS (``python -m email_triage``): the
key registry is per process, so clearing it in-process would be one more mock
of the boundary that hid this bug. The master key sits in a keyfile store, the
way a deployment holds it, and no test key is set anywhere. The grant's own
chained row must then verify under HMAC, and the gap chain must stay empty.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from _pin_harness import tree_src_env


@pytest.fixture(params=[False, True], ids=["hipaa-off", "hipaa-on"])
def install(request, tmp_path):
    from cryptography.fernet import Fernet

    from email_triage.secrets import DbSecrets, create_secrets_provider
    from email_triage.web.db import init_db

    keyfile, db = tmp_path / "wrap.key", tmp_path / "triage.db"
    keyfile.write_text(Fernet.generate_key().decode())
    create_secrets_provider(
        "keyfile", keyfile_path=str(keyfile), external_config={},
        master_key_name="ET_MASTER_KEY",
    ).set("ET_MASTER_KEY", DbSecrets.generate_master_key())
    init_db(db).close()
    yaml = tmp_path / "email-triage.yaml"
    yaml.write_text(
        f"logging:\n  level: INFO\n  format: json\n  hipaa: {str(request.param).lower()}\n"
        f"secrets:\n  backend: keyfile\n  keyfile_path: {keyfile.as_posix()}\n"
        f"  master_key_name: ET_MASTER_KEY\n"
        f"persistence:\n  db_path: {db.as_posix()}\n  encryption_enabled: false\n"
    )
    return yaml, db


def _cli(yaml: Path, *argv: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "email_triage", "--config", str(yaml), *argv],
        capture_output=True, text=True, env=tree_src_env(), timeout=240,
    )


def _chains(yaml: Path, db: Path) -> dict[str, dict]:
    """Verify every chained table with the keys wired the way the server boot wires them."""
    from email_triage.config import load_config
    from email_triage.db.audit import verify_all_audit_chains
    from email_triage.secrets import bootstrap_secrets_from_config, wire_audit_chain_hmac_keys
    from email_triage.web.db import init_db

    cfg = load_config(str(yaml))
    conn = init_db(db)
    try:
        wire_audit_chain_hmac_keys(bootstrap_secrets_from_config(conn, cfg), cfg)
        return verify_all_audit_chains(conn)
    finally:
        conn.close()


def _assert_keyed_and_no_gap(chains: dict[str, dict], table: str) -> None:
    assert chains[table]["rows_checked"] >= 1, chains[table]
    assert chains[table]["intact"] and chains[table]["keyless_count"] == 0, chains[table]
    assert chains["audit_gap_events"]["rows_checked"] == 0, chains["audit_gap_events"]
    assert all(r["intact"] for r in chains.values()), chains


def test_user_create_in_a_fresh_process_grants(install):
    yaml, db = install
    p = _cli(yaml, "user", "create", "--email", "monitor@monitor.invalid",
             "--name", "monitor", "--role", "health_ro")
    assert p.returncode == 0, p.stdout + p.stderr
    listed = _cli(yaml, "user", "list")
    assert "monitor@monitor.invalid" in listed.stdout and "health_ro" in listed.stdout, listed.stdout
    _assert_keyed_and_no_gap(_chains(yaml, db), "auth_events")


def test_apikey_create_in_a_fresh_process_mints(install):
    yaml, db = install
    p = _cli(yaml, "user", "create", "--email", "monitor@monitor.invalid", "--role", "health_ro")
    assert p.returncode == 0, p.stdout + p.stderr
    p = _cli(yaml, "apikey", "create", "--name", "rt-deps",
             "--user", "monitor@monitor.invalid", "--scope", "GET /health/runtime-deps")
    assert p.returncode == 0, p.stdout + p.stderr
    listed = _cli(yaml, "apikey", "list")
    assert "rt-deps" in listed.stdout, listed.stdout
    _assert_keyed_and_no_gap(_chains(yaml, db), "api_key_events")
