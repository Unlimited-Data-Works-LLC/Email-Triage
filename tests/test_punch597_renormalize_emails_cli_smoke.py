"""Punch 597 — drive ``email-triage user re-normalize-emails`` end to end through ``cli.main``.

The N-336 bug was ``_init_db(config.persistence.database_path)`` in this verb: an
AttributeError on first invocation (the CLI verb never ran: fail-closed at
runtime) that the structural pin could not see (fail-open in CI). The unit tests
for N-322 exercise the parser and ``canonical_email`` but never ran the verb. These
smokes do: real YAML, real config load, the real ``_cli_open_config_db`` funnel,
a seeded divergent row, ``--apply``, and a read-back.

* Plaintext arm: runs everywhere.
* Encrypted arm: needs ``sqlcipher3`` (Linux / container ``encryption`` extra; no
  Windows wheel). It ``importorskip``s locally and runs on the CI the deploy host runner.
"""
from __future__ import annotations

import json

import pytest

from _db_tracking import track


@pytest.fixture(autouse=True)
def _reset_dedicated_conn_encryption():
    """A CLI run stamps the process-global dedicated-conn encryption context
    (``_cli_stamp_db_encryption``). Where sqlcipher3 is installed (CI) an
    encrypted arm left it encrypted=True, and later plaintext tests on the same
    worker opened their DBs with a key (CI run 38182484137). Reset after every test."""
    yield
    from email_triage.db._engine import reset_dedicated_conn_encryption
    reset_dedicated_conn_encryption()


def _write_yaml(tmp_path, *, db_path, encrypted: bool) -> str:
    # The verb wires the audit-chain HMAC keys from the secrets store before it
    # writes (punch 844), so the store must hold a real Fernet master key, as a
    # deployed install does. The encrypted arm's env master is set by its test.
    from cryptography.fernet import Fernet

    from email_triage.secrets import DbSecrets, create_secrets_provider

    keyfile = tmp_path / "et.key"
    keyfile.write_text(Fernet.generate_key().decode())
    if not encrypted:
        create_secrets_provider(
            "keyfile", keyfile_path=str(keyfile), external_config={},
            master_key_name="ET_MASTER_KEY",
        ).set("ET_MASTER_KEY", DbSecrets.generate_master_key())
    yaml_path = tmp_path / "email-triage.yaml"
    secrets = (
        "secrets:\n  backend: env\n  master_key_name: ET_MASTER_KEY\n"
        if encrypted else
        f"secrets:\n  backend: keyfile\n  keyfile_path: {keyfile}\n"
        "  master_key_name: ET_MASTER_KEY\n"
    )
    yaml_path.write_text(
        "logging:\n  level: INFO\n  format: json\n"
        f"persistence:\n  db_path: {db_path}\n"
        f"  encryption_enabled: {'true' if encrypted else 'false'}\n"
        + secrets
    )
    return str(yaml_path)


def _seed_divergent(config) -> None:
    from email_triage.cli import _cli_open_config_db

    conn = track(_cli_open_config_db(config))
    try:
        conn.execute(
            "INSERT INTO users (email, name, role, created_at, notify_email) "
            "VALUES (?, ?, ?, ?, ?)",
            ("Alice <Alice@Example.COM>", "Alice", "admin",
             "2026-10-10T00:00:00+00:00", "ALICE@example.com"),
        )
        conn.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "hipaa, created_at, updated_at, aliases_json) "
            "VALUES (1, 'Box', 'imap', '{}', 0, ?, ?, ?)",
            ("2026-10-10T00:00:00+00:00", "2026-10-10T00:00:00+00:00",
             json.dumps(["Bob <BOB@Example.com>"])),
        )
        conn.commit()
    finally:
        conn.close()


def _read_back(config) -> tuple[str, str, list]:
    from email_triage.cli import _cli_open_config_db

    conn = track(_cli_open_config_db(config))
    try:
        email, notify = conn.execute("SELECT email, notify_email FROM users").fetchone()
        (aliases,) = conn.execute("SELECT aliases_json FROM email_accounts").fetchone()
        return email, notify, json.loads(aliases)
    finally:
        conn.close()


def _drive(tmp_path, capsys, *, encrypted: bool) -> None:
    from email_triage.cli import load_config, main

    db_path = tmp_path / "triage.db"
    cfg_path = _write_yaml(tmp_path, db_path=db_path, encrypted=encrypted)
    config = load_config(cfg_path)
    _seed_divergent(config)

    rc = main(["--config", cfg_path, "user", "re-normalize-emails"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Users needing re-normalize: 1" in out
    assert "[dry-run]" in out
    assert _read_back(config)[0] == "Alice <Alice@Example.COM>", "dry-run wrote"

    rc = main(["--config", cfg_path, "user", "re-normalize-emails", "--apply"])
    out = capsys.readouterr().out
    assert rc == 0, out
    email, notify, aliases = _read_back(config)
    assert email == "alice@example.com"
    assert notify == "alice@example.com"
    assert aliases == ["bob@example.com"]
    # Panel Z MUST-Z1-1: the sweep re-points the login address, so it writes the
    # chained user_email_changed witness (actor = the kernel CLI principal).
    from email_triage.cli import _cli_actor
    assert _email_witnesses(config) == [(
        1, _cli_actor(), "success",
        "old_email='Alice <Alice@Example.COM>' new_email='alice@example.com' "
        "source=cli actor_user_id=None")]

    # Idempotent: a second sweep finds nothing.
    rc = main(["--config", cfg_path, "user", "re-normalize-emails"])
    assert rc == 0
    assert "Users needing re-normalize: 0" in capsys.readouterr().out
    rc = main(["--config", cfg_path, "user", "re-normalize-emails", "--apply"])
    assert rc == 0
    assert len(_email_witnesses(config)) == 1, "an unchanged address was witnessed"


def _email_witnesses(config) -> list[tuple]:
    from email_triage.cli import _cli_open_config_db

    conn = track(_cli_open_config_db(config))
    try:
        return [tuple(r) for r in conn.execute(
            "SELECT user_id, email, outcome, detail FROM auth_events "
            "WHERE event_type = 'user_email_changed' ORDER BY id").fetchall()]
    finally:
        conn.close()


def test_renormalize_emails_runs_end_to_end_plaintext(tmp_path, capsys):
    _drive(tmp_path, capsys, encrypted=False)


def test_renormalize_emails_runs_end_to_end_encrypted(tmp_path, capsys, monkeypatch):
    pytest.importorskip("sqlcipher3")
    from email_triage.secrets import DbSecrets
    monkeypatch.setenv("ET_MASTER_KEY", DbSecrets.generate_master_key())
    _drive(tmp_path, capsys, encrypted=True)
    # The file on disk is ciphertext, not a plaintext SQLite database.
    head = (tmp_path / "triage.db").read_bytes()[:16]
    assert head != b"SQLite format 3\x00"


# ---------------------------------------------------------------------------
# Punch 703: two users whose login addresses canonicalise to ONE target
# (users.email is UNIQUE). The dry-run names every duplicate target; --apply
# refuses before any write, so the sweep is never left half-done.
# ---------------------------------------------------------------------------

def _seed_duplicate_targets(config) -> None:
    from email_triage.cli import _cli_open_config_db

    conn = track(_cli_open_config_db(config))
    try:
        for email in (
            "Carol <Carol@Example.COM>",   # divergent -> carol@example.com
            "carol@example.com",           # already canonical: the same target
            "Dan@Example.com",             # divergent -> dan@example.com
            "DAN@example.com",             # divergent -> dan@example.com
            "Erin <Erin@Example.com>",     # divergent, no clash
        ):
            conn.execute(
                "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
                (email, "U", "user", "2026-10-10T00:00:00+00:00"),
            )
        conn.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, config_json, "
            "hipaa, created_at, updated_at, aliases_json) "
            "VALUES (1, 'Box', 'imap', '{}', 0, ?, ?, ?)",
            ("2026-10-10T00:00:00+00:00", "2026-10-10T00:00:00+00:00",
             json.dumps(["Bob <BOB@Example.com>"])),
        )
        conn.commit()
    finally:
        conn.close()


def _users_and_aliases(config):
    from email_triage.cli import _cli_open_config_db

    conn = track(_cli_open_config_db(config))
    try:
        users = [tuple(r) for r in conn.execute("SELECT id, email FROM users ORDER BY id")]
        (aliases,) = conn.execute("SELECT aliases_json FROM email_accounts").fetchone()
        return users, json.loads(aliases)
    finally:
        conn.close()


def test_duplicate_targets_are_named_by_the_dry_run_and_refused_by_apply(tmp_path, capsys):
    from email_triage.cli import load_config, main

    db_path = tmp_path / "triage.db"
    cfg_path = _write_yaml(tmp_path, db_path=db_path, encrypted=False)
    config = load_config(cfg_path)
    _seed_duplicate_targets(config)
    before = _users_and_aliases(config)

    rc = main(["--config", cfg_path, "user", "re-normalize-emails"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Duplicate login-address targets (users.email is unique): 2" in out
    assert "'carol@example.com' <- user#1, user#2" in out
    assert "'dan@example.com' <- user#3, user#4" in out
    assert "erin@example.com' <-" not in out
    assert "--apply refuses" in out

    rc = main(["--config", cfg_path, "user", "re-normalize-emails", "--apply"])
    captured = capsys.readouterr()
    assert rc == 1, captured.out
    assert "REFUSED: 2 duplicate login-address target(s)" in captured.err
    assert "nothing was written" in captured.err
    assert "Applied re-normalize" not in captured.out
    # Nothing moved: not the clashing users, not the clean one, not the aliases.
    assert _users_and_aliases(config) == before
    assert _email_witnesses(config) == []


def test_apply_proceeds_once_the_duplicate_is_resolved(tmp_path, capsys):
    from email_triage.cli import _cli_open_config_db, load_config, main

    db_path = tmp_path / "triage.db"
    cfg_path = _write_yaml(tmp_path, db_path=db_path, encrypted=False)
    config = load_config(cfg_path)
    _seed_duplicate_targets(config)
    conn = track(_cli_open_config_db(config))
    try:
        conn.execute("UPDATE users SET email = 'carol.two@example.com' WHERE id = 2")
        conn.execute("UPDATE users SET email = 'dan.two@example.com' WHERE id = 4")
        conn.commit()
    finally:
        conn.close()

    rc = main(["--config", cfg_path, "user", "re-normalize-emails", "--apply"])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert "Duplicate login-address targets" not in out
    users, aliases = _users_and_aliases(config)
    assert dict(users)[1] == "carol@example.com"
    assert dict(users)[3] == "dan@example.com"
    assert dict(users)[5] == "erin@example.com"
    assert aliases == ["bob@example.com"]
