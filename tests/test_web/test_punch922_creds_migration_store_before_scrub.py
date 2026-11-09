"""Punch 922 (panel r17 db-sme SHOULD-B5): the per-account -> install-level
OAuth creds migrations committed the config_json scrub BEFORE the caller
stored the install-level secret, so a ``secrets.set`` failure lost the creds.

Now the caller's store runs inside the migration (``persist=``) before any
scrub UPDATE; a raise leaves nothing scrubbed. (Before any UPDATE, not just
before the commit: the prod ``DbSecrets.set`` commits the same connection.)
"""

from __future__ import annotations

import ast
import json

import pytest

from _pin_harness import iter_src_files, parse_module, relpath
from email_triage.secrets import DbSecrets, read_secret
from email_triage.web.oauth_secret_keys import (
    GOOGLE_OAUTH_WEB_CLIENT_ID,
    GOOGLE_OAUTH_WEB_CLIENT_SECRET,
    O365_OAUTH_CLIENT_ID,
    O365_OAUTH_TENANT_ID,
)
from email_triage.web.db import (
    migrate_o365_creds_to_install_level,
    migrate_oauth_creds_to_install_level,
)

_NOW = "2026-11-08T00:00:00+00:00"


def _account(db, provider: str, cfg: dict) -> int:
    uid = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (f"u{provider}@x.com", "U", "admin", _NOW),
    ).lastrowid
    aid = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 0, ?, ?)",
        (uid, "A", provider, json.dumps(cfg), _NOW, _NOW),
    ).lastrowid
    db.commit()
    return aid


def _cfg(db, aid: int) -> dict:
    return json.loads(db.execute(
        "SELECT config_json FROM email_accounts WHERE id = ?", (aid,)).fetchone()[0])


def test_gmail_store_failure_keeps_per_account_creds(db):
    aid = _account(db, "gmail_api", {"client_id": "cid", "client_secret": "sec"})

    def boom(pair):
        assert _cfg(db, aid) == {"client_id": "cid", "client_secret": "sec"}, (
            "persist must run before any scrub UPDATE")
        raise RuntimeError("secrets store down")

    with pytest.raises(RuntimeError):
        migrate_oauth_creds_to_install_level(db, persist=boom)
    assert _cfg(db, aid) == {"client_id": "cid", "client_secret": "sec"}

    got = []
    assert migrate_oauth_creds_to_install_level(db, persist=got.append) == ("cid", "sec")
    assert got == [("cid", "sec")]
    assert _cfg(db, aid) == {}


def test_o365_store_failure_keeps_per_account_creds(db):
    aid = _account(db, "office365", {"tenant_id": "t-guid", "client_id": "cid"})

    def boom(triple):
        assert _cfg(db, aid) == {"tenant_id": "t-guid", "client_id": "cid"}, (
            "persist must run before any scrub UPDATE")
        raise RuntimeError("secrets store down")

    with pytest.raises(RuntimeError):
        migrate_o365_creds_to_install_level(db, None, persist=boom)
    assert _cfg(db, aid) == {"tenant_id": "t-guid", "client_id": "cid"}

    got = []
    assert migrate_o365_creds_to_install_level(db, None, persist=got.append) == (
        "t-guid", "cid", "")
    assert got == [("t-guid", "cid", "")]
    assert _cfg(db, aid) == {}


def test_no_lift_means_no_persist_call(db):
    _account(db, "gmail_api", {"account": "a@gmail.com"})
    called = []
    assert migrate_oauth_creds_to_install_level(db, persist=called.append) is None
    assert migrate_o365_creds_to_install_level(db, None, persist=called.append) is None
    assert called == []


class _FailOn(DbSecrets):
    """Prod wiring: DbSecrets on the SAME conn, whose set() commits it."""

    fail_on: str | None = None

    def set(self, key, value):
        if key == self.fail_on:
            raise RuntimeError(f"injected store failure on {key}")
        super().set(key, value)


def _boot(db, secrets, monkeypatch):
    from email_triage.config import TriageConfig
    from email_triage.providers import factory

    for name in ("set_install_google_oauth", "set_install_office365_oauth",
                 "set_install_ingestion_config"):
        monkeypatch.setattr(factory, name, lambda *_a, **_k: None)
    factory.hydrate_and_register_install_oauth(TriageConfig(), secrets, db)


@pytest.mark.parametrize("fail_key", [
    GOOGLE_OAUTH_WEB_CLIENT_ID, GOOGLE_OAUTH_WEB_CLIENT_SECRET])
def test_gmail_dbsecrets_same_conn_failure_then_reboot(db, monkeypatch, fail_key):
    """hipaa-sme MUST-1: DbSecrets.set commits the shared conn, so a store
    after the scrub UPDATEs committed a half scrub; and a stored ID with a
    failed SECRET was never refilled (guard keyed on the ID only)."""
    aid = _account(db, "gmail_api", {"client_id": "cid", "client_secret": "sec"})
    s = _FailOn(db, DbSecrets.generate_master_key())
    s.fail_on = fail_key
    with pytest.raises(RuntimeError):
        _boot(db, s, monkeypatch)
    assert _cfg(db, aid) == {"client_id": "cid", "client_secret": "sec"}

    s.fail_on = None
    _boot(db, s, monkeypatch)
    assert _cfg(db, aid) == {}
    assert read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_ID) == "cid"
    assert read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_SECRET) == "sec"


def test_gmail_filling_the_id_overwrites_a_stray_secret(db, monkeypatch):
    """db-sme r2 SHOULD: an empty ID slot with an outside-written secret must
    not leave this client's ID paired with that secret."""
    _account(db, "gmail_api", {"client_id": "cid", "client_secret": "sec"})
    s = _FailOn(db, DbSecrets.generate_master_key())
    s.set(GOOGLE_OAUTH_WEB_CLIENT_SECRET, "stray")
    # db-sme r3 NIT: with ID written before SECRET, a SECRET failure left
    # ID=cid beside the stray secret, and the retry kept the stray one.
    s.fail_on = GOOGLE_OAUTH_WEB_CLIENT_SECRET
    with pytest.raises(RuntimeError):
        _boot(db, s, monkeypatch)
    s.fail_on = None
    _boot(db, s, monkeypatch)
    assert read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_ID) == "cid"
    assert read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_SECRET) == "sec"


def test_gmail_secret_never_paired_with_another_client(db, monkeypatch):
    _account(db, "gmail_api", {"client_id": "cid", "client_secret": "sec"})
    s = _FailOn(db, DbSecrets.generate_master_key())
    s.set(GOOGLE_OAUTH_WEB_CLIENT_ID, "other")
    _boot(db, s, monkeypatch)
    assert read_secret(s, GOOGLE_OAUTH_WEB_CLIENT_SECRET) is None


@pytest.mark.parametrize("fail_key", [
    O365_OAUTH_TENANT_ID, O365_OAUTH_CLIENT_ID])
def test_o365_dbsecrets_same_conn_failure_then_reboot(db, monkeypatch, fail_key):
    aid = _account(db, "office365", {"tenant_id": "t-guid", "client_id": "cid"})
    s = _FailOn(db, DbSecrets.generate_master_key())
    s.fail_on = fail_key
    with pytest.raises(RuntimeError):
        _boot(db, s, monkeypatch)
    assert _cfg(db, aid) == {"tenant_id": "t-guid", "client_id": "cid"}

    s.fail_on = None
    _boot(db, s, monkeypatch)
    assert _cfg(db, aid) == {}
    assert read_secret(s, O365_OAUTH_TENANT_ID) == "t-guid"
    assert read_secret(s, O365_OAUTH_CLIENT_ID) == "cid"


def test_o365_decrypt_error_after_a_set_keeps_creds(db, monkeypatch):
    """DA MUST-1 second trigger: read_secret raising SecretsDecryptError after
    an earlier set in the same persist must not leave a committed scrub."""
    from email_triage.secrets import SecretsDecryptError

    aid = _account(db, "office365", {"tenant_id": "t-guid", "client_id": "cid"})
    s = _FailOn(db, DbSecrets.generate_master_key())
    real_get = DbSecrets.get

    def get(self, key):
        if key == O365_OAUTH_CLIENT_ID:
            raise SecretsDecryptError(key)
        return real_get(self, key)

    monkeypatch.setattr(_FailOn, "get", get)
    with pytest.raises(SecretsDecryptError):
        _boot(db, s, monkeypatch)
    assert _cfg(db, aid) == {"tenant_id": "t-guid", "client_id": "cid"}


_MIGRATIONS = {"migrate_oauth_creds_to_install_level", "migrate_o365_creds_to_install_level"}


def _calls_without_persist(tree: ast.AST) -> list[int]:
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
        if name in _MIGRATIONS and not any(k.arg == "persist" for k in node.keywords):
            out.append(node.lineno)
    return out


def test_every_src_caller_passes_persist():
    """Count-agnostic: a src call to either migration without ``persist=``
    would store the secret after the scrub commits (the punch 922 shape)."""
    bad = []
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is not None:
            bad += [f"{relpath(path)}:{ln}" for ln in _calls_without_persist(tree)]
    assert not bad, f"creds migration called without persist= (punch 922): {bad}"


def test_persist_pin_has_teeth():
    assert _calls_without_persist(ast.parse("migrate_oauth_creds_to_install_level(c)\n")) == [1]
    assert _calls_without_persist(ast.parse("db.migrate_o365_creds_to_install_level(c, s)\n")) == [1]
    assert _calls_without_persist(
        ast.parse("migrate_oauth_creds_to_install_level(c, persist=f)\n")) == []
