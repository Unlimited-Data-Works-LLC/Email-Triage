""" — the Admin → Backup automated-backup CONFIG form + its save handler.

Two halves:
  * GET render (rule 17 — assert the rendered VIEW, under StrictUndefined so a
    template↔context drift 500s loudly instead of rendering blank).
  * POST /admin/backup/config-save — the config path (question 3: "enabled via
    CLI or the backup UI"). The fail-closed validations are the point: a
    public-key mode armed against a bad/empty key, or a junk retention spec, is
    rejected BEFORE the in-memory config is touched — never persisted only to
    FAIL every later unattended backup run.

YAML persistence itself is covered by
``tests/test_config_roundtrip.py::test_backup_config_roundtrip``; here the
writer is monkeypatched to a no-op so the success path doesn't depend on a
config file existing in the test app (matching the test_config.py convention of
asserting the in-memory mutation + deferring round-trip to the roundtrip suite).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

_WRITER = "email_triage.web.routers.ui._shared._write_config_yaml"


def _valid_x25519_pubkey_pem() -> str:
    priv = X25519PrivateKey.generate()
    return priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


# ---------------------------------------------------------------------------
# GET render
# ---------------------------------------------------------------------------

def test_backup_tab_renders_automated_form(
    client, admin_cookies, strict_undefined_templates,
):
    """The Backup tab renders the new Automated-backup form. StrictUndefined
    makes a missing context key (build_backup_context drift) a 500, not a blank
    field — so this is a real contract test, not just a 200 check."""
    resp = client.get("/config?tab=backup", cookies=admin_cookies)
    assert resp.status_code == 200
    body = resp.text
    assert "Automated backup" in body
    assert 'name="enabled"' in body
    assert 'name="encryption"' in body
    assert 'name="public_key"' in body
    assert 'name="cadence"' in body
    assert 'name="retention"' in body
    # The stale "no automation involved" copy must be GONE.
    assert "no automation involved" not in body
    # In-page ℹ️ help (the operator's ask): field tooltips + the X25519
    # disclosure with the Windows-friendly generation command.
    assert "data-tooltip" in body          # field ℹ️ tooltips present
    assert 'class="info-help"' in body      # the expandable disclosure
    assert "What is an X25519 key" in body  # the disclosure summary
    assert "python -m email_triage backup gen-keypair" in body  # Windows-friendly
    assert "age-keygen" in body             # the "don't use age" pitfall


def test_backup_tab_forbidden_for_regular_user(client, user_cookies):
    resp = client.get("/config?tab=backup", cookies=user_cookies)
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# POST /admin/backup/config-save — success
# ---------------------------------------------------------------------------

def test_config_save_master_key_success(client, app, admin_cookies, monkeypatch):
    monkeypatch.setattr(_WRITER, lambda config: None)
    resp = client.post(
        "/admin/backup/config-save",
        data={
            "enabled": "1",
            "cadence": "daily",
            "format": "db",
            "retention": "2w",
            "encryption": "master-key",
            "dir": "/srv/backups/et",
        },
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_msg" in resp.headers["location"]
    bk = app.state.config.backup
    assert bk.enabled is True
    assert bk.cadence == "daily"
    assert bk.format == "db"
    assert bk.retention == "2w"
    assert bk.encryption == "master-key"
    assert bk.dir == "/srv/backups/et"


def test_config_save_publickey_accepts_valid_x25519(
    client, app, admin_cookies, monkeypatch,
):
    monkeypatch.setattr(_WRITER, lambda config: None)
    pem = _valid_x25519_pubkey_pem()
    resp = client.post(
        "/admin/backup/config-save",
        data={
            "enabled": "1",
            "cadence": "weekly",
            "format": "etbk",
            "retention": "14",
            "encryption": "public-key",
            "public_key": pem,
        },
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_msg" in resp.headers["location"]
    assert app.state.config.backup.encryption == "public-key"
    assert "BEGIN PUBLIC KEY" in app.state.config.backup.public_key


# ---------------------------------------------------------------------------
# POST — fail-closed validation (reject BEFORE mutating config)
# ---------------------------------------------------------------------------

def _backup_snapshot(app):
    bk = app.state.config.backup
    return (bk.enabled, bk.cadence, bk.format, bk.retention,
            bk.encryption, bk.public_key, bk.dir)


def test_config_save_publickey_requires_key(client, app, admin_cookies, monkeypatch):
    """public-key mode with NO key is rejected — never persisted (else every
    unattended run would FAIL on seal)."""
    monkeypatch.setattr(_WRITER, lambda config: None)
    before = _backup_snapshot(app)
    resp = client.post(
        "/admin/backup/config-save",
        data={"enabled": "1", "encryption": "public-key", "public_key": "",
              "cadence": "daily", "format": "etbk", "retention": "14"},
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_error" in resp.headers["location"]
    assert _backup_snapshot(app) == before  # unchanged — fail-closed


def test_config_save_publickey_rejects_garbage(client, app, admin_cookies, monkeypatch):
    """A non-PEM / wrong-type key is rejected at config time, not at run time."""
    monkeypatch.setattr(_WRITER, lambda config: None)
    before = _backup_snapshot(app)
    resp = client.post(
        "/admin/backup/config-save",
        data={"enabled": "1", "encryption": "public-key",
              "public_key": "-----BEGIN PUBLIC KEY-----\nnot-base64!!!\n-----END PUBLIC KEY-----",
              "cadence": "daily", "format": "etbk", "retention": "14"},
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_error" in resp.headers["location"]
    assert _backup_snapshot(app) == before


def test_config_save_rejects_public_key_with_db_format(
    client, app, admin_cookies, monkeypatch,
):
    """devils-advocate FATAL-1: public-key + the raw ``db`` snapshot would be
    readable with the on-box master key (no seal layer) — voiding the mode's
    whole guarantee. The save form must REFUSE the combo, not persist it."""
    monkeypatch.setattr(_WRITER, lambda config: None)
    pem = _valid_x25519_pubkey_pem()
    before = _backup_snapshot(app)
    resp = client.post(
        "/admin/backup/config-save",
        data={"enabled": "1", "encryption": "public-key", "public_key": pem,
              "cadence": "daily", "format": "db", "retention": "14"},
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_error" in resp.headers["location"]
    assert _backup_snapshot(app) == before  # unchanged — fail-closed


def test_config_save_rejects_bad_retention(client, app, admin_cookies, monkeypatch):
    monkeypatch.setattr(_WRITER, lambda config: None)
    before = _backup_snapshot(app)
    resp = client.post(
        "/admin/backup/config-save",
        data={"enabled": "1", "encryption": "master-key",
              "cadence": "daily", "format": "etbk", "retention": "banana"},
        cookies=admin_cookies,
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "save_error" in resp.headers["location"]
    assert _backup_snapshot(app) == before


def test_config_save_forbidden_for_regular_user(client, user_cookies):
    resp = client.post(
        "/admin/backup/config-save",
        data={"enabled": "1", "encryption": "master-key",
              "cadence": "manual", "format": "etbk", "retention": "14"},
        cookies=user_cookies,
        follow_redirects=False,
    )
    assert resp.status_code in (302, 303, 403)
    # Whatever the redirect/deny shape, a non-admin must NOT have saved.
