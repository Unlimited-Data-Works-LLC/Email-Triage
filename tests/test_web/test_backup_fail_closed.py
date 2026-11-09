""" — run_backup_once must FAIL CLOSED even when the master-key read raises.

The final SME devils-advocate pass caught a silent-failure regression: the
master-key read sat OUTSIDE the try, so a SecretNotFound/decrypt failure killed
the run BEFORE the FAILURE status + audit were written — leaving the stale
success marker looking fresh. This pins the fix: a master-key failure writes a
FAILURE _LAST_RUN.json (so the freshness monitor / --wait CLI see it) and
re-raises, and NEVER the success marker."""

from __future__ import annotations

import asyncio
import sqlite3
import types

import pytest

from email_triage import backup as backup_mod
from email_triage.web import background_sweepers as bs


class _FakeSecrets:
    """Minimal SecretsProvider stand-in (mirrors tests/test_backup.py)."""

    def __init__(self, store):
        self._store = dict(store)

    def get(self, key):
        return self._store.get(key)

    def require(self, key):
        return self._store[key]

    def list_keys(self):
        return list(self._store)


def _seed_min_db(path):
    """A minimal but VALID SQLite DB so build_full_bundle's snapshot +
    write_verified_etbk's integrity gate have a real, traversable DB."""
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT, "
        "updated_at TEXT)"
    )
    conn.execute(
        "CREATE TABLE log_entries (id INTEGER PRIMARY KEY, ts TEXT, "
        "level TEXT, logger TEXT, message TEXT, extra_json TEXT)"
    )
    conn.execute(
        "INSERT INTO settings VALUES ('k', '{\"v\":1}', datetime('now'))"
    )
    # schema_migrations so read_db_schema_version returns a real MAX(version) —
    # the value the backup manifest must record (NOT the unset app.state.schema_version).
    conn.execute("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)")
    conn.executemany(
        "INSERT INTO schema_migrations (version) VALUES (?)", [(1,), (48,), (49,)]
    )
    conn.commit()
    return conn


def test_run_backup_once_fails_closed_on_master_key_error(tmp_path, monkeypatch):
    # run_backup_once runs on the explicit-trigger path regardless of the
    # config gate; a .backup section isn't required for this fail-closed test.
    cfg = types.SimpleNamespace(
        persistence=types.SimpleNamespace(db_path=str(tmp_path / "triage.db")),
        secrets=types.SimpleNamespace(master_key_name="k"),
        backup=types.SimpleNamespace(
            enabled=True, cadence="manual", format="etbk", retention="14", dir="",
        ),
    )
    app = types.SimpleNamespace(
        state=types.SimpleNamespace(config=cfg, db=None, version="t", schema_version=1)
    )

    # The master-key read raises (lazy import inside run_backup_once → patch at
    # the source module).
    def _boom(_c):
        raise RuntimeError("SecretNotFound")

    monkeypatch.setattr("email_triage.secrets.read_bootstrap_master_key", _boom)

    # The audit write would need a real DB conn; stub it (the audit failure is
    # itself best-effort — the test is about the FAILURE STATUS file).
    async def _noop_audit(db, *, outcome, detail):
        return None

    monkeypatch.setattr(bs, "_record_backup_audit", _noop_audit)

    out_dir = tmp_path / "backups"  # _backup_out_dir → <db_path parent>/backups

    # The run re-raises the master-key error...
    with pytest.raises(RuntimeError):
        asyncio.run(bs.run_backup_once(app, "etbk", trigger="cli"))

    # ...but FAILS CLOSED: a FAILURE per-run status was written, and NO success
    # marker masquerades as fresh.
    st = backup_mod.read_run_status(out_dir)
    assert st is not None and st["outcome"] == "failure"
    assert backup_mod.read_backup_marker(out_dir) is None


def test_run_backup_once_refuses_public_key_with_db_format(tmp_path, monkeypatch):
    """devils-advocate FATAL-1: ``encryption=public-key`` + the raw ``db``
    snapshot is a silent fail-OPEN — the off-box seal is applied ONLY by the
    etbk path, so a db snapshot would be readable with the on-box master key.
    The run actuator must REFUSE the combo (fail-closed: FAILURE status, NO
    success marker, NO snapshot file written) so a hand-edited YAML can't arm
    it even though the save form rejects it."""
    cfg = types.SimpleNamespace(
        persistence=types.SimpleNamespace(db_path=str(tmp_path / "triage.db")),
        secrets=types.SimpleNamespace(master_key_name="k"),
        backup=types.SimpleNamespace(
            enabled=True, cadence="manual", format="db", retention="14",
            dir="", encryption="public-key",
            public_key="-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----",
        ),
    )
    app = types.SimpleNamespace(
        state=types.SimpleNamespace(config=cfg, db=None, version="t", schema_version=1)
    )

    # Master-key read SUCCEEDS (the refusal must happen on the format/mode combo,
    # not because the key is missing).
    monkeypatch.setattr(
        "email_triage.secrets.read_bootstrap_master_key", lambda _c: b"\x00" * 32,
    )

    async def _noop_audit(db, *, outcome, detail):
        return None

    monkeypatch.setattr(bs, "_record_backup_audit", _noop_audit)

    out_dir = tmp_path / "backups"

    with pytest.raises(backup_mod.BackupError):
        asyncio.run(bs.run_backup_once(app, "db", trigger="cli"))

    # Fail-closed: a FAILURE status, NO success marker, and crucially NO snapshot
    # file was produced (no master-key-readable "public-key" backup landed).
    st = backup_mod.read_run_status(out_dir)
    assert st is not None and st["outcome"] == "failure"
    assert backup_mod.read_backup_marker(out_dir) is None
    snaps = list(out_dir.glob("*.db")) if out_dir.is_dir() else []
    assert snaps == []


def test_run_backup_once_etbk_produces_a_verified_bundle(tmp_path, monkeypatch):
    """REGRESSION (operator hit it LIVE 2026-06-18): run_backup_once passed the
    DB conn POSITIONALLY to build_full_bundle, which is keyword-only
    (``def build_full_bundle(*, db_conn, …)``) — so EVERY automated .etbk backup
    crashed with a TypeError ('takes 0 positional arguments…'). The manual export
    route already used db_conn=db; the automated path didn't. Prior tests mocked
    run_backup_once / monkeypatched the master-key read, so the real
    build_full_bundle call was NEVER executed (mock-the-boundary-not-the-seam).

    This EXECUTES the full etbk path end-to-end — REAL build_full_bundle + REAL
    write_verified_etbk (restorability gate) — so a positional/keyword or
    signature regression on either fails here. With the bug present this test
    raises TypeError; with the fix it lands a verified bundle."""
    db_path = tmp_path / "triage.db"
    conn = _seed_min_db(db_path)
    (tmp_path / "email-triage.yaml").write_text(
        "classifier:\n  backend: ollama\n", encoding="utf-8",
    )
    out_dir = tmp_path / "backups"

    cfg = types.SimpleNamespace(
        persistence=types.SimpleNamespace(db_path=str(db_path)),
        secrets=types.SimpleNamespace(
            master_key_name="ET_MASTER_KEY", backend="auto",
            keyfile_path="", external=None,
        ),
        tls=types.SimpleNamespace(cert_dir=""),
        backup=types.SimpleNamespace(
            enabled=True, cadence="manual", format="etbk", retention="14",
            dir=str(out_dir), encryption="master-key", public_key="",
        ),
    )
    app = types.SimpleNamespace(
        state=types.SimpleNamespace(
            config=cfg, db=conn, version="abc123def456", schema_version=42,
        ),
    )

    # Master key resolves; the bootstrap provider is a fake holding it. The
    # build_full_bundle + write_verified_etbk calls themselves are REAL.
    monkeypatch.setattr(
        "email_triage.secrets.read_bootstrap_master_key", lambda _c: b"\x00" * 32,
    )
    monkeypatch.setattr(
        "email_triage.web.routers.backup._make_bootstrap_provider",
        lambda _config: _FakeSecrets(
            {"ET_MASTER_KEY": "fernet-key-base64-here-32-bytes-padded"},
        ),
    )
    monkeypatch.setattr(
        "email_triage.db._engine.dedicated_conn_is_encrypted", lambda: False,
    )

    async def _noop_audit(db, *, outcome, detail):
        return None

    monkeypatch.setattr(bs, "_record_backup_audit", _noop_audit)

    try:
        result = asyncio.run(bs.run_backup_once(app, "etbk", trigger="cli"))
    finally:
        conn.close()

    # Success path: a verified .etbk landed + the success marker is written.
    assert result.get("outcome") == "success"
    etbks = list(out_dir.glob("*.etbk"))
    assert len(etbks) == 1, f"expected one .etbk, got {etbks}"
    st = backup_mod.read_run_status(out_dir)
    assert st is not None and st["outcome"] == "success"
    assert backup_mod.read_backup_marker(out_dir) is not None

    # REGRESSION (operator caught it 2026-06-18 in a restore --list verify):
    # the manifest must record the REAL DB schema (MAX schema_migrations = 49),
    # not the never-populated app.state.schema_version (set to 42 above) and not
    # the old hardcoded default of 1.
    pp = backup_mod.derive_etbk_passphrase(b"\x00" * 32)
    manifest = backup_mod.unbundle(etbks[0].read_bytes(), passphrase=pp).manifest
    assert manifest["schema_version"] == 49, (
        f"manifest schema_version={manifest['schema_version']} — expected 49 "
        "(the real DB schema), not app.state.schema_version/1"
    )
