"""Tests for the ``email-triage restore`` CLI subcommand (#65)."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

from email_triage.backup import (
    MAGIC_FULL,
    MAGIC_KEY_ONLY,
    build_full_bundle,
    build_key_only_bundle,
)
from email_triage.cli import cmd_restore


_PASSPHRASE = "operator-strong-passphrase-32-chars"


class _FakeSecrets:
    def __init__(self, mkey: str = "fake-master-key-32-bytes-padded"):
        self._k = mkey

    def get(self, k):
        return self._k if k == "ET_MASTER_KEY" else None

    def set(self, k, v):
        pass

    def list_keys(self):
        return ["ET_MASTER_KEY"]

    def require(self, k):
        v = self.get(k)
        if v is None:
            raise KeyError(k)
        return v


def _seed_db(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        "CREATE TABLE settings (key TEXT PRIMARY KEY, "
        "value_json TEXT NOT NULL, updated_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE log_entries ("
        "  id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "  ts TEXT NOT NULL, level TEXT, logger TEXT, "
        "  message TEXT, extra_json TEXT)"
    )
    conn.execute(
        "INSERT INTO settings (key, value_json, updated_at) "
        "VALUES ('k', '{}', datetime('now'))"
    )
    conn.commit()
    return conn


def _make_full_bundle(tmp_path: Path) -> Path:
    db_path = tmp_path / "src.db"
    conn = _seed_db(db_path)
    cfg = tmp_path / "src.yaml"
    cfg.write_text("classifier:\n  backend: ollama\n", encoding="utf-8")
    bundle = build_full_bundle(
        db_conn=conn,
        config_path=cfg,
        data_dir=tmp_path,
        cert_dir=None,
        secrets_provider=_FakeSecrets(),
        master_key_name="ET_MASTER_KEY",
        passphrase=_PASSPHRASE,
        operator_email="cli@test",
        hostname="testhost",
    )
    conn.close()
    bp = tmp_path / "test.etbk"
    bp.write_bytes(bundle)
    return bp


def _make_key_bundle(tmp_path: Path, mkey: str = "real-key-32-bytes-pad") -> Path:
    bundle = build_key_only_bundle(
        secrets_provider=_FakeSecrets(mkey=mkey),
        master_key_name="ET_MASTER_KEY",
        passphrase=_PASSPHRASE,
        operator_email="cli@test",
        hostname="testhost",
    )
    bp = tmp_path / "test.etbkkey"
    bp.write_bytes(bundle)
    return bp


def _make_args(**kwargs):
    """Build an argparse Namespace with the restore-subcommand fields."""
    defaults = dict(
        bundle="",
        target_dir="",
        master_key_out="",
        passphrase_file="",
        list=False,
        commit=False,
        force=False,
        config=None,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Full-bundle round-trip
# ---------------------------------------------------------------------------

class TestFullBundleRestore:
    def test_round_trip(self, tmp_path, capsys):
        bundle = _make_full_bundle(tmp_path)
        target = tmp_path / "out"
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")

        args = _make_args(
            bundle=str(bundle),
            target_dir=str(target),
            passphrase_file=str(passfile),
            force=True,
        )
        rc = cmd_restore(args)
        assert rc == 0
        assert (target / "triage.db").is_file()
        assert (target / "email-triage.yaml").is_file()
        captured = capsys.readouterr().out
        assert "testhost" in captured
        assert "Extracted:" in captured

    def test_list_mode_does_not_extract(self, tmp_path, capsys):
        bundle = _make_full_bundle(tmp_path)
        target = tmp_path / "out"
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")

        args = _make_args(
            bundle=str(bundle),
            target_dir=str(target),
            passphrase_file=str(passfile),
            list=True,
        )
        rc = cmd_restore(args)
        assert rc == 0
        assert not target.exists()
        captured = capsys.readouterr().out
        # Manifest summary printed even in list mode.
        assert "Files:" in captured
        assert "Extracted:" not in captured

    def test_wrong_passphrase_returns_1(self, tmp_path):
        bundle = _make_full_bundle(tmp_path)
        passfile = tmp_path / "pass.txt"
        passfile.write_text("totally-wrong-passphrase-32-here", encoding="utf-8")

        args = _make_args(
            bundle=str(bundle),
            target_dir=str(tmp_path / "out"),
            passphrase_file=str(passfile),
            force=True,
        )
        rc = cmd_restore(args)
        assert rc == 1

    def test_missing_bundle_file_returns_1(self, tmp_path, capsys):
        args = _make_args(bundle=str(tmp_path / "nope.etbk"))
        rc = cmd_restore(args)
        assert rc == 1
        assert "not found" in capsys.readouterr().out.lower()

    def test_non_bundle_file_returns_1(self, tmp_path, capsys):
        # Not a backup bundle -- just random bytes.
        garbage = tmp_path / "garbage.bin"
        garbage.write_bytes(b"this is not an email-triage bundle" * 10)
        args = _make_args(bundle=str(garbage))
        rc = cmd_restore(args)
        assert rc == 1


# ---------------------------------------------------------------------------
# Key-only round-trip
# ---------------------------------------------------------------------------

class TestKeyOnlyRestore:
    def test_round_trip_writes_master_key(self, tmp_path, capsys):
        bundle = _make_key_bundle(tmp_path, mkey="real-key-32-bytes-pad")
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")
        out_path = tmp_path / "extracted_key"

        args = _make_args(
            bundle=str(bundle),
            master_key_out=str(out_path),
            passphrase_file=str(passfile),
            force=True,
        )
        rc = cmd_restore(args)
        assert rc == 0
        assert out_path.is_file()
        assert out_path.read_bytes() == b"real-key-32-bytes-pad"
        captured = capsys.readouterr().out
        assert "key-only" in captured

    def test_missing_master_key_out_returns_2(self, tmp_path, capsys):
        bundle = _make_key_bundle(tmp_path)
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")
        # No --master-key-out specified.
        args = _make_args(
            bundle=str(bundle),
            passphrase_file=str(passfile),
            force=True,
        )
        rc = cmd_restore(args)
        assert rc == 2
        assert "master-key-out" in capsys.readouterr().out

    def test_list_mode_skips_extract_check(self, tmp_path):
        """--list should print manifest without requiring --master-key-out
        even for key-only bundles. Inspecting before deciding where the
        key goes is a valid workflow."""
        bundle = _make_key_bundle(tmp_path)
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")
        args = _make_args(
            bundle=str(bundle),
            passphrase_file=str(passfile),
            list=True,
        )
        rc = cmd_restore(args)
        assert rc == 0


# ---------------------------------------------------------------------------
# Confirmation prompt path
# ---------------------------------------------------------------------------

class TestConfirmationPrompt:
    def test_user_says_no_aborts_cleanly(self, tmp_path, capsys, monkeypatch):
        """No --force; user types 'n' at the prompt; CLI exits 0
        without writing files. Operator-driven decision -- not an
        error case."""
        bundle = _make_full_bundle(tmp_path)
        target = tmp_path / "out"
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")

        # Stub builtins.input to simulate the operator declining.
        monkeypatch.setattr("builtins.input", lambda *_: "n")

        args = _make_args(
            bundle=str(bundle),
            target_dir=str(target),
            passphrase_file=str(passfile),
            force=False,
        )
        rc = cmd_restore(args)
        assert rc == 0
        assert not target.exists()
        assert "Aborted" in capsys.readouterr().out

    def test_user_says_yes_proceeds(self, tmp_path, capsys, monkeypatch):
        bundle = _make_full_bundle(tmp_path)
        target = tmp_path / "out"
        passfile = tmp_path / "pass.txt"
        passfile.write_text(_PASSPHRASE, encoding="utf-8")

        monkeypatch.setattr("builtins.input", lambda *_: "y")

        args = _make_args(
            bundle=str(bundle),
            target_dir=str(target),
            passphrase_file=str(passfile),
            force=False,
        )
        rc = cmd_restore(args)
        assert rc == 0
        assert (target / "triage.db").is_file()
