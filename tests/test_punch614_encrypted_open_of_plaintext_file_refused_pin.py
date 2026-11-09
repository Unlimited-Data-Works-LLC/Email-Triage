"""Punch 614: an encrypted open of a PLAINTEXT database file is refused on its header.

Since ``903b96183`` a config that omits ``persistence.encryption_enabled`` resolves
to encrypted, so an existing plaintext install with such a config reached
``init_db_encrypted`` (``PRAGMA key``, then ``PRAGMA journal_mode = WAL``) with no
guard: the refusal was left to SQLCipher's wrong-mode behaviour (panel B2,
db-sme B4c). ``refuse_encrypted_open_of_plaintext_file`` mirrors the punch-547
guard on the same header reader, and both boot paths reach it: the boot contract
(app lifespan and every CLI DB command) and the ``preflight`` deploy check.

Panel B3 db-sme F1: a main file shorter than one header beside a non-empty
``-wal`` is refused in BOTH modes by ``refuse_orphan_wal``, before the mode
branch, because any open deletes that WAL and boots an empty database.

Pure functions; runs without ``sqlcipher3``.
"""
from __future__ import annotations

import ast
import hashlib
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from _pin_harness import REPO_ROOT, parse_module
from email_triage.db import _engine


@pytest.fixture(autouse=True)
def _reset_dedicated_conn_encryption():
    """A CLI run stamps the process-global dedicated-conn encryption context
    (``_cli_stamp_db_encryption``). Where sqlcipher3 is installed (CI) an
    encrypted arm left it encrypted=True, and later plaintext tests on the same
    worker opened their DBs with a key (CI run 38182484137). Reset after every test."""
    yield
    from email_triage.db._engine import reset_dedicated_conn_encryption
    reset_dedicated_conn_encryption()

MAGIC = b"SQLite format 3\x00"


def _cfg(db_path: Path, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(persistence=SimpleNamespace(encryption_enabled=enabled,
                                                       db_path=str(db_path)))


def _snapshot(directory: Path) -> dict:
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(directory.iterdir())}


def _plaintext_db(path: Path) -> None:
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    con.close()


def test_a_plaintext_file_with_encryption_requested_is_refused_untouched(tmp_path):
    db = tmp_path / "triage.db"
    _plaintext_db(db)
    before = _snapshot(tmp_path)
    with pytest.raises(RuntimeError, match="punch 614"):
        _engine.refuse_encrypted_open_of_plaintext_file(_cfg(db))
    assert _snapshot(tmp_path) == before, "the refusal must not touch the database"


def test_the_refusal_names_both_remedies(tmp_path):
    db = tmp_path / "triage.db"
    _plaintext_db(db)
    with pytest.raises(RuntimeError) as exc:
        _engine.refuse_encrypted_open_of_plaintext_file(_cfg(db))
    assert "encryption_enabled: false" in str(exc.value)
    assert "email-triage db encrypt" in str(exc.value)


@pytest.mark.parametrize("make", ["missing", "empty", "ciphertext"])
def test_new_and_encrypted_files_are_not_refused(tmp_path, make):
    db = tmp_path / "triage.db"
    if make == "empty":
        db.write_bytes(b"")
    elif make == "ciphertext":
        db.write_bytes(bytes(range(16)) + b"\x00" * 4080)
    _engine.refuse_orphan_wal(_cfg(db))
    _engine.refuse_encrypted_open_of_plaintext_file(_cfg(db))


def test_encryption_not_requested_is_not_this_guards_business(tmp_path):
    db = tmp_path / "triage.db"
    _plaintext_db(db)
    _engine.refuse_encrypted_open_of_plaintext_file(_cfg(db, enabled=False))


def _crash_copy(tmp_path: Path) -> Path:
    """A main file shorter than one header beside a -wal that holds data, built
    by hand. Panel B3 db-sme F1 measured that SQLite's own crash path never
    produces it (page 1 reaches the main file at ``PRAGMA journal_mode=WAL``,
    before any WAL frame), so it is external damage: a truncated main file or a
    partial restore."""
    live = tmp_path / "live"
    live.mkdir()
    src = live / "triage.db"
    con = sqlite3.connect(src)
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA wal_autocheckpoint = 0")
    con.execute("CREATE TABLE t (x)")
    con.execute("INSERT INTO t VALUES (1)")
    con.commit()
    crash = tmp_path / "crash"
    crash.mkdir()
    dst = crash / "triage.db"
    dst.write_bytes(src.read_bytes()[:0])  # the main file truncated to nothing
    shutil.copyfile(str(src) + "-wal", str(dst) + "-wal")
    con.close()
    return dst


_MODES = pytest.mark.parametrize("enabled", [True, False],
                                 ids=["encryption-on-614", "encryption-off-547"])


@_MODES
def test_an_orphan_wal_is_refused_in_both_modes_untouched(tmp_path, enabled):
    """Any open of a zero-page database deletes its -wal and builds an empty
    database (db-sme, measured), so the refusal is the same in both modes."""
    db = _crash_copy(tmp_path)
    assert Path(str(db) + "-wal").stat().st_size > 0
    before = _snapshot(db.parent)
    with pytest.raises(RuntimeError, match="orphan WAL"):
        _engine.refuse_orphan_wal(_cfg(db, enabled=enabled))
    assert _snapshot(db.parent) == before, "the refusal must not touch the database"
    assert not _engine.db_file_looks_plaintext(db)


@_MODES
def test_the_boot_contract_refuses_an_orphan_wal_before_its_mode_branch(tmp_path, enabled):
    """The 547 side (config OFF: the plaintext open used to delete the WAL and
    create a fresh database) and the 614 side (config ON) both refuse at the
    boot contract, before the plaintext open or the sqlcipher3 and key checks."""
    db = _crash_copy(tmp_path)
    with pytest.raises(RuntimeError, match="orphan WAL"):
        _engine.enforce_db_encryption_boot_contract(
            _cfg(db, enabled=enabled), master_key_available=True)


def test_an_encrypted_page_one_in_the_wal_is_refused(tmp_path):
    """FLIPPED at the panel B3 fold (db-sme F1). This test used to require that a
    short main file beside a WAL whose page 1 is ciphertext OPENS ("a crashed
    fresh encrypted database"). db-sme measured that SQLite deletes the WAL of a
    zero-page database on open, in either cipher mode, then builds an empty
    database that boots healthy: the old expectation defended the data-loss
    path. It is refused in both modes now."""
    db = tmp_path / "triage.db"
    db.write_bytes(b"")
    page = 4096
    header = b"\x37\x7f\x06\x82" + (3007000).to_bytes(4, "big") + page.to_bytes(4, "big") + b"\x00" * 20
    frame = (1).to_bytes(4, "big") + b"\x00" * 20
    Path(str(db) + "-wal").write_bytes(header + frame + bytes(range(256)) * (page // 256))
    for enabled in (True, False):
        with pytest.raises(RuntimeError, match="orphan WAL"):
            _engine.refuse_orphan_wal(_cfg(db, enabled=enabled))


PAGE = 512
CIPHER = bytes(range(16))


def _wal(db: Path, frames, salts=b"\x11" * 8) -> None:
    """A hand-built WAL: frames are (pgno, first 16 bytes, frame salts or None)."""
    header = (b"\x37\x7f\x06\x82" + (3007000).to_bytes(4, "big") + PAGE.to_bytes(4, "big")
              + b"\x00" * 4 + salts + b"\x00" * 8)
    body = b""
    for pgno, head, fsalts in frames:
        fh = pgno.to_bytes(4, "big") + b"\x00" * 4 + (fsalts or salts) + b"\x00" * 8
        body += fh + head + b"\x00" * (PAGE - len(head))
    db.write_bytes(b"")
    Path(str(db) + "-wal").write_bytes(header + body)


@pytest.mark.parametrize("frames", [
    [(2, CIPHER, None), (1, MAGIC, None)],              # plaintext page 1, not first
    [(1, MAGIC, b"\x22" * 8), (1, CIPHER, None)],       # stale plaintext, current cipher
    [(1, MAGIC, b"\x22" * 8)],                          # only a stale page 1
    [(2, CIPHER, None)],                                # no page 1 at all
], ids=["page-one-not-first", "stale-then-current", "stale-only", "no-page-one"])
def test_any_non_empty_wal_beside_a_short_main_file_is_refused(tmp_path, frames):
    """What the WAL's page 1 holds no longer changes the answer (the frame
    parser is gone): every open deletes the WAL, so every shape refuses."""
    db = tmp_path / "triage.db"
    _wal(db, frames)
    for enabled in (True, False):
        with pytest.raises(RuntimeError, match="orphan WAL"):
            _engine.refuse_orphan_wal(_cfg(db, enabled=enabled))


def test_an_empty_wal_beside_an_empty_main_file_is_new(tmp_path):
    db = tmp_path / "triage.db"
    db.write_bytes(b"")
    Path(str(db) + "-wal").write_bytes(b"")
    for enabled in (True, False):
        _engine.refuse_orphan_wal(_cfg(db, enabled=enabled))


def test_an_uninspectable_wal_is_refused(tmp_path, monkeypatch):
    db = tmp_path / "triage.db"
    db.write_bytes(b"")
    real_stat = Path.stat

    def _stat(self, *args, **kwargs):
        if str(self).endswith("-wal"):
            raise PermissionError("denied")
        return real_stat(self, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(Path, "stat", _stat)
        with pytest.raises(RuntimeError, match="Do NOT restore or delete anything"):
            _engine.refuse_orphan_wal(_cfg(db))


def test_an_unreadable_main_file_beside_a_live_wal_is_undecidable_not_orphan(tmp_path, monkeypatch):
    """Panel B3 db-sme fold check FC-1: an unreadable HEALTHY main file must not
    read as an orphan WAL, whose advice (restore a backup) would overwrite it."""
    db = tmp_path / "triage.db"
    _plaintext_db(db)
    Path(str(db) + "-wal").write_bytes(b"\x00" * 64)
    real_open = open

    def _open(file, *args, **kwargs):
        if str(file) == str(db):
            raise PermissionError("denied")
        return real_open(file, *args, **kwargs)

    with monkeypatch.context() as m:
        m.setattr(_engine, "open", _open, raising=False)
        assert _engine._db_content_kind(db) == "undecidable"
        assert _engine.db_file_looks_encrypted(db) is False
        with pytest.raises(RuntimeError, match="Do NOT restore or delete anything"):
            _engine.refuse_orphan_wal(_cfg(db))


@_MODES
def test_preflight_refuses_an_orphan_wal(tmp_path, capsys, enabled):
    """The deploy check refuses (78) in both modes, so deploy.sh aborts at 5a'."""
    import argparse

    from email_triage._env_registry import RETIRED_ENV_EXIT_CODE
    from email_triage.cli import cmd_preflight

    db = _crash_copy(tmp_path)
    cfg = tmp_path / "email-triage.yaml"
    cfg.write_text(
        f"persistence:\n  encryption_enabled: {str(enabled).lower()}\n"
        f"  db_path: {db.as_posix()}\n", encoding="utf-8")
    assert cmd_preflight(argparse.Namespace(config=str(cfg))) == RETIRED_ENV_EXIT_CODE
    assert "orphan WAL" in capsys.readouterr().err


def test_one_header_reader_serves_both_guards():
    """PD-5: the punch-547 and punch-614 predicates read the header through ONE
    function, so they cannot disagree on what a plaintext header is."""
    tree = parse_module(REPO_ROOT / "src" / "email_triage" / "db" / "_engine.py")
    calls = {}
    readers = ("db_file_looks_encrypted", "_db_content_kind")
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name in readers + ("db_file_looks_plaintext",):
            calls[n.name] = {c.func.id for c in ast.walk(n)
                             if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    assert set(calls) == set(readers) | {"db_file_looks_plaintext"}
    assert all("_db_header" in calls[r] for r in readers), calls
    assert "_db_content_kind" in calls["db_file_looks_plaintext"], calls
    opens = [n.name for n in ast.walk(tree)
             if isinstance(n, ast.FunctionDef)
             and any(isinstance(c, ast.Call) and getattr(c.func, "id", None) == "open"
                     for c in ast.walk(n))
             and n.name in readers + ("db_file_looks_plaintext",)]
    assert opens == [], f"a predicate reads the header itself: {opens}"


def test_every_boot_path_reaches_the_guard():
    """The boot contract (app lifespan and every CLI DB command) and the
    preflight deploy check both call the guard."""
    engine = parse_module(REPO_ROOT / "src" / "email_triage" / "db" / "_engine.py")
    cli = parse_module(REPO_ROOT / "src" / "email_triage" / "cli.py")

    def callers(tree, guard: str = "refuse_encrypted_open_of_plaintext_file") -> set[str]:
        out = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.FunctionDef):
                for c in ast.walk(n):
                    if (isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
                            and c.func.id == guard):
                        out.add(n.name)
        return out

    assert "enforce_db_encryption_boot_contract" in callers(engine)
    # By name (panel B3 hipaa-sme F5): any cli function calling the guard
    # would satisfy a bare non-empty check.
    assert "cmd_preflight" in callers(cli), (
        "the preflight deploy check (cmd_preflight) must call the punch-614 guard"
    )
    # Panel B3 db-sme F1: the orphan-WAL refusal holds in BOTH modes, so the boot
    # contract runs it before its mode branch, and preflight runs it too.
    assert "enforce_db_encryption_boot_contract" in callers(engine, "refuse_orphan_wal")
    assert "cmd_preflight" in callers(cli, "refuse_orphan_wal")
    contract = next(n for n in ast.walk(engine) if isinstance(n, ast.FunctionDef)
                    and n.name == "enforce_db_encryption_boot_contract")
    first_branch = min(n.lineno for n in ast.walk(contract) if isinstance(n, ast.If))
    orphan_call = min(c.lineno for c in ast.walk(contract) if isinstance(c, ast.Call)
                      and getattr(c.func, "id", None) == "refuse_orphan_wal")
    assert orphan_call < first_branch, "refuse_orphan_wal must run before the mode branch"
