"""Punch 711 (N-634 residual): a restore leaves a record in the chain the operator keeps.

Trace (verified at HEAD 6079ae06): ``@_cli_audit("restore")`` ->
``_emit_cli_audit_event`` -> ``_cli_open_config_db(config)`` writes its start and
end rows into the LIVE database, ``config.persistence.db_path``. ``cmd_restore``
only extracts to ``target_dir``; the swap-in it prints moves the live file to
``triage.db.preexisting``. So both rows left the kept chain with that file.

Fix: ``cmd_restore`` leaves a PHI-free marker in the live DATA dir (the swap does
not move it); the server boot records it into the post-swap chain
(``backup.ingest_restore_witness_markers``, called from the ``web/app.py``
lifespan) and removes it.
"""
from __future__ import annotations

import ast
import json
import sqlite3

import pytest

from email_triage.backup import (
    RESTORE_WITNESS_GLOB,
    RESTORE_WITNESS_KEYS,
    ingest_restore_witness_markers,
    pending_restore_witness_markers,
    write_restore_witness_marker,
)
from email_triage.cli import cmd_restore
from test_cli_audit import _hipaa_config_file  # noqa: F401  (fixture, reused)
from test_cli_restore import _PASSPHRASE, _make_args, _make_full_bundle

from _pin_harness import SRC_ROOT, parse_module


def _restore(tmp_path, yaml_path):
    src = tmp_path / "bundle-src"
    src.mkdir()
    bundle = _make_full_bundle(src)
    passfile = tmp_path / "pass.txt"
    passfile.write_text(_PASSPHRASE, encoding="utf-8")
    target = tmp_path / "restore-out"
    rc = cmd_restore(_make_args(
        bundle=str(bundle), target_dir=str(target), passphrase_file=str(passfile),
        force=True, config=str(yaml_path),
    ))
    return rc, target


def test_the_cli_rows_land_in_the_live_db_and_the_witness_in_its_data_dir(
        _hipaa_config_file, tmp_path, capsys):
    yaml_path, db_path, _cfg = _hipaa_config_file
    rc, target = _restore(tmp_path, yaml_path)
    assert rc == 0
    assert "restore witness" in capsys.readouterr().out
    # The start/end rows are in the file the printed swap moves aside.
    conn = sqlite3.connect(db_path)
    try:
        msgs = [r[0] for r in conn.execute(
            "SELECT message FROM log_entries WHERE message LIKE 'cli admin op: restore%' "
            "ORDER BY id")]
    finally:
        conn.close()
    assert msgs == ["cli admin op: restore (start)", "cli admin op: restore (end)"]
    # The witness sits beside that file, not in the extracted tree.
    (marker,) = db_path.parent.glob(RESTORE_WITNESS_GLOB)
    assert not list(target.rglob(RESTORE_WITNESS_GLOB))
    body = json.loads(marker.read_text(encoding="utf-8"))
    assert set(body) <= RESTORE_WITNESS_KEYS
    assert body["actor"].startswith("cli:")
    assert body["source_hostname"] == "testhost.invalid"
    assert body["bundle_name"] == "test.etbk"
    # Panel AB MUST C2-711: the newest live chain row (its own start row), host as data.
    conn = sqlite3.connect(db_path)
    try:
        held = conn.execute("SELECT message FROM log_entries WHERE row_hash = ?",
                            (body["live_chain_head"],)).fetchone()
    finally:
        conn.close()
    assert held is not None and held[0] == "cli admin op: restore (start)"
    assert body["cli_hostname"]
    # Punch 720: the head row's own stamp rides the marker (the boot's proof it was not pruned).
    conn = sqlite3.connect(db_path)
    try:
        (head_ts,) = conn.execute("SELECT ts FROM log_entries WHERE row_hash = ?",
                                  (body["live_chain_head"],)).fetchone()
    finally:
        conn.close()
    assert body["live_chain_head_ts"] == head_ts


def test_an_unloadable_config_writes_no_witness(tmp_path):
    """Same gate as the CLI audit rows: no loadable config, no rows to lose."""
    rc, _target = _restore(tmp_path, tmp_path / "absent.yaml")
    assert rc == 0
    assert not list(tmp_path.rglob(RESTORE_WITNESS_GLOB))


def _seed_history(db, ts="2026-09-01T00:00:00+00:00"):
    """A row older than the marker's head, as a restored bundle's earlier history is (punch 720)."""
    from email_triage.db.audit import record_cli_admin_op
    record_cli_admin_op(db, ts=ts, command="restore", phase="start", extra={"cli_command": "restore"})
    db.commit()


def test_the_boot_ingest_records_the_witness_then_removes_it(db, tmp_path):
    _seed_history(db)
    marker = write_restore_witness_marker(tmp_path, {
        "bundle_name": "b.etbk", "actor": "cli:triage", "exported_at": "2026-10-01T00:00:00Z",
        "live_chain_head": "e" * 64,  # a head this (restored) chain does not hold
        "live_chain_head_ts": "2026-10-28T00:00:00+00:00",  # punch 720: the chain holds older history
        "not_a_witness_key": "dropped",
    })
    assert "not_a_witness_key" not in json.loads(marker.read_text(encoding="utf-8"))
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert not marker.exists()
    (row,) = db.execute(
        "SELECT message, extra_json, row_hash FROM log_entries "
        "WHERE message = 'cli admin op: restore (swapped-in)'").fetchall()
    extra = json.loads(row["extra_json"])
    assert extra["actor"] == "cli:triage" and extra["bundle_name"] == "b.etbk"
    assert extra["marker"] == marker.name
    assert row["row_hash"], "the witness row must be chained"
    assert ingest_restore_witness_markers(db, tmp_path) == 0


def test_a_poison_marker_is_recorded_once_kept_and_never_blocks_the_others(db, tmp_path):
    """Panel AB SHOULD-C4: one unreadable marker no longer raises out of the loop."""
    bad = tmp_path / ".restore-witness-0-1.json"
    bad.write_text("{not json", encoding="utf-8")
    good = write_restore_witness_marker(tmp_path, {"bundle_name": "g.etbk", "actor": "cli:t"})
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert bad.exists() and not good.exists()
    assert ingest_restore_witness_markers(db, tmp_path) == 0
    rows = db.execute(
        "SELECT extra_json FROM log_entries WHERE message = "
        "'cli admin op: restore (restore-witness-unreadable)'").fetchall()
    assert len(rows) == 1, "the unreadable marker is recorded once, not every boot"
    assert json.loads(rows[0]["extra_json"])["marker"] == bad.name
    assert pending_restore_witness_markers(tmp_path) == [bad.name]


def _head(db):
    return db.execute(
        "SELECT row_hash FROM log_entries WHERE row_hash != '' ORDER BY id DESC LIMIT 1"
    ).fetchone()[0]


def test_a_marker_whose_chain_head_is_still_here_stays_pending(db, tmp_path):
    """Panel AB MUST C2-711: this database still holds the newest row of the one the
    CLI ran against, so no swap happened (a restart before the mv, or an abandoned
    swap). Recording here would put the witness into the file the swap moves aside."""
    from email_triage.db.audit import record_cli_admin_op
    record_cli_admin_op(db, ts="2026-10-28T00:00:00+00:00", command="restore",
                        phase="start", extra={"cli_command": "restore"})
    db.commit()
    marker = write_restore_witness_marker(tmp_path, {"bundle_name": "b", "live_chain_head": _head(db)})
    assert ingest_restore_witness_markers(db, tmp_path) == 0
    assert marker.exists()
    assert db.execute("SELECT COUNT(*) FROM log_entries WHERE message LIKE "
                      "'cli admin op: restore (swapped-in)'").fetchone()[0] == 0


def test_a_marker_whose_chain_head_is_absent_records_the_swap(db, tmp_path):
    _seed_history(db)
    marker = write_restore_witness_marker(
        tmp_path, {"bundle_name": "b", "live_chain_head": "f" * 64,
                   "live_chain_head_ts": "2026-10-28T00:00:00+00:00", "cli_hostname": "h.invalid"})
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert not marker.exists()
    (row,) = db.execute("SELECT extra_json FROM log_entries WHERE message = "
                        "'cli admin op: restore (swapped-in)'").fetchall()
    extra = json.loads(row["extra_json"])
    assert extra["swap_verified"] is True and extra["cli_hostname"] == "h.invalid"


def test_a_marker_with_no_chain_head_is_never_called_swapped_in(db, tmp_path):
    write_restore_witness_marker(tmp_path, {"bundle_name": "b"})
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert db.execute("SELECT COUNT(*) FROM log_entries WHERE message = "
                      "'cli admin op: restore (swapped-in)'").fetchone()[0] == 0
    (row,) = db.execute("SELECT extra_json FROM log_entries WHERE message = "
                        "'cli admin op: restore (swap-unverified)'").fetchall()
    assert json.loads(row["extra_json"])["swap_verified"] is False


def test_a_marker_already_in_the_chain_is_only_unlinked(db, tmp_path, monkeypatch):
    """Commit-then-unlink: an unlink that failed after the commit must not
    re-record the restore at the next boot (dedupe by marker name)."""
    import pathlib
    marker = write_restore_witness_marker(tmp_path, {"bundle_name": "b"})
    real = pathlib.Path.unlink
    monkeypatch.setattr(pathlib.Path, "unlink", lambda self, *a, **k: (_ for _ in ()).throw(PermissionError("x")))
    with pytest.raises(PermissionError):  # committed, then the unlink failed
        ingest_restore_witness_markers(db, tmp_path)
    assert marker.exists()
    monkeypatch.setattr(pathlib.Path, "unlink", real)
    assert ingest_restore_witness_markers(db, tmp_path) == 0
    assert not marker.exists()
    assert db.execute("SELECT COUNT(*) FROM log_entries WHERE instr(extra_json, ?) > 0",
                      (marker.name,)).fetchone()[0] == 1


def _older_recorded_and_undeletable_plus_a_newer(db, tmp_path, monkeypatch):
    """An older marker already in the chain whose unlink keeps failing (EACCES), and a newer
    marker not yet recorded that sorts after it. Returns ``(older, newer)`` with the unlink of
    ``older`` patched to raise PermissionError."""
    import pathlib
    older = write_restore_witness_marker(tmp_path, {"bundle_name": "old"})
    real = pathlib.Path.unlink

    def unlink(self, *a, **k):
        if self.name == older.name:
            raise PermissionError("EACCES")
        return real(self, *a, **k)

    monkeypatch.setattr(pathlib.Path, "unlink", unlink)
    with pytest.raises(PermissionError):  # recorded and committed, then its unlink failed
        ingest_restore_witness_markers(db, tmp_path)
    newer = tmp_path / older.name.replace(".restore-witness-", ".restore-witness-z", 1)
    newer.write_text(json.dumps({"bundle_name": "new"}), encoding="utf-8")
    assert sorted(p.name for p in tmp_path.glob(RESTORE_WITNESS_GLOB)) == [older.name, newer.name]
    return older, newer


def test_an_undeletable_recorded_marker_does_not_block_a_newer_witness(db, tmp_path, monkeypatch):
    """Punch 726 (hipaa SHOULD-2, class AH fold): before 726 the older marker's unlink raised
    inside the loop on every start, so the newer restore was never recorded. Red on the pre-726
    backup.py (both ways: --red-cwd on a 795e9be4 tree with this test copied in)."""
    older, newer = _older_recorded_and_undeletable_plus_a_newer(db, tmp_path, monkeypatch)
    try:
        ingest_restore_witness_markers(db, tmp_path)
    except PermissionError:
        pass  # the pre-NOTE-6 trailing loop raised; the witness question is the row below
    assert db.execute("SELECT COUNT(*) FROM log_entries WHERE instr(extra_json, ?) > 0",
                      (newer.name,)).fetchone()[0] == 1, "the newer restore was never witnessed"
    assert not newer.exists() and older.exists()


def test_a_failed_trailing_unlink_is_logged_and_keeps_the_count(db, tmp_path, monkeypatch):
    """hipaa NOTE 6 (class AH fold): the trailing unlink loop catches OSError per path, so the
    caller does not log "could not be recorded" for a witness that WAS committed, and the count of
    new markers recorded survives."""
    older, newer = _older_recorded_and_undeletable_plus_a_newer(db, tmp_path, monkeypatch)
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert older.exists() and not newer.exists()


def test_the_backup_collector_never_bundles_a_pending_marker():
    """Panel AB MUST C2-711: structural; the artifact set filters the marker glob."""
    src = (SRC_ROOT / "backup.py").read_text(encoding="utf-8")
    assert "p.match(RESTORE_WITNESS_GLOB)" in src


def test_the_server_boot_calls_the_ingest_on_the_live_data_dir():
    """Structural: the lifespan hands the ingest ``Path(db_path).parent``, and the
    CLI emitter opens the configured (live) DB; together they are the trace."""
    app = parse_module(SRC_ROOT / "web" / "app.py")
    calls = [n for n in ast.walk(app) if isinstance(n, ast.Call)
             and getattr(n.func, "id", None) == "ingest_restore_witness_markers"]
    assert len(calls) == 1
    assert ast.unparse(calls[0].args[1]) == "Path(db_path).parent"
    cli = parse_module(SRC_ROOT / "cli.py")
    emit = next(n for n in ast.walk(cli)
                if isinstance(n, ast.FunctionDef) and n.name == "_emit_cli_audit_event")
    assert any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_cli_open_config_db"
               for n in ast.walk(emit))
    restore = next(n for n in ast.walk(cli)
                   if isinstance(n, ast.FunctionDef) and n.name == "cmd_restore")
    assert any(isinstance(n, ast.Call) and getattr(n.func, "id", None) == "_write_restore_witness"
               for n in ast.walk(restore))
