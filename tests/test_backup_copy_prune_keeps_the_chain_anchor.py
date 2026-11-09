"""Panel P F8: the backup copy's log prune keeps the chain verifiable.

``backup._prune_log_entries_in_snapshot`` (the exclude-logs backup) used a raw
``DELETE FROM log_entries WHERE ts < ...`` and skipped ``_capture_chain_anchor``,
so ``audit verify --db`` on the §164.308(a)(7)(ii)(A) exact-copy backup broke at
its new head: the surviving head's ``prev_hash`` names a pruned row. It now goes
through the live prune funnel ``prune_log_entries_by_age_and_count``, which
stamps the anchor in the same transaction.
"""
from __future__ import annotations

from datetime import datetime, timezone

from _db_tracking import track
from email_triage.db.audit import insert_log_entry


def _seed(db_path):
    from email_triage.web.db import init_db
    conn = track(init_db(db_path))
    try:
        for i in range(3):
            insert_log_entry(conn, f"2020-01-01T00:00:0{i}Z", "INFO", "t", f"old{i}")
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        for i in range(2):
            insert_log_entry(conn, now, "INFO", "t", f"new{i}")
        conn.commit()
    finally:
        conn.close()


def _verify(path, capsys) -> tuple[int, str]:
    """rc and the quiet verdict on stdout (stderr can carry unrelated
    stdlib logging noise from the shared test process)."""
    from email_triage.cli import build_parser, cmd_audit_verify
    rc = cmd_audit_verify(build_parser().parse_args(
        ["audit", "verify", "--db", str(path), "--quiet"]))
    cap = capsys.readouterr()
    return rc, cap.out


def test_a_pruned_backup_copy_verifies(tmp_path, capsys):
    from email_triage.backup import _prune_log_entries_in_snapshot
    src = tmp_path / "triage.db"
    _seed(src)
    copy = tmp_path / "backup-copy.db"
    copy.write_bytes(_prune_log_entries_in_snapshot(src.read_bytes()))

    import sqlite3
    c = sqlite3.connect(str(copy))
    try:
        assert c.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0] == 2
    finally:
        c.close()
    rc, out = _verify(copy, capsys)
    assert rc == 0, out
    assert out.strip() == "PASS 2 gap_sentinels=0"


def test_teeth_the_raw_delete_breaks_the_copy(tmp_path, capsys):
    """The pre-F8 shape: the same prune without the anchor head-breaks."""
    import sqlite3
    src = tmp_path / "triage.db"
    _seed(src)
    c = sqlite3.connect(str(src))
    try:
        c.execute("DELETE FROM log_entries WHERE ts < datetime('now', '-30 days')")
        c.commit()
    finally:
        c.close()
    rc, out = _verify(src, capsys)
    assert rc == 1, out
