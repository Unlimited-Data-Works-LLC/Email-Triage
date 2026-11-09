"""Punch 720 and 772: the restore-witness marker's two remaining residuals (backup.py).

720: a marker left pending until ``log_entries`` pruned its head row (by age OR by count; the
boot prunes before it ingests) used to read as swapped-in. The marker now carries the head
row's ``ts`` and the boot records ``swapped-in`` only when the chain still holds history older
than that: both prune axes delete the OLDEST rows first, so a chain that pruned the head holds
nothing older, while a restored chain holds the bundle's earlier history.

772: ``_restore_marker_recorded`` matched the marker name and the phase as substrings of ANY
row's ``extra_json``; it now matches the ``marker``, ``cli_phase`` and ``cli_command`` fields.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from email_triage.backup import (
    _restore_marker_recorded,
    ingest_restore_witness_markers,
    write_restore_witness_marker,
)
from email_triage.db.audit import prune_log_entries_by_age_and_count, record_cli_admin_op


def _iso(**ago) -> str:
    return (datetime.now(timezone.utc) - timedelta(**ago)).isoformat()


def _row(db, ts: str, **extra) -> str:
    """One chained ``restore`` row at ``ts``; returns its ``row_hash``."""
    record_cli_admin_op(db, ts=ts, command="restore", phase="start",
                        extra={"cli_command": "restore", **extra})
    db.commit()
    return db.execute("SELECT row_hash FROM log_entries ORDER BY id DESC LIMIT 1").fetchone()[0]


def _witness_rows(db, phase: str) -> list[dict]:
    return [json.loads(r["extra_json"]) for r in db.execute(
        "SELECT extra_json FROM log_entries WHERE message = ?",
        (f"cli admin op: restore ({phase})",)).fetchall()]


def _held(db, row_hash: str) -> bool:
    return db.execute("SELECT 1 FROM log_entries WHERE row_hash = ?", (row_hash,)).fetchone() is not None


def test_a_head_pruned_by_age_reads_swap_unverified_not_swapped_in(db, tmp_path):
    _row(db, _iso(days=60))
    head_ts = _iso(days=40)
    head = _row(db, head_ts)
    marker = write_restore_witness_marker(tmp_path, {
        "bundle_name": "b", "live_chain_head": head, "live_chain_head_ts": head_ts})
    assert ingest_restore_witness_markers(db, tmp_path) == 0 and marker.exists()  # head still here
    # The boot prunes by age (web/app.py), then ingests.
    assert prune_log_entries_by_age_and_count(db, retention_days=30, max_rows=50000) >= 2
    assert not _held(db, head)
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert _witness_rows(db, "swapped-in") == []
    (extra,) = _witness_rows(db, "swap-unverified")
    assert extra["swap_verified"] is False and extra["swap_unverified_reason"] == "head-may-be-pruned"
    assert extra["marker"] == marker.name and not marker.exists()


def test_a_head_pruned_by_count_reads_swap_unverified_not_swapped_in(db, tmp_path):
    """The count axis prunes a YOUNG head; a horizon check on the marker's age alone misses it."""
    _row(db, _iso(days=2))
    head_ts = _iso(days=1)
    head = _row(db, head_ts)
    write_restore_witness_marker(tmp_path, {
        "bundle_name": "b", "live_chain_head": head, "live_chain_head_ts": head_ts})
    for _ in range(3):
        _row(db, _iso(minutes=1))
    assert prune_log_entries_by_age_and_count(db, retention_days=365, max_rows=3) >= 2
    assert not _held(db, head)
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert _witness_rows(db, "swapped-in") == []
    (extra,) = _witness_rows(db, "swap-unverified")
    assert extra["swap_unverified_reason"] == "head-may-be-pruned"


def test_a_chain_with_older_history_and_no_head_is_a_verified_swap(db, tmp_path):
    _row(db, _iso(days=30))
    write_restore_witness_marker(tmp_path, {
        "bundle_name": "b", "live_chain_head": "d" * 64, "live_chain_head_ts": _iso(days=1)})
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    (extra,) = _witness_rows(db, "swapped-in")
    assert extra["swap_verified"] is True and "swap_unverified_reason" not in extra


def test_a_marker_without_a_usable_head_stamp_is_never_swapped_in(db, tmp_path):
    """Fail closed (PD-8): an old marker has no stamp; a corrupt one parses to NULL."""
    _row(db, _iso(days=30))
    write_restore_witness_marker(tmp_path, {"bundle_name": "old", "live_chain_head": "a" * 64})
    write_restore_witness_marker(tmp_path, {
        "bundle_name": "bad", "live_chain_head": "b" * 64, "live_chain_head_ts": "not a time"})
    assert ingest_restore_witness_markers(db, tmp_path) == 2
    assert _witness_rows(db, "swapped-in") == []
    assert {e["swap_unverified_reason"] for e in _witness_rows(db, "swap-unverified")} == {"head-may-be-pruned"}


def test_history_barely_older_than_the_head_does_not_prove_a_swap(db, tmp_path):
    """The margin: two rows stamped out of order, or a clock stepped back, are not history."""
    head_ts = _iso(days=1)
    _row(db, (datetime.fromisoformat(head_ts) - timedelta(minutes=30)).isoformat())
    write_restore_witness_marker(tmp_path, {
        "bundle_name": "near", "live_chain_head": "c" * 64, "live_chain_head_ts": head_ts})
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert _witness_rows(db, "swapped-in") == []
    assert len(_witness_rows(db, "swap-unverified")) == 1


def test_a_row_that_only_mentions_the_marker_and_phase_is_not_its_witness(db, tmp_path):
    """Punch 772: the name and the phase as TEXT in other fields of another row do not count."""
    name = ".restore-witness-20261102T000000-1.json"
    record_cli_admin_op(db, ts=_iso(minutes=1), command="backup", phase="end", extra={
        "cli_command": "backup", "cli_phase": "end", "note": name, "other": "swapped-in"})
    db.commit()
    assert not _restore_marker_recorded(db, name, ("swapped-in",))
    # A row that names the marker but whose extra_json is not JSON (or not an object) is skipped.
    now = _iso(minutes=1)
    for bad in (f"not json{{ {name}", f'["{name}"]'):
        db.execute("INSERT INTO log_entries (ts, level, logger, message, extra_json, created_at) "
                   "VALUES (?, 'INFO', 't', 'm', ?, ?)", (now, bad, now))
    db.commit()
    assert not _restore_marker_recorded(db, name, ("swapped-in",))
    # Right marker and phase, wrong command: not a restore witness.
    record_cli_admin_op(db, ts=now, command="backup", phase="swapped-in", extra={
        "cli_command": "backup", "cli_phase": "swapped-in", "marker": name})
    db.commit()
    assert not _restore_marker_recorded(db, name, ("swapped-in",))
    # The real witness row counts, for its own marker and phase only.
    record_cli_admin_op(db, ts=now, command="restore", phase="swapped-in", extra={
        "cli_command": "restore", "cli_phase": "swapped-in", "marker": name})
    db.commit()
    assert _restore_marker_recorded(db, name, ("swap-unverified", "swapped-in"))
    assert not _restore_marker_recorded(db, name, ("swap-unverified",))
    assert not _restore_marker_recorded(db, name + "x", ("swapped-in",))


def test_a_marker_named_in_an_unrelated_row_is_still_ingested(db, tmp_path):
    """The 772 false match would have unlinked this marker without ever witnessing it."""
    _row(db, _iso(days=30))
    marker = write_restore_witness_marker(tmp_path, {
        "bundle_name": "b", "live_chain_head": "9" * 64, "live_chain_head_ts": _iso(days=1)})
    record_cli_admin_op(db, ts=_iso(minutes=1), command="backup", phase="end", extra={
        "cli_command": "backup", "cli_phase": "end", "note": marker.name, "other": "swapped-in"})
    db.commit()
    assert ingest_restore_witness_markers(db, tmp_path) == 1
    assert len(_witness_rows(db, "swapped-in")) == 1 and not marker.exists()
