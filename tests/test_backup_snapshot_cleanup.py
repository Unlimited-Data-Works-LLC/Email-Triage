"""Tests for ``email_triage.backup_snapshot_cleanup`` (CR-2b).

The cleanup module retires older ``triage.db.preupgrade-*`` rollback
snapshots when a successful encrypted backup-bundle export has
superseded their safety-net role. Retention rule:

* Always keep the single most-recent snapshot regardless of age.
* Delete snapshots with mtime strictly older than the just-completed
  backup's timestamp.
* No-op when no snapshots exist.
* Never raise -- failures are reported via the result struct.

These tests poke each invariant in isolation. No FastAPI / sqlite
dependencies; only the tmp filesystem.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from email_triage.backup_snapshot_cleanup import (
    CleanupResult,
    cleanup_after_successful_backup,
    cleanup_preupgrade_snapshots,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _touch_snapshot(data_dir: Path, sha: str, *, age_seconds: float) -> Path:
    """Create a snapshot file with mtime set to (now - age_seconds).

    Older age_seconds -> older file. Returns the path.
    """
    path = data_dir / f"triage.db.preupgrade-{sha}"
    path.write_bytes(b"SQLite format 3\x00" + b"x" * 64)
    target = time.time() - age_seconds
    os.utime(path, (target, target))
    return path


# ---------------------------------------------------------------------------
# Empty-state invariants
# ---------------------------------------------------------------------------

class TestNoSnapshots:
    def test_no_op_when_data_dir_missing(self, tmp_path):
        missing = tmp_path / "does-not-exist"
        result = cleanup_preupgrade_snapshots(
            missing, backup_timestamp=time.time(),
        )
        assert isinstance(result, CleanupResult)
        assert result.deleted_count == 0
        assert result.kept_count == 0
        assert result.inspected == ()

    def test_no_op_when_data_dir_has_no_snapshots(self, tmp_path):
        # Some unrelated files that DO NOT match the snapshot glob.
        (tmp_path / "triage.db").write_bytes(b"live")
        (tmp_path / "msal_cache.json").write_text("{}")
        (tmp_path / "certs").mkdir()
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        assert result.deleted_count == 0
        assert result.kept_count == 0


# ---------------------------------------------------------------------------
# Most-recent-snapshot retention
# ---------------------------------------------------------------------------

class TestMostRecentRetained:
    def test_single_old_snapshot_kept_regardless_of_age(self, tmp_path):
        """One snapshot that's older than the backup -- still kept,
        because it's the most recent (only one)."""
        snap = _touch_snapshot(tmp_path, "abc1234", age_seconds=86_400)
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        assert result.deleted_count == 0
        assert result.kept_count == 1
        assert snap.exists()

    def test_most_recent_kept_even_when_older_than_backup(self, tmp_path):
        """Two snapshots, both older than the backup. Most-recent is
        still kept; the older one is deleted."""
        old = _touch_snapshot(tmp_path, "old1234", age_seconds=7200)
        newer = _touch_snapshot(tmp_path, "new5678", age_seconds=3600)
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        assert result.deleted_count == 1
        assert result.kept_count == 1
        assert newer.exists(), "most-recent snapshot must survive"
        assert not old.exists(), "older snapshot must be deleted"


# ---------------------------------------------------------------------------
# Backup-timestamp gating
# ---------------------------------------------------------------------------

class TestBackupTimestampGate:
    def test_snapshot_newer_than_backup_kept(self, tmp_path):
        """A snapshot taken AFTER the backup represents state the
        backup couldn't capture. Must be kept."""
        old = _touch_snapshot(tmp_path, "old1111", age_seconds=10_000)
        newer = _touch_snapshot(tmp_path, "new2222", age_seconds=100)
        # Backup ran 5000s ago — newer survives because its mtime is
        # within the last 100s; old is older than the backup.
        backup_ts = time.time() - 5_000
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=backup_ts,
        )
        assert newer.exists()
        assert not old.exists()
        assert result.deleted_count == 1
        assert result.kept_count == 1

    def test_snapshot_older_than_backup_deleted(self, tmp_path):
        """Snapshots strictly older than the backup are deleted
        (except the most-recent, which is always retained)."""
        # Three snapshots: most-recent (300s ago), middle (3600s ago),
        # oldest (7200s ago). Backup ran 1200s ago. middle + oldest
        # should be deleted; most-recent is kept by the always-keep
        # rule.
        oldest = _touch_snapshot(tmp_path, "ooooo", age_seconds=7200)
        middle = _touch_snapshot(tmp_path, "mmmmm", age_seconds=3600)
        recent = _touch_snapshot(tmp_path, "rrrrr", age_seconds=300)
        backup_ts = time.time() - 1200
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=backup_ts,
        )
        assert recent.exists(), "most-recent must always be kept"
        assert not middle.exists(), "older-than-backup must be deleted"
        assert not oldest.exists(), "older-than-backup must be deleted"
        assert result.deleted_count == 2
        assert result.kept_count == 1


# ---------------------------------------------------------------------------
# Filesystem-mtime semantics
# ---------------------------------------------------------------------------

class TestRespectsFilesystemMtime:
    def test_sort_order_is_by_mtime_not_filename(self, tmp_path):
        """Two snapshots; alphabetically the older-suffix file sorts
        first, but mtime says the other one is newer. The mtime-
        based selection must keep the mtime-newer file."""
        # alphabetically-earlier name, but freshly touched.
        a_path = _touch_snapshot(tmp_path, "aaaaaa", age_seconds=60)
        # alphabetically-later name, but much older.
        z_path = _touch_snapshot(tmp_path, "zzzzzz", age_seconds=10_000)
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        # 'a' is newer (most-recent) -> kept; 'z' is older -> deleted.
        assert a_path.exists()
        assert not z_path.exists()
        assert result.deleted_count == 1


# ---------------------------------------------------------------------------
# Sibling files are not collateral damage
# ---------------------------------------------------------------------------

class TestUnrelatedFilesUntouched:
    def test_only_glob_matches_inspected(self, tmp_path):
        """The cleanup must touch ONLY files matching the
        ``triage.db.preupgrade-*`` glob. The live DB, msal cache,
        cert dir, and unrelated misc files must survive untouched."""
        # Sibling files.
        live = tmp_path / "triage.db"
        live.write_bytes(b"LIVE-DB")
        live_mtime_pre = live.stat().st_mtime
        msal = tmp_path / "msal_cache.json"
        msal.write_text("{}")
        sibling = tmp_path / "unrelated-backup.tar"
        sibling.write_bytes(b"xxx")
        # And two genuine snapshots.
        old = _touch_snapshot(tmp_path, "old1", age_seconds=7200)
        newer = _touch_snapshot(tmp_path, "new2", age_seconds=3600)
        cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        # Snapshot cleanup ran. Now check non-snapshot files.
        assert live.exists(), "live DB must not be touched"
        assert msal.exists(), "msal cache must not be touched"
        assert sibling.exists(), "unrelated files must not be touched"
        assert live.read_bytes() == b"LIVE-DB"
        # Sibling-file mtimes must not be perturbed either.
        assert live.stat().st_mtime == live_mtime_pre
        # Snapshot housekeeping happened.
        assert newer.exists()
        assert not old.exists()


# ---------------------------------------------------------------------------
# CleanupResult shape
# ---------------------------------------------------------------------------

class TestCleanupResult:
    def test_result_lists_every_file_inspected(self, tmp_path):
        a = _touch_snapshot(tmp_path, "a1", age_seconds=100)
        b = _touch_snapshot(tmp_path, "b2", age_seconds=200)
        c = _touch_snapshot(tmp_path, "c3", age_seconds=300)
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        # All three considered.
        assert len(result.inspected) == 3
        # Most-recent kept; other two deleted (both older than backup).
        assert result.kept_count == 1
        assert result.deleted_count == 2
        # Kept and deleted lists are disjoint.
        kept_set = set(result.kept)
        deleted_set = set(result.deleted)
        assert not (kept_set & deleted_set)

    def test_result_errors_field_empty_on_clean_run(self, tmp_path):
        _touch_snapshot(tmp_path, "x", age_seconds=100)
        result = cleanup_preupgrade_snapshots(
            tmp_path, backup_timestamp=time.time(),
        )
        assert result.errors == ()


# ---------------------------------------------------------------------------
# Convenience wrapper
# ---------------------------------------------------------------------------

class TestConvenienceWrapper:
    def test_wrapper_uses_current_time(self, tmp_path):
        """``cleanup_after_successful_backup`` captures time.time()
        at the call moment. Snapshots from just before the call
        should be deleted (except most-recent)."""
        old = _touch_snapshot(tmp_path, "old1", age_seconds=3600)
        newer = _touch_snapshot(tmp_path, "new2", age_seconds=300)
        result = cleanup_after_successful_backup(tmp_path)
        # Most-recent kept; older deleted.
        assert newer.exists()
        assert not old.exists()
        assert result.deleted_count == 1
        assert result.kept_count == 1

    def test_wrapper_no_op_on_empty_dir(self, tmp_path):
        result = cleanup_after_successful_backup(tmp_path)
        assert result.deleted_count == 0
        assert result.kept_count == 0
