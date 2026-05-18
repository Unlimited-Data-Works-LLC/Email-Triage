"""Pre-upgrade DB-snapshot cleanup (CR-2b).

The deploy script (``scripts/deploy.sh``) drops a raw ``sqlite3
.backup`` copy of the live DB into the data dir before swapping
images:

    /<data_dir>/triage.db.preupgrade-<commit_sha>

That file is the rollback safety net. If the post-apply health
check fails, deploy.sh swaps it back in. On success, the file
stays on disk -- internal-use only, plain copy, no master key,
not a substitute for an encrypted ``email-triage backup export``.

This module is the cleanup half of the lifecycle. When the
operator explicitly runs the full ``backup export`` (#65 encrypted
bundle), the rollback safety net is no longer required for the
pre-export state: the operator's real backup now captures
everything the snapshot would protect. We delete the older
preupgrade snapshots at that point.

**Retention rule** (conservative):

* Always keep the SINGLE most-recent snapshot regardless of age.
  If the operator runs ``backup export`` and immediately wants to
  undo a deploy from earlier today, the safety net is still there.
* Delete every other ``triage.db.preupgrade-*`` file whose mtime
  is older than the just-completed backup's timestamp.
* No-op when no snapshots exist (fresh install).

Wired in from the backup-export route's success path so the
cleanup runs only when the encrypted bundle was successfully
built AND delivered. A build failure mid-export leaves snapshots
alone (rollback safety net stays in place).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("email_triage.backup_snapshot_cleanup")

# Files matching this glob are treated as pre-upgrade snapshots. The
# suffix encodes the commit_sha the deploy ran from; we don't parse
# it -- mtime is the sort key, the suffix is for human inspection.
_SNAPSHOT_GLOB = "triage.db.preupgrade-*"


@dataclass(frozen=True)
class CleanupResult:
    """Summary returned to the caller for logging / audit.

    ``inspected`` — every snapshot file we considered.
    ``kept`` — files we retained (most-recent + any newer than the
              backup timestamp).
    ``deleted`` — files we removed.
    ``errors`` — files we tried to delete but couldn't (logged, not
                 raised; the bundle is already in the operator's
                 hands).
    """
    inspected: tuple[Path, ...] = ()
    kept: tuple[Path, ...] = ()
    deleted: tuple[Path, ...] = ()
    errors: tuple[tuple[Path, str], ...] = ()

    @property
    def deleted_count(self) -> int:
        return len(self.deleted)

    @property
    def kept_count(self) -> int:
        return len(self.kept)


def _list_snapshots(data_dir: Path) -> list[Path]:
    """Return every ``triage.db.preupgrade-*`` file in ``data_dir``,
    in newest-mtime-first order.

    Files that disappear between the listing and the stat call
    (parallel cleanup, manual rm) are skipped. Symlinks are
    resolved through ``stat`` -- the mtime is what the FS reports.
    """
    if not data_dir.is_dir():
        return []
    candidates: list[tuple[float, Path]] = []
    for p in data_dir.glob(_SNAPSHOT_GLOB):
        # Defensive: skip non-files (a directory with that name would
        # be a misconfiguration).
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        except OSError as e:
            logger.warning(
                "snapshot stat failed",
                extra={"_extra": {"path": str(p), "error": str(e)}},
            )
            continue
        # On POSIX stat returns S_ISREG via S_IFMT; the simpler is_file
        # follows symlinks, which is what we want here.
        if not p.is_file():
            continue
        candidates.append((st.st_mtime, p))
    candidates.sort(key=lambda t: t[0], reverse=True)
    return [p for _, p in candidates]


def cleanup_preupgrade_snapshots(
    data_dir: Path | str,
    *,
    backup_timestamp: float,
) -> CleanupResult:
    """Delete pre-upgrade snapshots older than ``backup_timestamp``,
    while keeping the single most-recent snapshot regardless.

    Parameters
    ----------
    data_dir
        Directory the deploy script writes ``triage.db.preupgrade-*``
        files into. Same directory the running container sees as
        ``/data``.
    backup_timestamp
        UNIX epoch seconds. Snapshots strictly older than this AND
        not the most-recent file are deleted. Typically the
        successful-export time; passing ``time.time()`` at the
        callsite is the canonical usage.

    Returns a :class:`CleanupResult`. Never raises -- a deletion
    failure logs and is reported via ``errors``.

    Lifecycle invariants:

    * Most-recent snapshot is ALWAYS kept (defensive against an
      operator who runs export-then-undo).
    * Snapshots with mtime ``>=`` backup_timestamp are kept (they
      represent state taken AFTER the backup, so the backup can't
      cover them).
    * No-op when ``data_dir`` doesn't exist or has no snapshots.
    """
    data_dir = Path(data_dir)
    snapshots = _list_snapshots(data_dir)
    if not snapshots:
        return CleanupResult()

    # Ordered newest-first. Index 0 is always-kept.
    most_recent = snapshots[0]
    kept: list[Path] = [most_recent]
    deleted: list[Path] = []
    errors: list[tuple[Path, str]] = []

    for snap in snapshots[1:]:
        try:
            mtime = snap.stat().st_mtime
        except FileNotFoundError:
            # Vanished between listing + stat; treat as already gone.
            continue
        except OSError as e:
            errors.append((snap, f"stat failed: {e}"))
            continue
        if mtime >= backup_timestamp:
            # Newer than the backup -- the backup didn't capture this
            # state. Keep it; rollback safety net still in force.
            kept.append(snap)
            continue
        # Older than the backup. Delete.
        try:
            snap.unlink()
            deleted.append(snap)
        except FileNotFoundError:
            # Race with another cleanup. Treat as success.
            deleted.append(snap)
        except OSError as e:
            errors.append((snap, f"unlink failed: {e}"))

    result = CleanupResult(
        inspected=tuple(snapshots),
        kept=tuple(kept),
        deleted=tuple(deleted),
        errors=tuple(errors),
    )
    logger.info(
        "preupgrade snapshot cleanup complete",
        extra={"_extra": {
            "data_dir": str(data_dir),
            "inspected": len(snapshots),
            "kept": result.kept_count,
            "deleted": result.deleted_count,
            "errors": len(result.errors),
        }},
    )
    return result


def cleanup_after_successful_backup(data_dir: Path | str) -> CleanupResult:
    """Convenience wrapper for the route layer.

    Captures ``time.time()`` at the call moment and forwards to
    :func:`cleanup_preupgrade_snapshots`. Pulling ``time`` lazily
    keeps the module clean of mock-the-clock test gymnastics --
    tests call :func:`cleanup_preupgrade_snapshots` directly with
    an explicit timestamp.
    """
    import time
    return cleanup_preupgrade_snapshots(
        data_dir, backup_timestamp=time.time(),
    )
