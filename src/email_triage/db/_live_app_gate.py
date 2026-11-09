"""SSOT for "is a live FastAPI app currently serving on this host / this DB?".

Two-layer gate:

1. **In-process bool** (fast-path). Set by ``mark_app_live`` in the FastAPI
   lifespan; cleared by ``mark_app_stopped``. Catches the same-process bypass
   (a CLI verb folded into a lifespan-adjacent path, a test harness that
   invokes a migration primitive under the same interpreter).

2. **Filesystem sentinel** (cross-process). Lifespan writes
   ``<dbdir>/.app-alive.<pid>`` on startup and unlinks it on shutdown; the
   migration primitives scan ``<dbdir>/.app-alive.*`` and refuse if any pid
   there is alive. This catches the primary NTH-3 threat model:
   ``podman exec email-triage python -m email_triage.cli migrate ...`` on a
   live container spawns a CHILD interpreter with fresh module state (bool
   is False by construction), but the sentinel filesystem is shared and the
   parent's app-PID is still alive.

Origin: N-432 walresetbug SME panel — devils-advocate NTH-3 (2026-07-19),
adversarially widened by the batched-fold NTH-panel (DA-MF-1, 2026-07-19):
the intra-process bool alone covers the LEAST-likely bypass path. The
sentinel escalation covers the operator-observable case.

Stale-sentinel handling: a crashed process leaves its sentinel behind. On
scan, any sentinel whose pid does NOT satisfy the liveness check (portable
across Windows + POSIX) is unlinked and treated as no-live. Fail-open on
stale is correct — a dead process can't race a checkpoint.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

from email_triage._atomicio import atomic_write_text
from email_triage._int_utils import parse_int_or_none


class LiveAppMigrationRefused(RuntimeError):
    """A migration primitive refused to run against a live app.

    Distinct exception class so a CLI wrapper can catch this specifically
    and print an operator-friendly diagnostic ("stop the container first")
    rather than surface a generic ``RuntimeError`` traceback.
    """


_LIVE: bool = False
_SENTINEL_DIRS: set[Path] = set()


def _sentinel_path(dbdir: Path, pid: int | None = None) -> Path:
    """Return the sentinel path for ``pid`` in ``dbdir`` (defaults to os.getpid())."""
    return dbdir / f".app-alive.{pid or os.getpid()}"


def _pid_alive(pid: int) -> bool:
    """Cross-platform liveness check for ``pid``. Never raises.

    POSIX: ``os.kill(pid, 0)`` sends signal 0 (no-op) — raises
    ``ProcessLookupError`` if the pid is gone, ``PermissionError`` if it
    exists but we can't signal it (still alive from a gate-check standpoint).

    Windows: ``os.kill(pid, 0)`` on Windows sends ``TerminateProcess`` and
    would kill the target — dangerous. Use the ctypes OpenProcess +
    GetExitCodeProcess path, checking for ``STILL_ACTIVE`` (259).
    """
    if os.name == "nt":  # pragma: no cover - Windows-specific
        try:
            import ctypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = ctypes.windll.kernel32.OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION, False, pid,
            )
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                ok = ctypes.windll.kernel32.GetExitCodeProcess(
                    handle, ctypes.byref(exit_code),
                )
                return bool(ok) and exit_code.value == STILL_ACTIVE
            finally:
                ctypes.windll.kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # process exists, we just can't signal it
    except OSError as e:
        if e.errno == errno.ESRCH:
            return False
        return True
    return True


def _resolve_dbdir(db_path: str | os.PathLike[str] | None) -> Path | None:
    """Return the directory containing ``db_path`` (resolved), or None if
    the path is unusable (``:memory:``, empty string, missing parent).
    """
    if not db_path:
        return None
    s = str(db_path)
    if s == ":memory:" or s.startswith("file::memory:"):
        return None
    try:
        return Path(s).resolve().parent
    except (OSError, ValueError):
        return None


def mark_app_live(db_path: str | os.PathLike[str] | None = None) -> None:
    """Stamp both layers. Called by ``web/app.py::lifespan`` after startup
    wiring completes.

    ``db_path`` is the app's live DB path — used to place the filesystem
    sentinel next to it so a cross-process migration invocation (which will
    receive the same DB path) can find it via ``assert_no_live_app``.
    Best-effort: filesystem-write failures don't fail startup; the in-process
    bool alone still covers the same-process bypass.
    """
    global _LIVE
    _LIVE = True
    dbdir = _resolve_dbdir(db_path)
    if dbdir is None:
        return
    try:
        dbdir.mkdir(parents=True, exist_ok=True)
        sentinel = _sentinel_path(dbdir)
        # A11 SSOT: route through `atomic_write_text` — owns fsync +
        # chmod-before-swap + except-arm tmp cleanup. `mode=0o600` chmods the
        # temp file BEFORE the rename so the active sentinel is only ever
        # swapped to the restricted-perms copy (no world-readable window).
        atomic_write_text(sentinel, str(os.getpid()), mode=0o600)
        _SENTINEL_DIRS.add(dbdir)
    except OSError:
        # Best-effort: filesystem is not required for the gate to function
        # (the in-process bool covers the same-process case).
        pass


def mark_app_stopped() -> None:
    """Clear both layers. Called by ``web/app.py::lifespan`` in the shutdown
    path AS THE LAST STEP (DA-SF-1: symmetric with mark_app_live being the
    last startup step before yield — keeps the gate SET for the entire
    serving+shutdown window).

    Also called by tests to reset the process-global between test cases.
    Idempotent — safe to call multiple times.
    """
    global _LIVE
    _LIVE = False
    for dbdir in list(_SENTINEL_DIRS):
        try:
            _sentinel_path(dbdir).unlink()
        except (OSError, FileNotFoundError):
            pass
        _SENTINEL_DIRS.discard(dbdir)


def is_app_live() -> bool:
    """True if the in-process bool is set. Fast-path check — the sentinel
    scan (``assert_no_live_app``) is the authoritative check."""
    return _LIVE


def _live_pid_in_dir(dbdir: Path) -> int | None:
    """Scan ``dbdir`` for ``.app-alive.<pid>`` sentinels; return the first
    alive pid found, else None. Cleans up stale sentinels as it goes."""
    if not dbdir.is_dir():
        return None
    try:
        candidates = list(dbdir.glob(".app-alive.*"))
    except OSError:
        return None
    for sentinel in candidates:
        # Skip our own atomic-write tmp files.
        if sentinel.name.endswith(".tmp"):
            continue
        # `.rsplit(".", 1)[-1]` always yields a str (rsplit never returns
        # an empty list); parse_int_or_none handles the "not-a-pid" case.
        pid = parse_int_or_none(sentinel.name.rsplit(".", 1)[-1])
        if pid is None:
            continue
        if _pid_alive(pid):
            return pid
        # Stale — best-effort unlink; a benign race with another cleaner
        # (FileNotFoundError) is fine.
        try:
            sentinel.unlink()
        except (OSError, FileNotFoundError):
            pass
    return None


def assert_no_live_app(
    operation: str,
    db_path: str | os.PathLike[str] | None = None,
) -> None:
    """Raise :class:`LiveAppMigrationRefused` if either layer indicates a
    live app.

    ``operation`` names the primitive for the diagnostic (e.g.
    ``"encrypt_plaintext_db"``). ``db_path`` is the DB file the primitive
    is about to touch — used to scope the sentinel scan to the correct
    directory (a live app on a DIFFERENT DB file must not falsely block a
    migration on THIS one).
    """
    if _LIVE:
        raise LiveAppMigrationRefused(
            f"Migration primitive {operation!r} refused: an in-process "
            "FastAPI lifespan has stamped `mark_app_live()`. Migrations run "
            "pre-app or under explicit quiesce; running against a live app "
            "can race the walresetbug (SQLite < 3.51.3) window the N-432 "
            "P0 stack is designed to close."
        )
    dbdir = _resolve_dbdir(db_path)
    if dbdir is None:
        return
    live_pid = _live_pid_in_dir(dbdir)
    if live_pid is not None:
        raise LiveAppMigrationRefused(
            f"Migration primitive {operation!r} refused: filesystem sentinel "
            f".app-alive.{live_pid} in {dbdir} indicates a live app process "
            f"(pid {live_pid}). Stop that app first (e.g. `systemctl stop "
            "email-triage` or `podman stop email-triage`) and re-run. The "
            "sentinel is auto-removed on clean shutdown; a stale sentinel "
            "from a crashed process is cleaned up on the next scan."
        )
