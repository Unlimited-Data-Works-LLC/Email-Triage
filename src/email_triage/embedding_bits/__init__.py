"""Lazy-install runtime for the heavy embedding stack (#180).

The v0.1.1+ container ships at ~250 MB by lifting torch + sentence-
transformers + the all-MiniLM-L6-v2 model weights out of the image
and downloading them on first use. This package is the consumer side
of the foundation laid in commit 96cb2f5:

* ``embedding_bits_install_state`` row (v31) — install lifecycle state.
* ``scripts/embedding-bits-manifest.json`` — pinned hashes baked into
  the image so the installer verifies against the manifest the image
  was built against, not whatever the operator's environment hands it.

Public API
----------
:func:`install_auto`
    Async installer that downloads each manifest-listed wheel +
    model file, hash-verifies, and pip-installs into the runtime
    deps target dir. Hard-refuses on any hash mismatch.

:func:`install_sideload`
    Async installer that consumes an operator-staged source dir
    (e.g. unpacked air-gap tarball) instead of downloading. Hash
    verification path is identical — sideload does NOT trust the
    operator-staged files either.

:func:`get_install_status`
    Read the embedding_bits_install_state row. Returns a dict the
    admin UI + status CLI render.

:func:`is_runtime_ready`
    Cheap check: can the embedding stack import from the runtime
    deps path? Used by FastAPI startup + the style-learning UI to
    gate features that need the embedding backend.

:func:`runtime_python_path`
    Filesystem paths the installer wrote to that need to live on
    ``sys.path`` for the lazy-installed packages to import.

:func:`add_runtime_to_sys_path`
    Idempotent ``sys.path.insert(0, p)`` for each runtime path.

:func:`get_runtime_deps_path`
    Resolves ``EMBEDDING_BITS_RUNTIME_DEPS`` env var, falling back
    to ``/app/data/runtime-deps``.

Cancel cooperation
------------------
:func:`request_cancel` / :func:`is_cancel_requested` form a tiny
process-local cancel flag. The installer checks it between files +
between pip-invoke phases. UI [Cancel] button POSTs to a route that
flips this flag.

Privacy
-------
* HF telemetry disabled via env: HF_HUB_DISABLE_TELEMETRY=1 +
  DO_NOT_TRACK=1 BEFORE pip + before any HF import.
* Every HTTP call is to a URL listed in the pinned manifest. Static
  test ``tests/test_privacy_invariants_no_embedding_telemetry.py``
  enforces this by scanning the module source.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

# Telemetry-off env vars. Set at module import time so any later HF
# import in the same process inherits them (env vars set after the
# import are sometimes too late depending on HF's bootstrap order).
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
os.environ.setdefault("DO_NOT_TRACK", "1")
# Disable HF implicit downloads / progress bars / update checks.
os.environ.setdefault("HF_HUB_DISABLE_IMPLICIT_TOKEN", "1")
os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "0")  # we DO need to fetch initially
# pip should never call home for version checks during our install.
os.environ.setdefault("PIP_DISABLE_PIP_VERSION_CHECK", "1")

log = logging.getLogger("email_triage.embedding_bits")

CHUNK = 64 * 1024
DEFAULT_RUNTIME_DEPS = "/app/data/runtime-deps"
DEFAULT_MANIFEST_PATH = "/app/scripts/embedding-bits-manifest.json"
DOWNLOAD_TIMEOUT_SECS = 300
PIP_TIMEOUT_SECS = 600

# Retry schedule for hash-mismatch + network errors during a single
# file's download. After 3 attempts the file (and the whole install)
# fails. Aligned with the foundation commit's docstring promise.
RETRY_BACKOFF_SECS: tuple[int, ...] = (1, 4, 16)


# ---------------------------------------------------------------------------
# Cancel flag (process-local; UI cancel button flips this)
# ---------------------------------------------------------------------------

_cancel_lock = threading.Lock()
_cancel_flag = False


def request_cancel() -> None:
    """Signal the running installer to stop at the next file boundary."""
    global _cancel_flag
    with _cancel_lock:
        _cancel_flag = True


def clear_cancel() -> None:
    """Reset the cancel flag. Called at the start of each install run."""
    global _cancel_flag
    with _cancel_lock:
        _cancel_flag = False


def is_cancel_requested() -> bool:
    with _cancel_lock:
        return _cancel_flag


class InstallCancelled(Exception):
    """Raised when the operator cancels an in-flight install."""


class HashMismatch(Exception):
    """A file's SHA-256 did not match the manifest. Hard refusal — no
    skip-hash override. Surfaces the offending filename so the
    operator can investigate (transient mirror corruption vs upstream
    poisoning vs manifest drift on a fork)."""

    def __init__(self, filename: str, expected: str, actual: str) -> None:
        super().__init__(
            f"SHA-256 mismatch on {filename}: expected {expected[:12]}…, "
            f"got {actual[:12]}…"
        )
        self.filename = filename
        self.expected = expected
        self.actual = actual


class PipInstallError(Exception):
    """pip exited non-zero. Stderr is captured but scrubbed before it
    lands in the install_state row."""


@dataclass
class InstallResult:
    status: Literal["installed", "failed", "cancelled"]
    error_class: str | None = None
    error_msg: str | None = None
    bytes_downloaded: int = 0
    files_installed: int = 0
    duration_secs: float = 0.0


# ---------------------------------------------------------------------------
# Path helpers (used by FastAPI startup + the runtime-ready check)
# ---------------------------------------------------------------------------

def get_runtime_deps_path() -> Path:
    """Resolve the runtime-deps target dir.

    Priority: ``EMBEDDING_BITS_RUNTIME_DEPS`` env var (Containerfile
    stage 2 sets it to ``/app/data/runtime-deps``) > built-in default.
    """
    raw = os.environ.get("EMBEDDING_BITS_RUNTIME_DEPS", "").strip()
    if raw:
        return Path(raw)
    return Path(DEFAULT_RUNTIME_DEPS)


def runtime_python_path() -> list[str]:
    """sys.path additions for the lazy-installed bits.

    pip is invoked with ``--prefix=<target>`` so the installed packages
    land in ``<target>/lib/pythonX.Y/site-packages``. We compute the
    site-packages path against the running interpreter's version and
    return it.
    """
    base = get_runtime_deps_path()
    out: list[str] = []
    # Standard --prefix install layout on POSIX:
    # <prefix>/lib/python<major>.<minor>/site-packages
    pyver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    sp = base / "lib" / pyver / "site-packages"
    if sp.exists():
        out.append(str(sp))
    # Windows --prefix layout: <prefix>/Lib/site-packages. We support
    # this path so dev runs on Windows can exercise the same code
    # path as the production Linux container.
    sp_win = base / "Lib" / "site-packages"
    if sp_win.exists():
        out.append(str(sp_win))
    return out


def add_runtime_to_sys_path() -> None:
    """Idempotent — call at FastAPI startup. Re-running is a no-op."""
    for p in runtime_python_path():
        if p not in sys.path:
            sys.path.insert(0, p)


def is_runtime_ready(*, runtime_deps_path: Path | None = None) -> bool:
    """Cheap probe: does ``sentence_transformers`` LOOK importable
    from the runtime path?

    Uses ``importlib.util.find_spec`` — returns True when the package
    directory exists on sys.path. Does NOT actually import, so does
    NOT catch the case where the package itself depends on a transitive
    that's missing from the install. The 2026-05-18 ``packaging``-
    missing regression bit because find_spec returned True even though
    ``import sentence_transformers`` raised ``ModuleNotFoundError``.

    Use this for:
      * FastAPI startup — log the install state, decide whether to
        wire the embedding backend or leave it None.
      * Style-learning UI gating — disable controls that need the
        embedding stack (per-page-render check; sub-ms cost matters).
      * Reindex job — refuse to run if False.

    For the install verify gate (hard check that "installed" actually
    means importable), use :func:`runtime_imports_cleanly` instead —
    that runs a real ``import sentence_transformers`` in a subprocess
    and catches missing-transitive failures.
    """
    global _runtime_ready_cache
    if _runtime_ready_cache is not None:
        return _runtime_ready_cache
    add_runtime_to_sys_path()
    try:
        import importlib.util
        spec = importlib.util.find_spec("sentence_transformers")
        _runtime_ready_cache = spec is not None
    except Exception:  # noqa: BLE001
        _runtime_ready_cache = False
    return _runtime_ready_cache


def runtime_imports_cleanly(
    *, runtime_deps_path: Path | None = None,
) -> tuple[bool, str | None]:
    """Strong probe: actually IMPORT ``sentence_transformers`` and
    catch any transitive-dep failures.

    Returns ``(True, None)`` on clean import; ``(False, <error_msg>)``
    when the import raises (typically
    ``ModuleNotFoundError: No module named 'X'`` from a missing
    transitive).

    Cost: 1-2 seconds — torch + transformers + tokenizers all chain-
    import. Pay it ONCE at the install verify gate, not on every page
    render.

    Implementation: runs the import in a SUBPROCESS so the parent
    process's sys.modules cache doesn't pollute the result, and so a
    failed import doesn't leave half-loaded module shadows in the
    parent. Subprocess inherits the parent's PATH + the runtime_deps
    sys.path additions via the inline probe script.
    """
    add_runtime_to_sys_path()
    import subprocess as _sp
    rdp = str(runtime_deps_path) if runtime_deps_path else ""
    # Inline probe — keeps the test self-contained without shipping
    # a separate script file in the image.
    probe = (
        "import sys, os\n"
        f"rdp = os.environ.get('EMBEDDING_BITS_RUNTIME_DEPS') or {rdp!r}\n"
        "if rdp:\n"
        "    pyver = f'python{sys.version_info.major}.{sys.version_info.minor}'\n"
        "    sp = f'{rdp}/lib/{pyver}/site-packages'\n"
        "    if sp not in sys.path:\n"
        "        sys.path.insert(0, sp)\n"
        "import sentence_transformers\n"
        "print('OK')\n"
    )
    try:
        result = _sp.run(  # noqa: S603
            [sys.executable, "-c", probe],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        return False, f"probe subprocess failed: {type(exc).__name__}: {exc}"
    if result.returncode == 0 and "OK" in (result.stdout or ""):
        return True, None
    err_tail = (result.stderr or "").strip().splitlines()
    msg = err_tail[-1] if err_tail else (
        f"probe exited {result.returncode}; no stderr captured"
    )
    return False, msg[:300]


_runtime_ready_cache: bool | None = None


def invalidate_runtime_ready_cache() -> None:
    """Reset the is_runtime_ready cache.

    Called after a successful install so the next probe reflects the
    new on-disk state without a process restart."""
    global _runtime_ready_cache
    _runtime_ready_cache = None


# ---------------------------------------------------------------------------
# Status row helpers (read + write embedding_bits_install_state)
# ---------------------------------------------------------------------------

def get_install_status(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the singleton install-state row as a dict.

    Always returns a dict — the foundation migration's INSERT OR
    IGNORE seed guarantees the row exists. Defensive fallback emits
    a synthetic ``not_installed`` shape if the row is somehow missing
    so the UI never crashes on a None row.
    """
    row = conn.execute(
        "SELECT * FROM embedding_bits_install_state WHERE id = 1"
    ).fetchone()
    if row is None:
        return _synthetic_not_installed()
    return dict(row)


def _synthetic_not_installed() -> dict[str, Any]:
    return {
        "id": 1,
        "status": "not_installed",
        "install_method": None,
        "manifest_sha256": None,
        "runtime_deps_path": None,
        "progress_files_done": 0,
        "progress_files_total": 0,
        "progress_bytes_done": 0,
        "progress_bytes_total": 0,
        "current_file": None,
        "attempt_count": 0,
        "last_attempt_at": None,
        "installed_at": None,
        "last_error_class": None,
        "last_error_msg": None,
        "last_error_at": None,
        "created_at": "",
    }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _scrub_error(text: str | None) -> str | None:
    """Trim + clip error messages before writing to the row.

    Hard cap: 500 chars (matches the foundation docstring promise).
    Strips trailing whitespace + collapses CR/LF runs so a multi-
    line pip stderr renders cleanly in the admin banner.
    """
    if not text:
        return None
    flat = " ".join(str(text).split())
    return flat[:500]


def _update_state(
    conn: sqlite3.Connection,
    *,
    status: str | None = None,
    install_method: str | None = None,
    manifest_sha256: str | None = None,
    runtime_deps_path: str | None = None,
    progress_files_done: int | None = None,
    progress_files_total: int | None = None,
    progress_bytes_done: int | None = None,
    progress_bytes_total: int | None = None,
    current_file: str | None = None,
    bump_attempt: bool = False,
    set_last_attempt_now: bool = False,
    set_installed_now: bool = False,
    last_error_class: str | None = None,
    last_error_msg: str | None = None,
    clear_error: bool = False,
) -> None:
    """Patch the install-state row. Only non-None fields are updated.

    SQL is built dynamically from the provided fields so the row's
    other columns retain their values across partial updates.
    """
    sets: list[str] = []
    params: list[Any] = []
    if status is not None:
        sets.append("status = ?")
        params.append(status)
    if install_method is not None:
        sets.append("install_method = ?")
        params.append(install_method)
    if manifest_sha256 is not None:
        sets.append("manifest_sha256 = ?")
        params.append(manifest_sha256)
    if runtime_deps_path is not None:
        sets.append("runtime_deps_path = ?")
        params.append(runtime_deps_path)
    if progress_files_done is not None:
        sets.append("progress_files_done = ?")
        params.append(int(progress_files_done))
    if progress_files_total is not None:
        sets.append("progress_files_total = ?")
        params.append(int(progress_files_total))
    if progress_bytes_done is not None:
        sets.append("progress_bytes_done = ?")
        params.append(int(progress_bytes_done))
    if progress_bytes_total is not None:
        sets.append("progress_bytes_total = ?")
        params.append(int(progress_bytes_total))
    if current_file is not None:
        sets.append("current_file = ?")
        params.append(current_file)
    if bump_attempt:
        sets.append("attempt_count = attempt_count + 1")
    if set_last_attempt_now:
        sets.append("last_attempt_at = ?")
        params.append(_now_iso())
    if set_installed_now:
        sets.append("installed_at = ?")
        params.append(_now_iso())
        # Reset attempt_count on success — the foundation docstring's
        # promise.
        sets.append("attempt_count = 0")
    if clear_error:
        sets.append("last_error_class = NULL")
        sets.append("last_error_msg = NULL")
        sets.append("last_error_at = NULL")
    if last_error_class is not None:
        sets.append("last_error_class = ?")
        params.append(last_error_class[:64])
        sets.append("last_error_at = ?")
        params.append(_now_iso())
    if last_error_msg is not None:
        sets.append("last_error_msg = ?")
        params.append(_scrub_error(last_error_msg))

    if not sets:
        return
    conn.execute(
        f"UPDATE embedding_bits_install_state SET {', '.join(sets)} "
        f"WHERE id = 1",
        params,
    )
    conn.commit()


def _emit_progress(
    callback: Callable[[dict], None] | None,
    payload: dict[str, Any],
) -> None:
    """Invoke a progress callback with a try/except guard.

    The UI router persists the payload to the DB row. We do NOT let a
    callback exception poison the install loop — log + continue.
    """
    if callback is None:
        return
    try:
        callback(dict(payload))
    except Exception:
        log.exception("install progress_callback raised; ignoring")


# ---------------------------------------------------------------------------
# Hashing + manifest loading
# ---------------------------------------------------------------------------

def _hash_file(path: Path) -> str:
    """Compute SHA-256 of a file on disk (streaming)."""
    import hashlib
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            buf = fh.read(CHUNK)
            if not buf:
                break
            h.update(buf)
    return h.hexdigest()


def _manifest_sha256(manifest_path: Path) -> str:
    """Compute SHA-256 over the raw manifest JSON bytes.

    Used to fingerprint the manifest the install ran against; the
    admin re-verify path compares this against
    embedding_bits_install_state.manifest_sha256 to detect a drift
    (operator pulled a new image whose manifest differs from the
    one the install on disk was hash-built against).
    """
    return _hash_file(manifest_path)


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    with manifest_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _check_manifest_hashes_populated(manifest: dict[str, Any]) -> None:
    """Refuse to run with a placeholder-hash manifest.

    The foundation commit ships a skeleton with PLACEHOLDER_*_SHA256
    strings. Running install_auto against that would download bytes,
    fail every hash check, and emit a wall of HashMismatch errors —
    clearer if we trip at the entry point.
    """
    for w in manifest.get("wheels", []):
        if "PLACEHOLDER" in str(w.get("sha256", "")):
            raise RuntimeError(
                f"Manifest entry {w.get('name')!r} has a placeholder "
                f"sha256. The release-cut process must run "
                f"scripts/build-embedding-bits-manifest.py to fill in "
                f"real hashes before an install can proceed."
            )
    for m in manifest.get("models", []):
        for f in m.get("files", []):
            if "PLACEHOLDER" in str(f.get("sha256", "")):
                raise RuntimeError(
                    f"Manifest model file {f.get('name')!r} has a "
                    f"placeholder sha256. Run "
                    f"scripts/build-embedding-bits-manifest.py."
                )


# ---------------------------------------------------------------------------
# Download primitives (auto path)
# ---------------------------------------------------------------------------

UA = "email-triage-installer/1.0"


def _http_download(url: str, dest: Path) -> int:
    """Stream ``url`` to ``dest`` and return the byte count.

    Atomic — writes to a sibling tempfile + renames. No partial
    files left behind on crash.
    """
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    dest.parent.mkdir(parents=True, exist_ok=True)
    size = 0
    with tempfile.NamedTemporaryFile(
        delete=False, dir=str(dest.parent), prefix=".partial-",
    ) as tmp:
        tmp_path = Path(tmp.name)
        try:
            with urllib.request.urlopen(  # noqa: S310
                req, timeout=DOWNLOAD_TIMEOUT_SECS,
            ) as resp:
                while True:
                    buf = resp.read(CHUNK)
                    if not buf:
                        break
                    tmp.write(buf)
                    size += len(buf)
        except Exception:
            tmp.close()
            tmp_path.unlink(missing_ok=True)
            raise
    tmp_path.replace(dest)
    return size


def _fetch_with_retry(
    *,
    url: str,
    dest: Path,
    expected_sha256: str,
    filename: str,
) -> int:
    """Download ``url`` to ``dest`` and verify ``expected_sha256``.

    Retries up to len(RETRY_BACKOFF_SECS) times on network errors OR
    hash mismatches. The hash-mismatch retry is intentional: a flaky
    mirror can serve a partial file that decodes cleanly but hashes
    wrong; one retry usually clears it. After all retries: raises the
    final exception (HashMismatch or the network error).
    """
    last_exc: Exception | None = None
    for attempt, delay in enumerate(RETRY_BACKOFF_SECS):
        try:
            size = _http_download(url, dest)
            actual = _hash_file(dest)
            if actual != expected_sha256:
                raise HashMismatch(filename, expected_sha256, actual)
            return size
        except (urllib.error.URLError, HashMismatch, OSError) as e:
            last_exc = e
            # Don't sleep after the final attempt — we're about to raise.
            if attempt < len(RETRY_BACKOFF_SECS) - 1:
                log.warning(
                    "embedding_bits: fetch attempt %d failed (%s); "
                    "sleeping %ds before retry",
                    attempt + 1, type(e).__name__, delay,
                )
                time.sleep(delay)
            # Clean up partial file before retry so the next try starts
            # from scratch.
            dest.unlink(missing_ok=True)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# pip install
# ---------------------------------------------------------------------------

def _run_pip_install(
    *, wheels_dir: Path, target_dir: Path, wheel_names: list[str],
) -> None:
    """Invoke pip via subprocess to install the staged wheels.

    Why subprocess + the pip CLI (not pip's internal API): pip's
    internal API has NO stable interface — every minor version moves
    things around. The CLI is the supported surface.

    Flags:
      --no-index : refuse to contact PyPI. The wheels we want are all
                   in wheels_dir; anything pip wants beyond that is a
                   manifest gap we'd rather surface as an error than
                   silently fetch.
      --find-links wheels_dir : look here for the wheels.
      --prefix target_dir : land the installed packages under
                            target_dir/lib/pythonX.Y/site-packages.
                            We add that path to sys.path on next boot.
      --no-build-isolation : we're installing only pre-built wheels;
                             no PEP 517 backend invocation needed.
    """
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        "--find-links", str(wheels_dir),
        "--prefix", str(target_dir),
        "--no-build-isolation",
        "--no-deps",  # we control transitives via the manifest
        "--disable-pip-version-check",
        "--no-warn-script-location",
        *wheel_names,
    ]
    # Inherit the env vars set at module-import time (telemetry off,
    # pip version check off). subprocess inherits os.environ by default
    # so the setdefault calls at the top of this module propagate.
    proc = subprocess.run(  # noqa: S603
        cmd,
        capture_output=True,
        text=True,
        timeout=PIP_TIMEOUT_SECS,
        check=False,
    )
    if proc.returncode != 0:
        # Combine stderr + last 20 lines of stdout for context. Scrubbed
        # by _scrub_error before persistence.
        tail = "\n".join((proc.stdout or "").splitlines()[-20:])
        raise PipInstallError(
            f"pip exited {proc.returncode}: "
            f"stderr={proc.stderr or ''} stdout-tail={tail}"
        )


# ---------------------------------------------------------------------------
# Already-installed fast-path
# ---------------------------------------------------------------------------

def _all_files_present_and_valid(
    *, manifest: dict[str, Any], target_dir: Path,
) -> bool:
    """True if every manifest file is on disk with the correct hash.

    Used by the idempotent fast-path: a second install_auto call
    against a target_dir that already has every file should be a
    no-op.
    """
    wheels_dir = target_dir / "wheels"
    for w in manifest.get("wheels", []):
        p = wheels_dir / w["filename"]
        if not p.exists():
            return False
        if _hash_file(p) != w["sha256"]:
            return False
    hf_dir = target_dir / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"
    for model in manifest.get("models", []):
        for f in model.get("files", []):
            # Preserve subdir structure in the model dir
            p = hf_dir / f["name"]
            if not p.exists():
                return False
            if _hash_file(p) != f["sha256"]:
                return False
    return True


# ---------------------------------------------------------------------------
# Public install API
# ---------------------------------------------------------------------------

async def install_auto(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None = None,
) -> InstallResult:
    """Download + hash-verify + pip-install the embedding stack.

    Hard-fails on any hash mismatch (no skip-hash option). Retries
    each file up to 3 times with exponential backoff. Updates the
    install_state row at every state transition.
    """
    return await asyncio.to_thread(
        _install_auto_sync,
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        progress_callback=progress_callback,
    )


def _install_auto_sync(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    return _install_common(
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        source_dir=None,
        method="auto",
        progress_callback=progress_callback,
    )


async def install_sideload(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    source_dir: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None = None,
) -> InstallResult:
    """Copy + hash-verify + pip-install from an operator-staged dir.

    ``source_dir`` must contain ``wheels/`` and ``hf-cache/
    sentence-transformers_all-MiniLM-L6-v2/`` populated by
    scripts/download-embedding-bits.sh on a connected machine.

    Hash verification is IDENTICAL to the auto path — sideload does
    NOT trust the operator-staged files. A bit-corrupted tarball or
    a tampered air-gap drop trips the same HashMismatch refusal as
    a poisoned PyPI mirror.
    """
    return await asyncio.to_thread(
        _install_sideload_sync,
        conn=conn,
        manifest_path=manifest_path,
        source_dir=source_dir,
        target_dir=target_dir,
        progress_callback=progress_callback,
    )


def _install_sideload_sync(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    source_dir: Path,
    target_dir: Path,
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    return _install_common(
        conn=conn,
        manifest_path=manifest_path,
        target_dir=target_dir,
        source_dir=source_dir,
        method="sideload",
        progress_callback=progress_callback,
    )


def _install_common(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
    source_dir: Path | None,
    method: Literal["auto", "sideload"],
    progress_callback: Callable[[dict], None] | None,
) -> InstallResult:
    """Shared install pipeline for auto + sideload.

    The only difference between the two paths is the source of each
    file's bytes (HTTP fetch vs filesystem copy). Hash verify + pip
    invoke + state transitions are identical.
    """
    start = time.monotonic()
    clear_cancel()

    target_dir.mkdir(parents=True, exist_ok=True)
    wheels_dir = target_dir / "wheels"
    hf_dir = target_dir / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"
    wheels_dir.mkdir(parents=True, exist_ok=True)
    hf_dir.mkdir(parents=True, exist_ok=True)

    try:
        manifest = _load_manifest(manifest_path)
        _check_manifest_hashes_populated(manifest)
    except Exception as e:
        _update_state(
            conn,
            status="failed",
            install_method=method,
            bump_attempt=True,
            set_last_attempt_now=True,
            last_error_class=type(e).__name__,
            last_error_msg=str(e),
        )
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            duration_secs=time.monotonic() - start,
        )

    manifest_sha = _manifest_sha256(manifest_path)

    # Fast-path: if every wheel + model file is already on disk + hash-
    # valid, skip the slow download phase BUT still rerun pip-install +
    # the post-install verification. The 2026-05-18 bug this comment
    # used to lie about: pre-fix this block jumped straight to
    # ``status="installed"`` without ever calling ``_run_pip_install``,
    # so an operator clicking [Retry] after a failed-during-pip first
    # attempt (wheels staged, pip OOM'd) saw the state flip to
    # ``installed`` while ``/app/data/runtime-deps/lib/`` remained empty
    # and ``sentence_transformers`` still didn't import. Post-fix the
    # fast-path re-invokes pip + verifies the runtime is importable
    # before declaring installed; if the verify gate fails, status
    # flips to "failed" with a clear error.
    if _all_files_present_and_valid(
        manifest=manifest, target_dir=target_dir,
    ):
        log.info(
            "embedding_bits: all files already present + hash-valid; "
            "fast-path (still running pip + verify)",
        )
        _update_state(
            conn,
            status="installing",
            install_method=method,
            manifest_sha256=manifest_sha,
            runtime_deps_path=str(target_dir),
            current_file=None,
            bump_attempt=True,
            set_last_attempt_now=True,
            clear_error=True,
        )
        _emit_progress(progress_callback, {"status": "installing"})
        wheel_names = [w["name"] for w in manifest.get("wheels", [])]
        try:
            _run_pip_install(
                wheels_dir=target_dir / "wheels",
                target_dir=target_dir,
                wheel_names=wheel_names,
            )
        except Exception as e:  # noqa: BLE001
            _update_state(
                conn,
                status="failed",
                last_error_class=type(e).__name__,
                last_error_msg=_scrub_error(str(e)),
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": type(e).__name__,
            })
            return InstallResult(
                status="failed",
                error_class=type(e).__name__,
                error_msg=_scrub_error(str(e)),
                duration_secs=time.monotonic() - start,
            )
        # Verify pip actually wrote site-packages + sentence_transformers
        # is importable from the runtime path. Catches the silent-no-op
        # case where pip exits 0 but didn't install anything (e.g. all
        # packages already satisfied from the system interpreter, an
        # unusual edge case but possible if the container's base image
        # ever changes).
        invalidate_runtime_ready_cache()
        add_runtime_to_sys_path()
        import importlib as _il
        _il.invalidate_caches()
        # 2026-05-18: switched from the cheap find_spec probe
        # (is_runtime_ready) to the strong actual-import probe
        # (runtime_imports_cleanly). find_spec returns True when the
        # package directory exists, even if the package itself fails
        # to import due to a missing transitive. The strong probe
        # catches that class of regression (operator hit "ModuleNotFoundError:
        # No module named 'packaging'" with the find_spec gate saying
        # "imports successfully"). One subprocess invocation, 1-2 sec.
        ok, import_err = runtime_imports_cleanly(
            runtime_deps_path=target_dir,
        )
        if not ok:
            err = (
                f"sentence_transformers does not import: {import_err}. "
                f"Likely a manifest gap (missing transitive dep) or a "
                f"half-installed site-packages. Try [Re-install], or "
                f"delete /app/data/runtime-deps and try again."
            )
            _update_state(
                conn,
                status="failed",
                last_error_class="PostInstallVerifyFailed",
                last_error_msg=err,
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": "PostInstallVerifyFailed",
            })
            return InstallResult(
                status="failed",
                error_class="PostInstallVerifyFailed",
                error_msg=err,
                duration_secs=time.monotonic() - start,
            )
        _update_state(
            conn,
            status="installed",
            install_method=method,
            manifest_sha256=manifest_sha,
            runtime_deps_path=str(target_dir),
            set_installed_now=True,
            current_file=None,
            clear_error=True,
        )
        _emit_progress(progress_callback, {"status": "installed"})
        return InstallResult(
            status="installed",
            files_installed=_count_manifest_files(manifest),
            duration_secs=time.monotonic() - start,
        )

    total_files = _count_manifest_files(manifest)
    total_bytes = _sum_manifest_bytes(manifest)

    _update_state(
        conn,
        status="downloading",
        install_method=method,
        manifest_sha256=manifest_sha,
        runtime_deps_path=str(target_dir),
        progress_files_done=0,
        progress_files_total=total_files,
        progress_bytes_done=0,
        progress_bytes_total=total_bytes,
        current_file=None,
        bump_attempt=True,
        set_last_attempt_now=True,
        clear_error=True,
    )
    _emit_progress(progress_callback, {
        "status": "downloading",
        "progress_files_total": total_files,
        "progress_bytes_total": total_bytes,
    })

    files_done = 0
    bytes_done = 0

    try:
        # 1. Wheels
        for w in manifest.get("wheels", []):
            if is_cancel_requested():
                raise InstallCancelled()
            dest = wheels_dir / w["filename"]
            _stage_one(
                source_dir=source_dir,
                source_subdir="wheels",
                url=w.get("url", ""),
                dest=dest,
                expected_sha256=w["sha256"],
                filename=w["filename"],
            )
            files_done += 1
            bytes_done += int(w.get("size_bytes") or 0) or dest.stat().st_size
            _update_state(
                conn,
                current_file=w["filename"],
                progress_files_done=files_done,
                progress_bytes_done=bytes_done,
            )
            _emit_progress(progress_callback, {
                "status": "downloading",
                "current_file": w["filename"],
                "progress_files_done": files_done,
                "progress_files_total": total_files,
                "progress_bytes_done": bytes_done,
                "progress_bytes_total": total_bytes,
            })

        # 2. Model files
        for model in manifest.get("models", []):
            for f in model.get("files", []):
                if is_cancel_requested():
                    raise InstallCancelled()
                dest = hf_dir / f["name"]
                _stage_one(
                    source_dir=source_dir,
                    source_subdir="hf-cache/sentence-transformers_all-MiniLM-L6-v2",
                    url=f.get("url", ""),
                    dest=dest,
                    expected_sha256=f["sha256"],
                    filename=f["name"],
                )
                files_done += 1
                bytes_done += int(f.get("size_bytes") or 0) or dest.stat().st_size
                _update_state(
                    conn,
                    current_file=f"{model['name']}/{f['name']}",
                    progress_files_done=files_done,
                    progress_bytes_done=bytes_done,
                )
                _emit_progress(progress_callback, {
                    "status": "downloading",
                    "current_file": f"{model['name']}/{f['name']}",
                    "progress_files_done": files_done,
                    "progress_files_total": total_files,
                    "progress_bytes_done": bytes_done,
                    "progress_bytes_total": total_bytes,
                })

        # 3. Verify (after-the-fact full sweep — defence in depth; each
        #    file was already verified inline but a final pass catches
        #    e.g. an on-disk corruption between staging and pip-install)
        if is_cancel_requested():
            raise InstallCancelled()
        _update_state(conn, status="verifying", current_file=None)
        _emit_progress(progress_callback, {"status": "verifying"})
        for w in manifest.get("wheels", []):
            p = wheels_dir / w["filename"]
            actual = _hash_file(p)
            if actual != w["sha256"]:
                raise HashMismatch(w["filename"], w["sha256"], actual)
        for model in manifest.get("models", []):
            for f in model.get("files", []):
                p = hf_dir / f["name"]
                actual = _hash_file(p)
                if actual != f["sha256"]:
                    raise HashMismatch(f["name"], f["sha256"], actual)

        # 4. pip install
        if is_cancel_requested():
            raise InstallCancelled()
        _update_state(conn, status="installing", current_file=None)
        _emit_progress(progress_callback, {"status": "installing"})
        wheel_names = [w["name"] for w in manifest.get("wheels", [])]
        _run_pip_install(
            wheels_dir=wheels_dir,
            target_dir=target_dir,
            wheel_names=wheel_names,
        )

        # Point HF_HOME at the model cache so the embedding backend
        # finds the all-MiniLM-L6-v2 files we just staged. The
        # Containerfile sets this env var at image build, but we also
        # set it here so an installer-CLI invocation outside the
        # container (test runs) finds the model.
        os.environ.setdefault("HF_HOME", str(target_dir / "hf-cache"))

        # 5. Verify pip actually populated the runtime path. Pip's
        # exit 0 isn't enough — it's possible for pip to short-circuit
        # on "already satisfied" without writing anything. The verify
        # gate calls ``is_runtime_ready`` post-cache-invalidation; if
        # ``sentence_transformers`` still doesn't import from the
        # runtime path, the install is NOT installed regardless of
        # what pip's exit code said.
        invalidate_runtime_ready_cache()
        add_runtime_to_sys_path()
        import importlib as _il
        _il.invalidate_caches()
        # 2026-05-18: switched from the cheap find_spec probe
        # (is_runtime_ready) to the strong actual-import probe
        # (runtime_imports_cleanly). find_spec returns True when the
        # package directory exists, even if the package itself fails
        # to import due to a missing transitive. The strong probe
        # catches that class of regression (operator hit "ModuleNotFoundError:
        # No module named 'packaging'" with the find_spec gate saying
        # "imports successfully"). One subprocess invocation, 1-2 sec.
        ok, import_err = runtime_imports_cleanly(
            runtime_deps_path=target_dir,
        )
        if not ok:
            err = (
                f"sentence_transformers does not import: {import_err}. "
                f"Likely a manifest gap (missing transitive dep) or a "
                f"half-installed site-packages. Try [Re-install], or "
                f"delete /app/data/runtime-deps and try again."
            )
            _update_state(
                conn,
                status="failed",
                last_error_class="PostInstallVerifyFailed",
                last_error_msg=err,
            )
            _emit_progress(progress_callback, {
                "status": "failed",
                "error_class": "PostInstallVerifyFailed",
            })
            return InstallResult(
                status="failed",
                error_class="PostInstallVerifyFailed",
                error_msg=err,
                files_installed=total_files,
                bytes_downloaded=bytes_done,
                duration_secs=time.monotonic() - start,
            )

        # 6. Success
        _update_state(
            conn,
            status="installed",
            set_installed_now=True,
            current_file=None,
            clear_error=True,
            progress_files_done=total_files,
            progress_bytes_done=total_bytes,
        )
        _emit_progress(progress_callback, {
            "status": "installed",
            "progress_files_done": total_files,
            "progress_files_total": total_files,
            "progress_bytes_done": total_bytes,
            "progress_bytes_total": total_bytes,
        })
        return InstallResult(
            status="installed",
            files_installed=total_files,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )

    except InstallCancelled:
        _update_state(
            conn,
            status="not_installed",  # back to ready-to-retry state
            current_file=None,
            last_error_class="InstallCancelled",
            last_error_msg="Install cancelled by operator",
        )
        _emit_progress(progress_callback, {
            "status": "not_installed",
            "cancelled": True,
        })
        return InstallResult(
            status="cancelled",
            error_class="InstallCancelled",
            error_msg="Install cancelled by operator",
            files_installed=files_done,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )

    except Exception as e:  # noqa: BLE001
        err_class = type(e).__name__
        err_msg = str(e)
        _update_state(
            conn,
            status="failed",
            current_file=None,
            last_error_class=err_class,
            last_error_msg=err_msg,
        )
        _emit_progress(progress_callback, {
            "status": "failed",
            "last_error_class": err_class,
            "last_error_msg": _scrub_error(err_msg),
        })
        log.exception("embedding_bits install failed")
        return InstallResult(
            status="failed",
            error_class=err_class,
            error_msg=_scrub_error(err_msg),
            files_installed=files_done,
            bytes_downloaded=bytes_done,
            duration_secs=time.monotonic() - start,
        )


def _stage_one(
    *,
    source_dir: Path | None,
    source_subdir: str,
    url: str,
    dest: Path,
    expected_sha256: str,
    filename: str,
) -> None:
    """Materialise one manifest file at ``dest`` + verify the hash.

    Auto path (source_dir=None): downloads via _fetch_with_retry.
    Sideload path: copies from ``source_dir/source_subdir/<basename>``
    and then hash-checks.

    Either way, the file ends up at ``dest`` with verified bytes or
    the function raises.

    Fast-path: if ``dest`` already exists with the expected hash,
    return immediately (idempotent inner loop — relevant when a
    previous attempt got partway through, e.g. crashed mid-file 8 of
    18).
    """
    if dest.exists():
        try:
            if _hash_file(dest) == expected_sha256:
                return
        except OSError:
            pass
        # Stale partial / mismatched bytes — drop + re-stage.
        dest.unlink(missing_ok=True)

    if source_dir is None:
        # Auto path
        _fetch_with_retry(
            url=url, dest=dest,
            expected_sha256=expected_sha256, filename=filename,
        )
    else:
        # Sideload path
        # Last path component of the dest is the filename we look for
        # in source_dir; the source mirrors the dest layout.
        rel = dest.relative_to(dest.parent)
        src = source_dir / source_subdir / rel
        if not src.exists():
            raise FileNotFoundError(
                f"Sideload source missing: {src} (expected from the "
                f"operator-staged tarball — was scripts/download-"
                f"embedding-bits.sh run on a connected machine?)"
            )
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        actual = _hash_file(dest)
        if actual != expected_sha256:
            raise HashMismatch(filename, expected_sha256, actual)


def _count_manifest_files(manifest: dict[str, Any]) -> int:
    n = len(manifest.get("wheels", []))
    for model in manifest.get("models", []):
        n += len(model.get("files", []))
    return n


def _sum_manifest_bytes(manifest: dict[str, Any]) -> int:
    n = 0
    for w in manifest.get("wheels", []):
        n += int(w.get("size_bytes") or 0)
    for model in manifest.get("models", []):
        for f in model.get("files", []):
            n += int(f.get("size_bytes") or 0)
    return n


# ---------------------------------------------------------------------------
# Re-verify (no download)
# ---------------------------------------------------------------------------

def reverify(
    *,
    conn: sqlite3.Connection,
    manifest_path: Path,
    target_dir: Path,
) -> InstallResult:
    """Re-hash every staged file against the current manifest.

    No downloads. Updates the install_state row on success/failure.
    Used by the admin [Re-verify] button to confirm the on-disk
    bytes still match what the installer wrote (catches bit-rot +
    operator-side tampering).
    """
    start = time.monotonic()
    try:
        manifest = _load_manifest(manifest_path)
        _check_manifest_hashes_populated(manifest)
    except Exception as e:
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            duration_secs=time.monotonic() - start,
        )

    wheels_dir = target_dir / "wheels"
    hf_dir = target_dir / "hf-cache" / "sentence-transformers_all-MiniLM-L6-v2"

    files_checked = 0
    try:
        for w in manifest.get("wheels", []):
            p = wheels_dir / w["filename"]
            if not p.exists():
                raise FileNotFoundError(
                    f"Missing staged wheel: {w['filename']}"
                )
            actual = _hash_file(p)
            if actual != w["sha256"]:
                raise HashMismatch(w["filename"], w["sha256"], actual)
            files_checked += 1
        for model in manifest.get("models", []):
            for f in model.get("files", []):
                p = hf_dir / f["name"]
                if not p.exists():
                    raise FileNotFoundError(
                        f"Missing staged model file: {f['name']}"
                    )
                actual = _hash_file(p)
                if actual != f["sha256"]:
                    raise HashMismatch(f["name"], f["sha256"], actual)
                files_checked += 1
        _update_state(
            conn,
            status="installed",
            set_installed_now=True,
            clear_error=True,
        )
        return InstallResult(
            status="installed",
            files_installed=files_checked,
            duration_secs=time.monotonic() - start,
        )
    except Exception as e:
        _update_state(
            conn,
            status="failed",
            last_error_class=type(e).__name__,
            last_error_msg=str(e),
        )
        return InstallResult(
            status="failed",
            error_class=type(e).__name__,
            error_msg=_scrub_error(str(e)),
            files_installed=files_checked,
            duration_secs=time.monotonic() - start,
        )


# ---------------------------------------------------------------------------
# Public exports
# ---------------------------------------------------------------------------

__all__ = [
    "install_auto",
    "install_sideload",
    "get_install_status",
    "is_runtime_ready",
    "runtime_python_path",
    "runtime_imports_cleanly",
    "add_runtime_to_sys_path",
    "get_runtime_deps_path",
    "request_cancel",
    "clear_cancel",
    "is_cancel_requested",
    "invalidate_runtime_ready_cache",
    "reverify",
    "InstallResult",
    "InstallCancelled",
    "HashMismatch",
    "PipInstallError",
    "DEFAULT_MANIFEST_PATH",
    "DEFAULT_RUNTIME_DEPS",
]
