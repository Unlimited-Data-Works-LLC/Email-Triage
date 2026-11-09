"""Atomic file writes — the crash-safe write SSOT (A11, census 2026-06-09).

A plain ``open(path, "w")`` TRUNCATES the file before writing; a crash (or a
raised exception) mid-write leaves the file half-written — for a config /
state file that means a corrupt YAML the next boot can't parse. The
codebase already knew this and hand-rolled "write a sibling tempfile then
``os.replace``" in ~5 places (``tls.py``, ``tls_csr.py``, ``acme_renewer``,
``db/_migrate``, ``embedding_bits``) — but the config writer
(``_write_config_yaml``) used a bare ``open(..., "w")`` and was the one
critical writer that could corrupt its target.

``os.replace`` is atomic on POSIX and Windows (same-filesystem rename), so a
reader sees either the old file or the new one, never a torn write.
``tests/test_atomic_write_pin_a11.py`` pins config/state writers to this.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Union

_PathLike = Union[str, "os.PathLike[str]"]


def atomic_write_text(
    path: _PathLike, text: str, *, encoding: str = "utf-8",
    mode: int | None = None,
) -> None:
    """Atomically write ``text`` to ``path``.

    Writes a sibling temp file (same directory, so ``os.replace`` is a
    same-filesystem atomic rename), ``fsync``s it, then replaces the target.
    On any failure the temp file is cleaned up and the original is left
    intact (never truncated).

    ``mode`` (e.g. ``0o600``): chmod the temp BEFORE the replace, so the
    active file is only ever swapped to the restricted-perms copy — there is
    no window where it is world-readable. Used for sensitive files (OAuth
    token caches, the secrets store, TLS private keys). POSIX-effective;
    a best-effort no-op on Windows (the deploy target is Linux).

    Notes (db-sme A11 review): assumes ``path`` is a regular file, not a
    symlink — ``os.replace`` replaces the link itself rather than following
    it (config/state paths here are never symlinks). The ``fsync`` only buys
    durability across power-loss, not atomicity (``os.replace`` provides
    that); if ``fsync`` raises on an exotic mount the write fails closed
    (caller sees the error, target file untouched), which is acceptable —
    never a torn write."""
    p = Path(path)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                # Fail CLOSED on POSIX — never os.replace a world-readable
                # credential file into place; only swallow on Windows, which
                # has no POSIX perms model (the deploy target is Linux).
                import sys
                if sys.platform != "win32":
                    raise
        os.replace(tmp, p)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def atomic_write_bytes(
    path: _PathLike, data: bytes, *, mode: int | None = None,
    pre_replace: "Callable[[Path], None] | None" = None,
) -> None:
    """Binary sibling of :func:`atomic_write_text` (``mode`` as documented there).

    ``pre_replace`` (N-210b R23 extension, 2026-07-02): optional callback that
    runs AFTER chmod-of-tmp but BEFORE os.replace. Callback receives the tmp
    path; raise any exception to abort the swap (tmp is unlinked, target file
    unchanged). Use for HIPAA-integrity verify-before-swap patterns —
    ``backup.py``'s ``_verify_snapshot_file(tmp)`` and pubkey-bundle checks.
    """
    p = Path(path)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None:
            try:
                os.chmod(tmp, mode)
            except OSError:
                # Fail CLOSED on POSIX — never os.replace a world-readable
                # credential file into place; only swallow on Windows, which
                # has no POSIX perms model (the deploy target is Linux).
                import sys
                if sys.platform != "win32":
                    raise
        if pre_replace is not None:
            pre_replace(tmp)  # raises → the outer except unlinks + re-raises
        os.replace(tmp, p)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
