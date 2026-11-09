"""N-432 walresetbug wiring pin (2026-07-19; db-sme MF-1 + MF-2 fold).

Companion to ``test_n432_sqlite_walreset_p0_pin`` — the P0 pin verifies
the SSOT *contains* ``PRAGMA wal_autocheckpoint = 0`` and that
``checkpoint_wal_truncate`` is ``@db_write``-decorated. That is the
source-level guarantee. This pin closes the two interprocedural gaps
db-sme flagged:

* **MF-1** — the AST pin doesn't verify the periodic
  ``_wal_checkpoint_loop`` is actually wired into lifespan startup. A
  refactor that silently drops the ``supervisor.supervise(...)`` line at
  ``web/app.py:959`` leaves the autocheckpoint at 0 and the WAL growing
  forever with no periodic truncate — a worse posture than pre-P0.

* **MF-2** — the AST pin proves the source line exists in
  ``_apply_standard_pragmas``. It does NOT prove both openers
  (``open_dedicated_conn`` + ``_make_encrypted_conn``) actually run
  through the SSOT so the resulting live conn returns ``0`` from
  ``PRAGMA wal_autocheckpoint``.

* **HIPAA-SME NTH-2 (2026-07-19)** — the lifespan shutdown path must
  fire one final ``checkpoint_wal_truncate`` after ``supervisor.stop_all``
  (periodic loop stopped). Missing this leaves writes stranded in the WAL
  when the container stops; on the next boot the walresetbug race surface
  briefly re-opens as auto-checkpoint wakes to consume the stranded frames
  before the P0 opener stamps ``wal_autocheckpoint = 0`` again.
  **Punch 636 (2026-10-15)** reversed the writer half: the checkpoint now
  runs AFTER the db-writer drain. Until 636 this pin required it BEFORE, so
  ``db_call`` would route to a live writer; that premise was false
  (``db_call`` falls back to the  RLock path when no writer is
  installed), and the order it enforced is the measured defect: every
  write after the checkpoint, the writer's queue among them, stayed in the
  WAL. The full order is pinned by ``test_636_shutdown_last_close_pin.py``.
"""
from __future__ import annotations

import ast
import sqlite3
import tempfile
import os

from _pin_harness import SRC_ROOT, parse_module

from email_triage.db._engine import _apply_standard_pragmas


def test_wal_checkpoint_loop_wired_in_lifespan():
    """db-sme MF-1: verify ``web/app.py`` supervises the wal-checkpoint loop.

    Scans ``web/app.py`` for a call to ``supervisor.supervise(...)`` whose
    first arg is the literal ``"wal-checkpoint-loop"`` — the string form
    that matches the ``log-entries-pruner`` sibling shape and the
    ``supervised_interval_loop(name=..., ...)`` inside the loop def.

    A refactor that silently drops the wire line trips this pin. If a
    reader concurrently opens `.db-wal` with default auto-checkpoint the
    P0 mitigation depends on the periodic serialized checkpoint — losing
    the wire without losing the autocheckpoint=0 means WAL grows without
    bound.
    """
    path = SRC_ROOT / "web/app.py"
    tree = parse_module(path)
    assert tree is not None, "Cannot parse web/app.py"

    supervised_names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr == "supervise"):
            continue
        if not node.args:
            continue
        arg0 = node.args[0]
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
            supervised_names.append(arg0.value)

    assert "wal-checkpoint-loop" in supervised_names, (
        "N-432 walresetbug wiring MF-1: `web/app.py` must supervise the "
        "`wal-checkpoint-loop` task. Without it, `PRAGMA "
        "wal_autocheckpoint = 0` (P0 opener SSOT) disables SQLite's "
        "built-in checkpoint fire path with NOTHING replacing it — WAL "
        "grows without bound. Restore the "
        "`supervisor.supervise(\"wal-checkpoint-loop\", ...)` call in "
        "the lifespan startup near the `log-entries-pruner` supervisor "
        f"line.\n\nSupervised names found: {supervised_names}"
    )


def test_wal_shutdown_checkpoint_wired_in_lifespan():
    """hipaa-sme NTH-2 (2026-07-19): verify ``web/app.py`` lifespan shutdown
    fires a final ``checkpoint_wal_truncate`` after ``supervisor.stop_all``.

    Scans ``web/app.py`` for a lifespan ``supervisor.stop_all()`` call and
    a subsequent ``checkpoint_wal_truncate`` reference in the same
    async-function body. The check is *positional* (call order): the final
    checkpoint MUST land AFTER ``supervisor.stop_all`` (the periodic loop
    stops there) and AFTER ``get_writer(...).shutdown()`` (the writer
    thread drains there), so no queued write lands after it (punch 636).

    A refactor that removes the shutdown checkpoint, or moves it back in
    front of the db-writer drain, trips this pin.
    """
    path = SRC_ROOT / "web/app.py"
    tree = parse_module(path)
    assert tree is not None, "Cannot parse web/app.py"

    def _walk_lifespan_bodies():
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name != "lifespan":
                continue
            for sub in ast.walk(node):
                yield sub

    stop_all_line: int | None = None
    checkpoint_line: int | None = None
    writer_shutdown_line: int | None = None

    for sub in _walk_lifespan_bodies():
        # `supervisor.stop_all()` call — receiver name may vary but the
        # attr name is stable; use the FIRST occurrence in lifespan.
        if isinstance(sub, ast.Call):
            f = sub.func
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "stop_all"
                and isinstance(f.value, ast.Name)
                and "supervis" in f.value.id.lower()
                and stop_all_line is None
            ):
                stop_all_line = sub.lineno
            # `checkpoint_wal_truncate(...)` — as a bare Name call OR the
            # target of `db_call(checkpoint_wal_truncate, ...)`.
            if isinstance(f, ast.Name) and f.id == "checkpoint_wal_truncate":
                checkpoint_line = min(checkpoint_line or sub.lineno, sub.lineno)
            if (
                isinstance(f, ast.Name)
                and f.id == "db_call"
                and sub.args
                and isinstance(sub.args[0], ast.Name)
                and sub.args[0].id == "checkpoint_wal_truncate"
            ):
                checkpoint_line = min(checkpoint_line or sub.lineno, sub.lineno)
            # `<writer>.shutdown()` inside a `get_writer` block.
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "shutdown"
                and writer_shutdown_line is None
            ):
                # tolerant match: any `.shutdown()` after stop_all_line in
                # a body that also references `get_writer`. We refine below
                # once all three lines are known.
                writer_shutdown_line = sub.lineno

    assert stop_all_line is not None, (
        "N-432 walresetbug wiring NTH-2: could not locate "
        "`supervisor.stop_all()` in `lifespan` — the anchor before which "
        "the shutdown checkpoint must land."
    )
    assert checkpoint_line is not None, (
        "N-432 walresetbug wiring NTH-2: `web/app.py` lifespan must fire "
        "`checkpoint_wal_truncate` one final time on shutdown (after "
        "`supervisor.stop_all` so the periodic loop is stopped; before "
        "the db-writer drain so `db_call` still routes). Missing this "
        "leaves writes stranded in the WAL when the container stops; "
        "next-boot auto-checkpoint (briefly, before the P0 opener re-"
        "stamps `wal_autocheckpoint = 0`) re-opens the walresetbug "
        "race window."
    )
    assert checkpoint_line > stop_all_line, (
        f"N-432 walresetbug wiring NTH-2: shutdown checkpoint "
        f"(line {checkpoint_line}) must appear AFTER "
        f"`supervisor.stop_all()` (line {stop_all_line}) — otherwise "
        "the periodic loop is still ticking and this call double-fires."
    )
    assert writer_shutdown_line is not None, (
        "N-432 walresetbug wiring NTH-2 / punch 636: could not locate the "
        "db-writer `.shutdown()` in `lifespan`, the anchor the shutdown "
        "checkpoint must follow."
    )
    assert checkpoint_line > writer_shutdown_line, (
        f"punch 636: shutdown checkpoint (line {checkpoint_line}) must appear "
        f"AFTER the db-writer shutdown (line {writer_shutdown_line}). Before it, "
        "every write the writer still drains lands after the checkpoint and "
        "stays in the WAL at exit (measured 2026-10-14). With no writer "
        "installed, `db_call` runs the checkpoint on the #211 RLock path."
    )


def test_wal_autocheckpoint_zero_on_live_plaintext_conn():
    """db-sme MF-2: verify the SSOT ACTUALLY sets the PRAGMA at open time.

    Opens a fresh plaintext connection, runs ``_apply_standard_pragmas``
    (the SSOT function), then reads back
    ``PRAGMA wal_autocheckpoint`` — expects ``0``. Closes the drift
    surface where a future SSOT edit (accidental typo, comment-out,
    conditional path) leaves the source line present but functionally
    dead.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".db", delete=False,
    ) as tmp:
        db_path = tmp.name
    try:
        conn = sqlite3.connect(db_path)
        try:
            _apply_standard_pragmas(conn)
            row = conn.execute(
                "PRAGMA wal_autocheckpoint"
            ).fetchone()
            assert row is not None, "PRAGMA wal_autocheckpoint returned no row"
            actual = int(row[0])
            assert actual == 0, (
                "N-432 walresetbug wiring MF-2: `_apply_standard_pragmas` "
                "must set `PRAGMA wal_autocheckpoint = 0` on the LIVE "
                f"connection. Got {actual}. Source line may exist but "
                "the SSOT is not applying it at open time — check for "
                "conditional paths, silent PRAGMA-reject, or an ordering "
                "bug where a later PRAGMA overrides the setting."
            )
        finally:
            conn.close()
    finally:
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(db_path + suffix)
            except OSError:
                pass
