"""N-432 migration-primitive live-app guard pin (devils-advocate NTH-3 fold, 2026-07-19).

The raw-``sqlite3.connect`` migration primitives in :mod:`email_triage.db._migrate`
(``encrypt_plaintext_db``, ``decrypt_encrypted_db``, ``_checkpoint_plaintext``)
are safe by *timing* — invoked pre-app by CLI verbs or under a quiesce-gated
``BEGIN IMMEDIATE``. The N-432 SME panel (devils-advocate NTH-3) flagged that
this convention has no runtime enforcement: a future call site (test harness,
dev-mode script, a folded CLI verb invoked mid-lifespan) could silently violate
the assumption and re-open the walresetbug race window against the running app.

The enforcement half is :mod:`email_triage.db._live_app_gate` —
``mark_app_live`` / ``mark_app_stopped`` (called from ``web/app.py`` lifespan)
+ ``assert_no_live_app`` (called from the migration primitives). This pin
verifies both halves.
"""
from __future__ import annotations

import ast
import pytest

from _pin_harness import SRC_ROOT, parse_module


def _walk_functiondefs(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def _fn_calls_assert_no_live_app(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for sub in ast.walk(fn):
        if not isinstance(sub, ast.Call):
            continue
        f = sub.func
        if isinstance(f, ast.Name) and f.id == "assert_no_live_app":
            return True
    return False


def test_migration_primitives_call_assert_no_live_app():
    """AST: every PUBLIC migration primitive must call ``assert_no_live_app``
    at entry.

    Public = non-underscore-prefixed. Underscore-prefixed helpers
    (``_checkpoint_plaintext``, ``_is_plaintext_sqlite``) are covered by their
    caller's guard.
    """
    path = SRC_ROOT / "db/_migrate.py"
    tree = parse_module(path)
    assert tree is not None, "Cannot parse db/_migrate.py"

    REQUIRED = {"encrypt_plaintext_db", "decrypt_encrypted_db"}
    seen: set[str] = set()
    missing: list[str] = []

    for fn in _walk_functiondefs(tree):
        if fn.name not in REQUIRED:
            continue
        seen.add(fn.name)
        if not _fn_calls_assert_no_live_app(fn):
            missing.append(fn.name)

    unfound = REQUIRED - seen
    assert not unfound, (
        f"N-432 DA NTH-3: expected migration primitives {sorted(unfound)} "
        "not found in db/_migrate.py — the pin is stale, update REQUIRED."
    )
    assert not missing, (
        "N-432 DA NTH-3: these migration primitives DO NOT call "
        "`assert_no_live_app(...)` at entry:\n  " + "\n  ".join(missing)
        + "\nAdd `from email_triage.db._live_app_gate import assert_no_live_app;"
        " assert_no_live_app(\"<fn-name>\")` as the first executable statement — "
        "protects against a future call site running against a live app."
    )


def test_lifespan_marks_app_live_and_stopped():
    """AST: ``web/app.py::lifespan`` must call ``mark_app_live()`` BEFORE the
    ``yield`` and ``mark_app_stopped()`` AFTER (in the shutdown path).
    """
    path = SRC_ROOT / "web/app.py"
    tree = parse_module(path)
    assert tree is not None, "Cannot parse web/app.py"

    # Find the `lifespan` function.
    lifespan_fn: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for fn in _walk_functiondefs(tree):
        if fn.name == "lifespan":
            lifespan_fn = fn
            break
    assert lifespan_fn is not None, "Could not locate `lifespan` in web/app.py"

    yield_line: int | None = None
    live_line: int | None = None
    stopped_line: int | None = None
    writer_shutdown_line: int | None = None

    for sub in ast.walk(lifespan_fn):
        if isinstance(sub, ast.Yield) and yield_line is None:
            yield_line = sub.lineno
        if isinstance(sub, ast.Call):
            f = sub.func
            if isinstance(f, ast.Name) and f.id == "mark_app_live" and live_line is None:
                live_line = sub.lineno
            if isinstance(f, ast.Name) and f.id == "mark_app_stopped" and stopped_line is None:
                stopped_line = sub.lineno
            # `<writer>.shutdown()` — the db-writer drain anchor. Take the
            # LAST occurrence so we anchor on the writer drain, not any
            # earlier `.shutdown()` (there is only one today, but be
            # defensive).
            if (
                isinstance(f, ast.Attribute)
                and f.attr == "shutdown"
            ):
                writer_shutdown_line = sub.lineno

    assert yield_line is not None, "lifespan has no `yield` — malformed"
    assert live_line is not None, (
        "N-432 DA NTH-3: `web/app.py::lifespan` must call `mark_app_live()` "
        "in the startup phase to stamp the process-global gate."
    )
    assert stopped_line is not None, (
        "N-432 DA NTH-3: `web/app.py::lifespan` must call `mark_app_stopped()` "
        "in the shutdown phase to clear the process-global gate."
    )
    assert live_line < yield_line, (
        f"N-432 DA NTH-3: `mark_app_live()` (line {live_line}) must appear "
        f"BEFORE the `yield` (line {yield_line}) so migration primitives "
        "invoked during the yield-window are refused."
    )
    assert stopped_line > yield_line, (
        f"N-432 DA NTH-3: `mark_app_stopped()` (line {stopped_line}) must "
        f"appear AFTER the `yield` (line {yield_line}) so the gate stays "
        "set for the whole serving-window."
    )
    # DA-SF-1 (batched NTH-panel 2026-07-19): mark_app_stopped MUST be the
    # LAST shutdown step, after the db-writer drain — otherwise the gate
    # LIES while the writer thread is still routing db_call and any
    # mid-shutdown migration primitive sees a false-negative guard.
    if writer_shutdown_line is not None:
        assert stopped_line > writer_shutdown_line, (
            f"N-432 DA-SF-1: `mark_app_stopped()` (line {stopped_line}) "
            f"must appear AFTER the last `.shutdown()` (line "
            f"{writer_shutdown_line}) — the db-writer drain. Otherwise "
            "the gate is cleared while the writer thread is still alive, "
            "leaving a shutdown-window gap where a migration primitive "
            "would pass the guard falsely."
        )


@pytest.fixture
def _reset_app_live_gate():
    """Ensures the process-global gate is stopped before and after the test —
    critical because the flag is process-scoped and other tests may leave it
    set (though none should — the app-live wiring is only in lifespan)."""
    from email_triage.db._live_app_gate import mark_app_stopped
    mark_app_stopped()
    yield
    mark_app_stopped()


def test_encrypt_plaintext_db_refuses_when_app_live(_reset_app_live_gate, tmp_path):
    """Runtime: with the app-live gate set, ``encrypt_plaintext_db`` raises
    ``LiveAppMigrationRefused`` and does NOT touch the file.
    """
    from email_triage.db._live_app_gate import (
        LiveAppMigrationRefused, mark_app_live,
    )
    from email_triage.db._migrate import encrypt_plaintext_db

    # Create a minimal plaintext file; the guard fires BEFORE any file work.
    db_path = tmp_path / "triage.db"
    db_path.write_bytes(b"")  # empty; guard runs first, so validity irrelevant.

    mark_app_live()
    with pytest.raises(LiveAppMigrationRefused, match="encrypt_plaintext_db"):
        encrypt_plaintext_db(str(db_path), master_key="k" * 32)


def test_decrypt_encrypted_db_refuses_when_app_live(_reset_app_live_gate, tmp_path):
    """Runtime: with the app-live gate set, ``decrypt_encrypted_db`` raises
    ``LiveAppMigrationRefused`` and does NOT touch the file.
    """
    from email_triage.db._live_app_gate import (
        LiveAppMigrationRefused, mark_app_live,
    )
    from email_triage.db._migrate import decrypt_encrypted_db

    db_path = tmp_path / "triage.db"
    db_path.write_bytes(b"")

    mark_app_live()
    with pytest.raises(LiveAppMigrationRefused, match="decrypt_encrypted_db"):
        decrypt_encrypted_db(str(db_path), master_key="k" * 32)


def test_gate_toggle_roundtrip(_reset_app_live_gate):
    """Sanity: the flag toggles and is-app-live reflects it."""
    from email_triage.db._live_app_gate import (
        is_app_live, mark_app_live, mark_app_stopped,
    )
    assert is_app_live() is False
    mark_app_live()
    assert is_app_live() is True
    mark_app_stopped()
    assert is_app_live() is False
