"""N-432 walresetbug P0 structural pin (2026-07-19).

Audit workflow ``wf_9eb87251-e17`` synthesis 2026-07-19 12:00 EDT surfaced
that email-triage's baked-in SQLite (3.45.3 via SQLCipher + 3.46.1 via
stdlib ``python:3.12-slim``) is BELOW the upstream walresetbug fix floor
(3.51.3, 2026-03-13). The bug races WAL checkpoint against concurrent
writers and can corrupt the WAL header; on the HMAC-chained
``log_entries`` audit table that is §164.312(b)/(c)(1) integrity loss.

P0 mitigation is TWO PARTS, both landed same-commit:

1. ``PRAGMA wal_autocheckpoint = 0`` at the opener SSOT
   ``db/_engine.py::_apply_standard_pragmas`` — disables SQLite's
   built-in reader-driven auto-checkpoint. The auto-checkpoint fires
   OUTSIDE the process-wide writer lock and IS the race surface.
2. Periodic serialized checkpoint via ``web/db.py::checkpoint_wal_truncate``
   (``@db_write``) wired to ``web/app.py::_wal_checkpoint_loop`` at 5-min
   cadence. Every checkpoint in the process runs on the writer thread
   under the writer-lock — no concurrent writer/checkpoint race.

This pin bans regressions of BOTH parts + the interprocedural drift shape
where a caller re-enables auto-checkpoint or calls a raw
``PRAGMA wal_checkpoint`` outside the SSOT.

Waives:
- ``db/_engine.py::_apply_standard_pragmas`` — the SSOT itself.
- ``web/db.py::checkpoint_wal_truncate`` — the serialized checkpoint SSOT.
- Test files (they may set autocheckpoint manually to REPRODUCE the pre-P0
  behaviour under negative-control tests).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_MODULE = "db/_engine.py"
_SSOT_FN = "_apply_standard_pragmas"
_CHECKPOINT_MODULE = "web/db.py"
_CHECKPOINT_FN = "checkpoint_wal_truncate"

# Additional waives for the raw-``PRAGMA wal_checkpoint`` pin: the
# migration-time plaintext quiesce primitive is a one-shot pre-app
# operation (no concurrent app writers exist at that point), so a raw
# checkpoint outside the writer-lock is safe by construction there.
_WAL_CHECKPOINT_WAIVES = {
    # `_checkpoint_plaintext` runs `BEGIN IMMEDIATE`/COMMIT quiesce at
    # db/_migrate.py:153 BEFORE the raw wal_checkpoint at :160 — refuses
    # if any writer holds RESERVED. Pre-app / migration primitive only.
    ("db/_migrate.py", "_checkpoint_plaintext"),
    # `decrypt_encrypted_db` runs the same `BEGIN IMMEDIATE` quiesce at
    # db/_migrate.py:312 BEFORE the raw wal_checkpoint at :319. Pre-app.
    ("db/_migrate.py", "decrypt_encrypted_db"),
}


def _iter_pragma_execute_calls(tree: ast.AST):
    """Yield (lineno, sql_string) for every ``<expr>.execute("PRAGMA ...")``."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"):
            continue
        if not node.args:
            continue
        arg0 = node.args[0]
        if not (isinstance(arg0, ast.Constant)
                and isinstance(arg0.value, str)):
            continue
        sql = arg0.value.strip().upper()
        if "PRAGMA" not in sql:
            continue
        yield node.lineno, arg0.value


def _find_fn_range(tree: ast.AST, fn_name: str) -> tuple[int, int] | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            return node.lineno, node.end_lineno or node.lineno
    return None


def _fn_containing_line(tree: ast.AST, lineno: int) -> str | None:
    """Return the innermost function name whose body contains ``lineno``."""
    best_name: str | None = None
    best_span = None
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        end = node.end_lineno or node.lineno
        if node.lineno <= lineno <= end:
            span = end - node.lineno
            if best_span is None or span < best_span:
                best_name = node.name
                best_span = span
    return best_name


def _has_decorator(tree: ast.AST, fn_name: str, decorator_name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == fn_name:
            for dec in node.decorator_list:
                if isinstance(dec, ast.Name) and dec.id == decorator_name:
                    return True
                if (isinstance(dec, ast.Attribute)
                        and dec.attr == decorator_name):
                    return True
    return False


def test_ssot_contains_wal_autocheckpoint_zero():
    """``_apply_standard_pragmas`` MUST set ``PRAGMA wal_autocheckpoint = 0``.

    Removing this line re-enables SQLite's built-in auto-checkpoint,
    which races the walresetbug outside the writer-lock. A pin that
    doesn't verify the SSOT contains the actual mitigation is worthless.
    """
    ssot_path = SRC_ROOT / _SSOT_MODULE
    tree = parse_module(ssot_path)
    assert tree is not None, f"Cannot parse {_SSOT_MODULE}"
    fn_range = _find_fn_range(tree, _SSOT_FN)
    assert fn_range is not None, f"{_SSOT_FN} not found in {_SSOT_MODULE}"
    lo, hi = fn_range
    found = False
    for lineno, sql in _iter_pragma_execute_calls(tree):
        if lo <= lineno <= hi and "WAL_AUTOCHECKPOINT" in sql.upper():
            # Any zero-valued setting counts. Reject non-zero even inside SSOT.
            if "= 0" in sql or "=0" in sql:
                found = True
                break
    assert found, (
        f"N-432 walresetbug P0: `{_SSOT_FN}` in {_SSOT_MODULE} must set "
        f"`PRAGMA wal_autocheckpoint = 0`. Removing / weakening this pin "
        f"re-exposes the HMAC-chained audit log to §164.312(b)/(c)(1) "
        f"integrity loss on SQLite < 3.51.3 (baked-in 3.45.3 + 3.46.1)."
    )


def test_no_raw_wal_autocheckpoint_write_outside_ssot():
    """Ban raw ``PRAGMA wal_autocheckpoint = ...`` outside the SSOT.

    Interprocedural: scans every source file. A caller that sets
    autocheckpoint to a non-zero value (or overrides the SSOT's zero
    later in a session-scoped conn) re-opens the race.
    """
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        ssot_range = None
        if rel == _SSOT_MODULE:
            ssot_range = _find_fn_range(tree, _SSOT_FN)
        for lineno, sql in _iter_pragma_execute_calls(tree):
            if "WAL_AUTOCHECKPOINT" not in sql.upper():
                continue
            if (ssot_range is not None
                    and ssot_range[0] <= lineno <= ssot_range[1]):
                continue  # SSOT itself
            offenders.append(f"{rel}:{lineno}  execute({sql!r})")
    assert not offenders, (
        "N-432 walresetbug P0: raw `PRAGMA wal_autocheckpoint = ...` "
        "outside the SSOT. The setting MUST route through "
        f"`{_SSOT_FN}` so every opened conn inherits it. Any override "
        "elsewhere re-exposes the WAL-checkpoint race under "
        "SQLite < 3.51.3.\n\n" + "\n".join(offenders)
    )


def test_no_raw_wal_checkpoint_call_outside_serialized_ssot():
    """Ban raw ``PRAGMA wal_checkpoint(...)`` outside ``checkpoint_wal_truncate``.

    The serialized-checkpoint SSOT is ``@db_write``-decorated so every
    checkpoint runs under the process-wide writer-lock. A caller that
    invokes ``PRAGMA wal_checkpoint`` directly bypasses that lock and
    can race a concurrent writer — the exact walresetbug race.
    """
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        tree = parse_module(path)
        if tree is None:
            continue
        ssot_range = None
        if rel == _CHECKPOINT_MODULE:
            ssot_range = _find_fn_range(tree, _CHECKPOINT_FN)
        for lineno, sql in _iter_pragma_execute_calls(tree):
            sql_upper = sql.upper()
            if "WAL_CHECKPOINT" not in sql_upper:
                continue
            # Skip the `wal_autocheckpoint` PRAGMA (different setting;
            # covered by its own pin above).
            if "WAL_AUTOCHECKPOINT" in sql_upper:
                continue
            if (ssot_range is not None
                    and ssot_range[0] <= lineno <= ssot_range[1]):
                continue  # SSOT itself
            fn = _fn_containing_line(tree, lineno)
            if fn is not None and (rel, fn) in _WAL_CHECKPOINT_WAIVES:
                continue  # explicitly waived migration primitive
            offenders.append(f"{rel}:{lineno}  execute({sql!r})")
    assert not offenders, (
        f"N-432 walresetbug P0: raw `PRAGMA wal_checkpoint(...)` outside "
        f"`{_CHECKPOINT_FN}` in {_CHECKPOINT_MODULE}. Every checkpoint "
        f"MUST run under the `@db_write` writer-lock so it cannot race a "
        f"concurrent writer.\n\n" + "\n".join(offenders)
    )


def test_serialized_checkpoint_ssot_is_db_write_decorated():
    """``checkpoint_wal_truncate`` MUST wear ``@db_write`` — that's what
    makes it serialized. Removing the decorator drops the writer-lock and
    the whole P0 mitigation goes with it.
    """
    path = SRC_ROOT / _CHECKPOINT_MODULE
    tree = parse_module(path)
    assert tree is not None, f"Cannot parse {_CHECKPOINT_MODULE}"
    assert _has_decorator(tree, _CHECKPOINT_FN, "db_write"), (
        f"N-432 walresetbug P0: `{_CHECKPOINT_FN}` in {_CHECKPOINT_MODULE} "
        f"must be `@db_write`-decorated. Without the writer-lock the "
        f"periodic checkpoint can race a concurrent writer — that IS "
        f"the walresetbug surface."
    )
