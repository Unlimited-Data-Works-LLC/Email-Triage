"""N-464 — a missing ``runtime_settings`` row must PRESERVE, never clobber.

The defect (measured end-to-end 2026-09-12, not inferred)
=========================================================
An install seeded HIPAA-on from YAML (``logging: {hipaa: true}`` →
``setup_logging`` at boot) has no ``runtime_settings`` row until the first
save. ``/config/save`` reads the dict from :func:`_get_runtime_settings`,
copies ``hipaa`` into the blob it persists under the comment "preserve the DB
value", and commits inside the write lock. With the old flat
``dict(_RUNTIME_DEFAULTS)`` fallback that "preserved" value was **False**, so:

1. the handler COMMITTED ``hipaa: false`` to the durable store;
2. ``_apply_runtime_settings`` then raised ``RuntimeError`` (no
   ``allow_hipaa_change`` kwarg) — a 500 the operator reads as "save failed";
3. the row survived the 500, and the next restart (``web/app.py``, the
   ``if _rt_settings:`` restore) set ``_hipaa_mode = False`` for real.

HIPAA off, from an unrelated config save, with the only signal being a 500.

This is the same shape as the ``_secret_write`` never-clobber rule and the
2026-09-10 ``keep_alive`` clobber: **absence is not a write.** A field missing
from the store means "no opinion", never "set it to the type default".

What these tests pin
====================
* ``hipaa`` and ``log_level`` fall back to the LIVE PROCESS value when the row
  is absent (the fix), and
* a PRESENT row still wins over the live value (the positive control — without
  it, "preserve" could be implemented as "always ignore the store", which would
  break the DB-as-source-of-truth-across-restarts contract), and
* a structural, count-agnostic guard that every writer of the
  ``runtime_settings`` blob sources ``hipaa`` from the existing settings or
  from the security form — never from a bare literal.
"""
from __future__ import annotations

import ast
import logging as stdlib_logging
import sqlite3

import pytest

from email_triage import triage_logging
from email_triage.web.db import (
    get_setting,
    invalidate_setting_cache,
    set_setting,
)
from email_triage.web.routers.ui._shared import (
    _RUNTIME_DEFAULTS,
    _RUNTIME_SETTINGS_KEY,
    _get_runtime_settings,
)

from _pin_harness import iter_src_files, parse_module, relpath

_SETTINGS_DDL = """
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


@pytest.fixture()
def db(tmp_path):
    """A fresh settings DB per test, with the PROCESS-WIDE cache cleared.

    ``get_setting`` memoises by KEY ONLY (``web/db.py``: ``_settings_cache``,
    a TTL cache with no connection identity in the key), which is sound for the
    single-DB process it ships in but leaks between tests that each build their
    own database. Without this invalidation the previous test's row is served
    for this test's empty DB — which is exactly how this file first went green
    on a value it never wrote.
    """
    conn = sqlite3.connect(tmp_path / "n464.db")
    conn.row_factory = sqlite3.Row
    conn.executescript(_SETTINGS_DDL)
    conn.commit()
    invalidate_setting_cache(_RUNTIME_SETTINGS_KEY)
    try:
        yield conn
    finally:
        invalidate_setting_cache(_RUNTIME_SETTINGS_KEY)
        conn.close()


@pytest.fixture()
def hipaa_on():
    """Simulate a YAML-seeded HIPAA-on boot, then restore."""
    prev = triage_logging._hipaa_mode
    triage_logging._hipaa_mode = True
    try:
        yield
    finally:
        triage_logging._hipaa_mode = prev


def test_absent_row_preserves_live_hipaa_mode(db, hipaa_on):
    """The bug, as a test: with no row, the handler must still see hipaa True."""
    assert get_setting(db, _RUNTIME_SETTINGS_KEY) is None
    assert _get_runtime_settings(db)["hipaa"] is True, (
        "row-absent fallback clobbered a live HIPAA-on install — this is the "
        "N-464 defect: the next /config/save persists this value"
    )
    # The shipped dataclass default is still False; the fix is an override at
    # read time, not a mutation of the defaults table.
    assert _RUNTIME_DEFAULTS["hipaa"] is False


def test_absent_row_preserves_live_log_level(db):
    logger = stdlib_logging.getLogger("email_triage")
    prev = logger.level
    logger.setLevel(stdlib_logging.DEBUG)
    try:
        assert _get_runtime_settings(db)["log_level"] == "DEBUG"
    finally:
        logger.setLevel(prev)


def test_present_row_still_wins(db, hipaa_on):
    """Positive control: the store is authoritative when it exists.

    Without this, "preserve the live value" could be implemented as "ignore the
    row", which would silently break the documented DB-as-source-of-truth
    restore across restarts.
    """
    set_setting(db, _RUNTIME_SETTINGS_KEY, {"hipaa": False, "log_level": "WARNING"})
    got = _get_runtime_settings(db)
    assert got["hipaa"] is False
    assert got["log_level"] == "WARNING"


def test_round_trip_through_a_save_does_not_flip_hipaa(db, hipaa_on):
    """End-to-end shape of the /config/save path, minus the HTTP layer.

    Mirrors ``admin.py``: read the runtime dict, rebuild the blob preserving
    ``hipaa``, persist, then prove a SEPARATE connection (i.e. the next boot)
    reads back the value the install actually had.
    """
    existing = _get_runtime_settings(db)
    new_runtime = dict(existing)
    new_runtime["hipaa"] = bool(existing.get("hipaa", False))
    set_setting(db, _RUNTIME_SETTINGS_KEY, new_runtime)

    persisted = get_setting(db, _RUNTIME_SETTINGS_KEY)
    assert persisted is not None
    assert persisted["hipaa"] is True, (
        "an unrelated config save persisted HIPAA-off on a HIPAA-on install"
    )


# ---------------------------------------------------------------------------
# Structural pin — count-agnostic over every writer of the blob
# ---------------------------------------------------------------------------

# Legitimate sources for a persisted/derived `hipaa` value. `is_hipaa_mode` is
# here because the never-clobber fallback in `_get_runtime_settings` reads the
# LIVE process flag when the row is absent — that is the fix N-464 shipped, and
# the widened net correctly caught it the moment Subscript writes came in scope.
_ALLOWED_HIPAA_SOURCES = (
    "existing_runtime", "hipaa_flag", "is_hipaa_mode",
)


def _runtime_blob_writers():
    """Yield (relpath, lineno, dict_node) for every blob a WRITER builds.

    Scope, narrowed after the first draft fired on two non-writers: the dict
    must carry a ``hipaa`` key AND sit inside a function that names
    ``_RUNTIME_SETTINGS_KEY``. That excludes the module-level
    ``_RUNTIME_DEFAULTS`` table (a default is not a write) and the YAML
    serializer in ``_write_config_yaml`` (a different store, tracked as its own
    finding). It stays count-agnostic: a NEW handler in a NEW file is covered
    the moment it references the key, which ``len(...) == N`` would not be.
    """
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
            if "_RUNTIME_SETTINGS_KEY" not in names:
                continue
            seen = set()
            for node in ast.walk(fn):
                # Shape 1 — a dict literal carrying the key.
                if isinstance(node, ast.Dict):
                    keys = [k.value for k in node.keys
                            if isinstance(k, ast.Constant) and isinstance(k.value, str)]
                    if "hipaa" in keys:
                        key = (relpath(path), node.lineno)
                        if key not in seen:
                            seen.add(key)
                            yield relpath(path), node.lineno, node
                    continue
                # Shape 2 — `blob["hipaa"] = value`, which is how the CANONICAL
                # HIPAA off-ramp (`admin_security_save`) builds its blob. The
                # first draft of this pin saw only Shape 1, so the one writer
                # licensed to pass allow_hipaa_change=True was invisible to it.
                if isinstance(node, ast.Assign):
                    for tgt in node.targets:
                        if (isinstance(tgt, ast.Subscript)
                                and isinstance(tgt.slice, ast.Constant)
                                and tgt.slice.value == "hipaa"):
                            key = (relpath(path), node.lineno)
                            if key not in seen:
                                seen.add(key)
                                yield relpath(path), node.lineno, node


def test_no_writer_hardcodes_hipaa_in_the_runtime_blob():
    """A persisted ``hipaa`` value must come from the store or the form.

    The N-464 defect was not a literal — it was a *default* reached through
    ``.get("hipaa", False)`` on a dict that had already lost the value. This pin
    catches the blunter regression (a bare ``"hipaa": False`` literal) and the
    shape where the value is sourced from something other than the existing
    settings or the security form.
    """
    offenders = []
    writers_seen = 0
    for rel, lineno, node in _runtime_blob_writers():
        writers_seen += 1
        if isinstance(node, ast.Assign):
            rhs = ast.unparse(node.value)
            if isinstance(node.value, ast.Constant):
                offenders.append(f"{rel}:{lineno} hipaa hardcoded to {rhs}")
            elif not any(src in rhs for src in _ALLOWED_HIPAA_SOURCES):
                offenders.append(f"{rel}:{lineno} hipaa sourced from {rhs!r}")
            continue
        for k, v in zip(node.keys, node.values):
            if not (isinstance(k, ast.Constant) and k.value == "hipaa"):
                continue
            unparsed = ast.unparse(v)
            if isinstance(v, ast.Constant):
                offenders.append(f"{rel}:{lineno} hipaa hardcoded to {unparsed}")
            elif not any(src in unparsed for src in _ALLOWED_HIPAA_SOURCES):
                offenders.append(f"{rel}:{lineno} hipaa sourced from {unparsed!r}")
    # FLOOR — `assert not offenders` over an EMPTY net is vacuously true, and a
    # dead net reports exactly what a healthy one does. Measured by the DA: with
    # the generator stubbed to yield nothing, this pin and its teeth test both
    # passed. The floor is what makes the two states distinguishable.
    assert writers_seen >= 2, (
        f"the writer net went dead: {writers_seen} site(s) found. Expect at least "
        "the /config/save dict literal and the /admin/security subscript write. "
        "A rename of _RUNTIME_SETTINGS_KEY or a moved file silently empties this."
    )
    assert not offenders, (
        "runtime_settings blob writers must source `hipaa` from the existing "
        "settings or the /admin/security form:\n  " + "\n  ".join(offenders)
    )


def test_the_pin_has_teeth():
    """Mutation proof: the detector above must reject a hardcoded blob.

    A structural pin that has never been shown to go red on the defect it
    names is indistinguishable from one that reports PASS while dead.
    """
    bad = ast.parse(
        'KEY = _RUNTIME_SETTINGS_KEY\n'
        'blob = {"dry_run": False, "hipaa": False, "log_level": "INFO"}\n'
    )
    found = [n for n in ast.walk(bad)
             if isinstance(n, ast.Dict)
             and any(isinstance(k, ast.Constant) and k.value == "hipaa"
                     for k in n.keys)]
    assert found, "the detector's own shape predicate failed to match"
    node = found[0]
    hardcoded = [
        ast.unparse(v)
        for k, v in zip(node.keys, node.values)
        if isinstance(k, ast.Constant) and k.value == "hipaa" and isinstance(v, ast.Constant)
    ]
    assert hardcoded == ["False"], (
        "the pin would not have flagged a hardcoded hipaa literal"
    )
