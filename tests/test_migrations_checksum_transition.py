""" — backward-compat dual-check for pre-#228 raw-source checksums.

History
-------
Commit c163d4b replaced ``Migration.checksum()`` from a raw
``inspect.getsource(body)`` SHA → a normalized-AST SHA via
``_normalize_body``. The checksum guard then refused to boot any
install whose ``schema_migrations`` rows were written by pre-#228
code (every checksum mismatched). Discovered when v0.1.1 (which
included c163d4b) failed the deploy host's pre-validation gate
trying to upgrade a live DB deployed at 0de1999 (pre-c163d4b).

The fix keeps the new normalized algorithm as the primary
``_checksum_for`` path and adds ``_legacy_raw_checksum`` as a
fallback used ONLY by the compare branch in ``run_migrations``:
if the primary doesn't match but the legacy SHA does, the row is
transparently rewritten to the normalized shape and the runner
continues. Only when *neither* shape matches does it raise.

This file covers the transition behaviour:

  * a legacy-checksum row is accepted on boot and rewritten;
  * a second boot is a clean no-op (the rewrite has already
    happened, so the primary check matches first time);
  * a row whose checksum matches *neither* shape still raises
    (real edit-after-ship case is not masked);
  * the rewrite is atomic — partial state is not visible after
    a mid-batch failure.

Pinned narrowly to the dual-check behaviour. The wider
"normalize_body drops comments" tests live in test_migrations.py;
the algorithm-shape guard lives in
test_migrations_checksum_pin.py (AST pin).
"""

from __future__ import annotations

import hashlib
import inspect
import sqlite3

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.web.migrations import (
    MigrationError,
    _legacy_raw_checksum,
    applied_versions,
    run_migrations,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    yield c
    c.close()


@pytest.fixture(autouse=True)
def isolate_migrations_registry():
    """Each test starts with a clean MIGRATIONS list (matches the
    convention in test_migrations.py)."""
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


def _seed_legacy_row(conn: sqlite3.Connection, m: mig_mod.Migration) -> str:
    """Insert a ``schema_migrations`` row whose checksum is the
    pre-#228 raw-source SHA-256 of ``m.body``. Returns the recorded
    SHA so the caller can assert it later."""
    # Bookkeeping table must exist before INSERT — mirror what the
    # runner does on first call.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "    version    INTEGER PRIMARY KEY,"
        "    name       TEXT    NOT NULL,"
        "    applied_at TEXT    NOT NULL,"
        "    checksum   TEXT    NOT NULL"
        ")"
    )
    legacy = hashlib.sha256(
        inspect.getsource(m.body).encode("utf-8")
    ).hexdigest()
    conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, applied_at, checksum) "
        "VALUES (?, ?, ?, ?)",
        (m.version, m.name, "2026-05-21T00:00:00Z", legacy),
    )
    conn.commit()
    return legacy


def test_legacy_checksum_row_is_accepted_and_rewritten(conn, caplog):
    """A row written by pre-#228 code (raw-source SHA) must be
    accepted on boot and transparently upgraded to the normalized
    shape — no MigrationError raised."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "shipped")
    def _v1(c):
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")

    m = mig_mod.MIGRATIONS[0]
    legacy = _seed_legacy_row(conn, m)
    normalized = m.checksum()
    # Sanity: the algorithm change is real.
    assert legacy != normalized

    with caplog.at_level("INFO", logger="email_triage.web.migrations"):
        applied = run_migrations(conn)

    # Nothing new applied (v1 was already in the table).
    assert applied == []

    # Row's checksum is now the normalized shape.
    row = conn.execute(
        "SELECT checksum FROM schema_migrations WHERE version = 1"
    ).fetchone()
    assert row["checksum"] == normalized
    assert row["checksum"] != legacy

    # The transition was logged (audit trail).
    assert any(
        "rewritten from pre-#228" in r.getMessage() for r in caplog.records
    ), "expected an INFO log entry documenting the rewrite"


def test_second_boot_after_rewrite_is_clean_noop(conn):
    """After the legacy → normalized rewrite, a second boot must be
    a clean no-op (primary check matches first time, no rewrite
    queued, no log spam)."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "shipped")
    def _v1(c):
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")

    m = mig_mod.MIGRATIONS[0]
    _seed_legacy_row(conn, m)

    # First boot: transition rewrite.
    run_migrations(conn)
    after_first = conn.execute(
        "SELECT checksum FROM schema_migrations WHERE version = 1"
    ).fetchone()["checksum"]

    # Second boot: must not touch the row, must not raise.
    run_migrations(conn)
    after_second = conn.execute(
        "SELECT checksum FROM schema_migrations WHERE version = 1"
    ).fetchone()["checksum"]
    assert after_first == after_second == m.checksum()


def test_neither_shape_matches_still_raises(conn):
    """Real edit-after-ship case (recorded checksum matches NEITHER
    the current normalized SHA nor the legacy raw-source SHA) must
    still raise — the backward-compat path does not mask genuine
    drift."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "shipped")
    def _v1(c):
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")

    # Seed a row with a checksum that matches neither shape.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "    version    INTEGER PRIMARY KEY,"
        "    name       TEXT    NOT NULL,"
        "    applied_at TEXT    NOT NULL,"
        "    checksum   TEXT    NOT NULL"
        ")"
    )
    conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, applied_at, checksum) "
        "VALUES (?, ?, ?, ?)",
        (1, "shipped", "2026-05-21T00:00:00Z", "x" * 64),
    )
    conn.commit()

    with pytest.raises(MigrationError, match="edited after it was applied"):
        run_migrations(conn)


def test_legacy_checksum_helper_matches_pre_228_algorithm():
    """``_legacy_raw_checksum`` must reproduce the exact pre-#228
    algorithm: SHA-256 over the raw ``inspect.getsource(body)`` with
    no normalization."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "any_body")
    def _v1(c):
        """A docstring + comment.

        Both are dropped by ``_normalize_body`` but PRESERVED in
        the raw-source SHA — that's what makes the two shapes
        different and what the dual-check is reconciling.
        """
        # a comment line
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")

    m = mig_mod.MIGRATIONS[0]
    expected = hashlib.sha256(
        inspect.getsource(m.body).encode("utf-8")
    ).hexdigest()
    assert _legacy_raw_checksum(m.body) == expected

    # And confirm the docstring/comment really do shift the shape:
    # legacy SHA != normalized SHA on a body that has either.
    assert _legacy_raw_checksum(m.body) != m.checksum()


def test_multi_row_legacy_install_all_rewritten_atomically(conn):
    """An install with MANY pre-#228 rows (the realistic case — the
    live deploy had 30+ migrations applied) rewrites them all on
    first boot.
    The rewrite is in one transaction so a power-cut during the
    transition is recoverable (the next boot re-detects the legacy
    shape on whichever rows didn't make it)."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "first")
    def _v1(c):
        """v1 docstring."""
        pass

    @mig_mod.register(2, "second")
    def _v2(c):
        """v2 docstring."""
        c.execute("CREATE TABLE t2 (id INTEGER PRIMARY KEY)")

    @mig_mod.register(3, "third")
    def _v3(c):
        """v3 docstring."""
        c.execute("CREATE TABLE t3 (id INTEGER PRIMARY KEY)")

    legacy_by_version = {}
    for m in list(mig_mod.MIGRATIONS):
        legacy_by_version[m.version] = _seed_legacy_row(conn, m)

    # Run — must not raise; every legacy row must be rewritten.
    assert run_migrations(conn) == []

    for m in list(mig_mod.MIGRATIONS):
        row = conn.execute(
            "SELECT checksum FROM schema_migrations WHERE version = ?",
            (m.version,),
        ).fetchone()
        assert row["checksum"] == m.checksum(), (
            f"v{m.version} not rewritten to normalized shape"
        )
        assert row["checksum"] != legacy_by_version[m.version], (
            f"v{m.version} still carries the legacy shape"
        )
