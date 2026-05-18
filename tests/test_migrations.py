"""Tests for the numbered schema-migration framework."""

from __future__ import annotations

import sqlite3

import pytest

from email_triage.web import migrations as mig_mod
from email_triage.web.migrations import (
    Migration,
    MigrationError,
    applied_versions,
    pending_migrations,
    run_migrations,
    schema_version,
)


@pytest.fixture
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    yield c
    c.close()


@pytest.fixture(autouse=True)
def isolate_migrations_registry():
    """Each test starts with a clean MIGRATIONS list.

    The module-level ``MIGRATIONS`` registry is append-only by design;
    tests that register synthetic migrations would otherwise pollute
    the global state for subsequent tests.
    """
    saved = list(mig_mod.MIGRATIONS)
    yield
    mig_mod.MIGRATIONS.clear()
    mig_mod.MIGRATIONS.extend(saved)


# ---------------------------------------------------------------------------
# Bookkeeping behaviour
# ---------------------------------------------------------------------------

def test_fresh_db_starts_at_version_zero(conn):
    assert schema_version(conn) == 0
    assert applied_versions(conn) == {}


def test_register_and_apply_migration(conn):
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "create_widgets")
    def _v1(c):
        c.execute("CREATE TABLE widgets (id INTEGER PRIMARY KEY)")

    applied = run_migrations(conn)
    assert applied == [1]
    assert schema_version(conn) == 1
    rows = applied_versions(conn)
    assert rows[1]["name"] == "create_widgets"
    # Table actually exists.
    conn.execute("INSERT INTO widgets DEFAULT VALUES")


def test_run_migrations_is_idempotent(conn):
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "noop")
    def _v1(c):
        pass

    run_migrations(conn)
    second = run_migrations(conn)
    assert second == []  # nothing to do
    assert schema_version(conn) == 1


def test_pending_excludes_already_applied(conn):
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "first")
    def _v1(c):
        pass

    run_migrations(conn)

    @mig_mod.register(2, "second")
    def _v2(c):
        pass

    pending = pending_migrations(conn)
    assert [m.version for m in pending] == [2]


def test_duplicate_version_raises_at_register():
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "first")
    def _v1(c):
        pass

    with pytest.raises(RuntimeError, match="duplicate"):
        @mig_mod.register(1, "again")
        def _v1b(c):
            pass


def test_out_of_order_version_raises_at_register():
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(5, "five")
    def _v5(c):
        pass

    with pytest.raises(RuntimeError, match="strictly increase"):
        @mig_mod.register(3, "three")
        def _v3(c):
            pass


# ---------------------------------------------------------------------------
# Failure handling
# ---------------------------------------------------------------------------

def test_body_failure_rolls_back_and_records_nothing(conn):
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "broken")
    def _v1(c):
        c.execute("CREATE TABLE half (id INTEGER PRIMARY KEY)")
        raise RuntimeError("simulated mid-migration failure")

    with pytest.raises(MigrationError, match="broken"):
        run_migrations(conn)

    # Table created INSIDE the transaction must NOT survive.
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='half'"
    )
    assert cur.fetchall() == []
    # No bookkeeping row written either.
    assert applied_versions(conn) == {}


def test_subsequent_migration_runs_after_failure_fixed(conn):
    """If a migration body is fixed and re-tried, runner picks up where
    it left off (the failed one is still pending)."""
    mig_mod.MIGRATIONS.clear()
    fail_count = [0]

    @mig_mod.register(1, "flaky")
    def _v1(c):
        if fail_count[0] == 0:
            fail_count[0] += 1
            raise RuntimeError("first attempt fails")
        c.execute("CREATE TABLE later (id INTEGER PRIMARY KEY)")

    with pytest.raises(MigrationError):
        run_migrations(conn)
    # Try again — should succeed now.
    applied = run_migrations(conn)
    assert applied == [1]
    conn.execute("INSERT INTO later DEFAULT VALUES")


def test_checksum_mismatch_refuses_to_run(conn):
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "shipped")
    def _v1(c):
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY)")

    run_migrations(conn)

    # Simulate someone editing the migration body in place AFTER
    # it shipped: replace the entry in the module-level registry
    # with a body whose source differs.
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "shipped")
    def _v1_edited(c):
        c.execute("CREATE TABLE foo (id INTEGER PRIMARY KEY, name TEXT)")

    with pytest.raises(MigrationError, match="edited after it was applied"):
        run_migrations(conn)


def test_db_newer_than_code_refuses(conn):
    """If the bookkeeping table reports a higher version than this
    code knows about (rollback to older code), runner refuses."""
    mig_mod.MIGRATIONS.clear()

    @mig_mod.register(1, "v1")
    def _v1(c):
        pass

    run_migrations(conn)

    # Plant a fake row implying a v999 has been applied.
    conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, applied_at, checksum) VALUES (?, ?, ?, ?)",
        (999, "from_future", "2099-01-01T00:00:00Z", "x" * 64),
    )
    conn.commit()

    with pytest.raises(MigrationError, match="only knows up to"):
        run_migrations(conn)


# ---------------------------------------------------------------------------
# Integration with init_db
# ---------------------------------------------------------------------------

def test_init_db_runs_framework_and_creates_v1():
    """init_db should run the registered framework migrations, including
    the bootstrap v1 row."""
    from email_triage.web.db import init_db

    conn = init_db(":memory:")
    try:
        # Bookkeeping table exists.
        rows = conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        versions = [r[0] for r in rows]
        # At minimum, v1 (framework bootstrap) is recorded.
        assert 1 in versions
    finally:
        conn.close()


def test_init_db_idempotent_against_old_db_layout():
    """Running init_db a second time on the same connection (simulating
    a fresh process picking up an existing DB) must be a no-op for the
    framework — no duplicate-version errors, no checksum drift."""
    from email_triage.web.db import init_db

    # First init creates schema + framework row.
    conn = init_db(":memory:")
    try:
        rows_before = conn.execute(
            "SELECT version, checksum FROM schema_migrations"
        ).fetchall()
        # Re-run framework runner against the same connection.
        from email_triage.web.migrations import run_migrations
        applied = run_migrations(conn)
        assert applied == []  # nothing new
        rows_after = conn.execute(
            "SELECT version, checksum FROM schema_migrations"
        ).fetchall()
        assert [tuple(r) for r in rows_before] == [tuple(r) for r in rows_after]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# v26 — ai_backends table + email_accounts.style_learning_backend_id FK
# ---------------------------------------------------------------------------

def test_v26_creates_ai_backends_table_and_account_fk():
    """Fresh ``init_db`` should land the v26 schema: ``ai_backends``
    table, selector index, and the new FK column on email_accounts."""
    from email_triage.web.db import init_db

    conn = init_db(":memory:")
    try:
        # ai_backends table + columns.
        cols = {
            row["name"]: row
            for row in conn.execute(
                "PRAGMA table_info(ai_backends)"
            ).fetchall()
        }
        for expected in (
            "id", "name", "type", "endpoint", "api_key_secret_ref",
            "model", "baa_certified", "baa_expires_at", "enabled",
            "created_by", "created_at",
        ):
            assert expected in cols, f"missing column {expected!r}"

        # Selector index exists.
        idx_names = {
            row["name"] for row in conn.execute(
                "PRAGMA index_list(ai_backends)"
            ).fetchall()
        }
        assert "idx_ai_backends_selector" in idx_names

        # email_accounts.style_learning_backend_id column landed.
        acct_cols = {
            row["name"] for row in conn.execute(
                "PRAGMA table_info(email_accounts)"
            ).fetchall()
        }
        assert "style_learning_backend_id" in acct_cols

        # v26 recorded in bookkeeping.
        applied = applied_versions(conn)
        assert 26 in applied
        assert applied[26]["name"] == "create_ai_backends"
    finally:
        conn.close()


def test_v26_type_check_constraint_rejects_unknown_value():
    """The CHECK constraint on ``type`` must reject values outside the
    five-element allowlist."""
    from email_triage.web.db import init_db

    conn = init_db(":memory:")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ai_backends "
                "(name, type, endpoint, enabled) "
                "VALUES (?, ?, ?, 1)",
                ("BadBackend", "anthropic", "https://api.anthropic.com"),
            )
            conn.commit()
    finally:
        conn.close()


def test_v26_baa_certified_requires_expiration():
    """The CHECK constraint pinning ``baa_certified=1 → baa_expires_at
    NOT NULL`` must reject a half-set BAA row."""
    from email_triage.web.db import init_db

    conn = init_db(":memory:")
    try:
        # baa_certified=1 with NULL expiration must fail.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO ai_backends "
                "(name, type, endpoint, baa_certified, baa_expires_at, "
                "enabled) "
                "VALUES (?, ?, ?, ?, ?, 1)",
                ("Bad", "openai", "https://x", 1, None),
            )
            conn.commit()

        # baa_certified=1 with expiration must succeed.
        conn.execute(
            "INSERT INTO ai_backends "
            "(name, type, endpoint, baa_certified, baa_expires_at, "
            "enabled) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            ("OK", "openai", "https://x", 1, "2027-01-01"),
        )
        conn.commit()
        row = conn.execute(
            "SELECT baa_certified, baa_expires_at FROM ai_backends "
            "WHERE name='OK'"
        ).fetchone()
        assert row["baa_certified"] == 1
        assert row["baa_expires_at"] == "2027-01-01"

        # baa_certified=0 with NULL expiration is fine (non-BAA).
        conn.execute(
            "INSERT INTO ai_backends "
            "(name, type, endpoint, baa_certified, baa_expires_at, "
            "enabled) "
            "VALUES (?, ?, ?, ?, ?, 1)",
            ("Local", "ollama", "http://localhost:11434", 0, None),
        )
        conn.commit()
    finally:
        conn.close()


def test_v26_idempotent_re_run_on_existing_db():
    """Re-running v26 on a DB that already has the schema is a no-op.

    Belt-and-braces test even though the framework caches by checksum
    — protects against accidental edits to v26 body that would
    otherwise trip the checksum guard."""
    from email_triage.web.db import init_db
    from email_triage.web.migrations import run_migrations

    conn = init_db(":memory:")
    try:
        # Already-applied v26 from init_db. Running again is a no-op.
        applied = run_migrations(conn)
        assert applied == []  # everything already in place

        # Schema still intact.
        cols = {
            row["name"] for row in conn.execute(
                "PRAGMA table_info(ai_backends)"
            ).fetchall()
        }
        assert "baa_expires_at" in cols
    finally:
        conn.close()


def test_v26_upgrade_path_from_v25(monkeypatch):
    """Simulate upgrading a v25 install to v26: drop v26 from the
    registry, init_db (lands at v25), restore v26, run_migrations,
    schema should now include the v26 surface."""
    from email_triage.web import migrations as mig_mod
    from email_triage.web.migrations import run_migrations

    # Snapshot v26 entry and remove it from the registry.
    v26_entries = [m for m in mig_mod.MIGRATIONS if m.version == 26]
    assert len(v26_entries) == 1, "v26 must be registered before this test"
    v26 = v26_entries[0]
    mig_mod.MIGRATIONS[:] = [
        m for m in mig_mod.MIGRATIONS if m.version != 26
    ]
    try:
        from email_triage.web.db import init_db
        conn = init_db(":memory:")
        try:
            # Pre-v26 state: table doesn't exist, column doesn't exist.
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='ai_backends'"
            )
            assert cur.fetchall() == []
            acct_cols = {
                row["name"] for row in conn.execute(
                    "PRAGMA table_info(email_accounts)"
                ).fetchall()
            }
            assert "style_learning_backend_id" not in acct_cols

            # Restore v26 and re-run the framework.
            mig_mod.MIGRATIONS.append(v26)
            applied = run_migrations(conn)
            assert applied == [26]

            # Schema now reflects v26.
            cur = conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name='ai_backends'"
            )
            assert cur.fetchall() != []
            acct_cols = {
                row["name"] for row in conn.execute(
                    "PRAGMA table_info(email_accounts)"
                ).fetchall()
            }
            assert "style_learning_backend_id" in acct_cols
        finally:
            conn.close()
    finally:
        # Restore registry state for downstream tests.
        if not any(m.version == 26 for m in mig_mod.MIGRATIONS):
            mig_mod.MIGRATIONS.append(v26)
