"""v0.1.2 baseline — delegates to legacy init_db() for the full schema.

Per `internal documentation` §4 Phase 1 deliverable 4:
the baseline IS the post-`init_db()` schema (= `_ALL_DDL` +
`_apply_migrations` ALTERs + 38 numbered migrations in
`web/migrations.py` + ensure_* helpers). Rather than reflect that
state into synthetic DDL strings (SA reflection mishandles
expression-DEFAULTs and INTEGER PRIMARY KEY inlining), the baseline
upgrade() calls the legacy ``init_db()`` directly against the
Alembic-managed DB path.

After v0.1.2 cuts to the public mirror, the legacy ``init_db()`` may
be retired; until then, this delegation is the simplest possible
"baseline = whatever ships today" pattern.

Subsequent post-v0.1.2 schema changes go in new Alembic revisions
on top of this baseline.

Revision ID: 0001_baseline_v0_1_2
Revises:
Create Date: (set when migration first runs)
"""
from __future__ import annotations

from alembic import op


revision = "0001_baseline_v0_1_2"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Replay the v0.1.2 baseline schema via the legacy init_db().

    init_db() owns the COMPLETE schema-build sequence (_ALL_DDL +
    _apply_migrations + ensure_categories_user_id_migration +
    scrub_queue_summary_from_routes + run_migrations). Replicating that
    chain partially is the bug builder-2 flagged — so call init_db()
    directly against the Alembic-managed DB path. It's idempotent
    (CREATE ... IF NOT EXISTS + version-tracked migrations), opens its
    own connection, and commits + closes before returning. Under WAL
    the Alembic bind + init_db's connection coexist; Alembic writes
    alembic_version after upgrade() returns.
    """
    from email_triage.web.db import init_db

    bind = op.get_bind()
    db_path = bind.engine.url.database
    if not db_path:
        raise RuntimeError(
            "Alembic baseline requires a file-backed DB; got an empty URL."
        )

    init_conn = init_db(db_path)
    try:
        init_conn.commit()
    except Exception:
        pass
    finally:
        try:
            init_conn.close()
        except Exception:
            pass


def downgrade() -> None:
    """Baseline downgrade is a NO-OP — rolling back the baseline would
    mean dropping every table, which has no operational meaning under
    the forward-only migration model.
    """
    pass
