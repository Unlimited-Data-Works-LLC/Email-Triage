"""Alembic env.py — wires migrations through the app's SA Core engine.

Per `internal documentation` §4 Phase 1: Alembic
uses the SAME `create_engine_for_app(...)` factory the runtime app
uses, so migrations execute against the SQLCipher-encrypted file via
the `creator=` callable. The DATABASE_URL env-var pattern still
applies — Alembic reads `EMAIL_TRIAGE_DATABASE_URL` (or falls back to
`config.persistence.db_path` from `cfg`) and the engine factory does
the rest.

ORM is NOT used. ``target_metadata`` is ``None`` because we are not
auto-generating from SQLAlchemy declarative models — every migration
under ``alembic/versions/`` is hand-authored with ``op.execute()``
on raw DDL (matches the project's qmark-retained, hand-tuned SQL
discipline per the build plan).
"""

from __future__ import annotations

import logging
import os
from logging.config import fileConfig

from alembic import context

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# Hand-authored migrations only — no declarative-model autogen.
target_metadata = None


def _resolve_db_path() -> str:
    """Pick the DB path the same way the running app does."""
    env_url = os.environ.get("EMAIL_TRIAGE_DATABASE_URL")
    if env_url:
        # Strip the SA URL prefix if present; we feed the raw path to
        # `create_engine_for_app` which wraps via creator=.
        for prefix in ("sqlite:///", "sqlite://"):
            if env_url.startswith(prefix):
                return env_url[len(prefix):] or ":memory:"
        return env_url

    try:
        from email_triage.config import load_config

        cfg = load_config()
        return cfg.persistence.db_path
    except Exception:
        logger.warning(
            "Alembic could not load app config; falling back to :memory:"
        )
        return ":memory:"


def _build_engine():
    """Return the same SA Core engine the running app uses."""
    from email_triage.db._engine import create_engine_for_app

    db_path = _resolve_db_path()

    # Encryption posture inherits from app config. For migration runs
    # against an unencrypted local sandbox (the dev workflow), allow
    # `EMAIL_TRIAGE_ALEMBIC_PLAIN=1` to skip the master-key requirement.
    plain = os.environ.get("EMAIL_TRIAGE_ALEMBIC_PLAIN") == "1"
    if plain:
        return create_engine_for_app(db_path, encrypted=False)

    try:
        from email_triage.secrets import DbSecrets

        secrets = DbSecrets.from_config()
        master_key = secrets.master_key_str()
    except Exception as exc:
        raise RuntimeError(
            "Alembic could not load the DbSecrets master key. Either set "
            "EMAIL_TRIAGE_ALEMBIC_PLAIN=1 for a local dev sandbox run "
            "OR ensure the secret backend is reachable."
        ) from exc

    return create_engine_for_app(db_path, encrypted=True, master_key=master_key)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode — emits SQL to stdout."""
    url = _resolve_db_path()
    context.configure(
        url=f"sqlite:///{url}",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode against the live engine."""
    engine = _build_engine()
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
