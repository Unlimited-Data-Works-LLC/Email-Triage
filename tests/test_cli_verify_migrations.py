"""/N-85 — `version-check --verify-migrations` catches an edited applied
migration BEFORE the deploy swaps the image.

The 2026-06-11 the deploy host deploy break (N-85): the A10 SSOT sweep edited the
executable source of two already-applied migration bodies, so `run_migrations`'
boot-time checksum tamper-guard refused to start — but only AT BOOT, post-swap,
because `deploy.sh`'s plaintext-only init_db smoke + `--db` version-check are
SKIPPED on encrypted installs ("F6"). This pin covers the testable core of the
encryption-aware replacement: open a COPY of the live DB through the boot
migration path so the checksum break surfaces as a non-zero exit, non-
destructively, with NO live container needed.

Coverage note (DA 2026-06-11): these run on the PLAINTEXT path
(``encrypted=False``) — the checksum re-verify they exercise lives in
``run_migrations``, which ``init_db`` and ``init_db_encrypted`` both reach via
``_bootstrap_schema`` IDENTICALLY (only the opener differs), so the plaintext
test proves the N-85 CATCH. The ENCRYPTED opener itself (needs sqlcipher3 + the
master key, absent in CI) is validated end-to-end against the live the deploy host
encrypted DB by the deploy's own ``version-check --verify-migrations`` smoke and
the 2026-06-11 pre-deploy dry-run (VERIFY_OK rc=0).
"""

from __future__ import annotations
from _db_tracking import track

import sqlite3
from pathlib import Path

from email_triage.cli import (
    _VERIFY_MIGRATIONS_FAILED,
    _VERIFY_MIGRATIONS_INFRA,
    _verify_migrations_on_copy,
)
from email_triage.web.db import init_db


def _fresh_db(tmp_path: Path) -> Path:
    db = tmp_path / "live.db"
    conn = track(init_db(str(db)))
    conn.close()
    return db


def test_clean_db_verifies_ok(tmp_path):
    """A DB whose recorded checksums match the migration source migrates the
    copy cleanly → exit 0."""
    db = _fresh_db(tmp_path)
    rc, msg = _verify_migrations_on_copy(db, encrypted=False, master_key=None)
    assert rc == 0, msg


def test_tampered_applied_migration_is_caught(tmp_path):
    """The N-85 class: a recorded checksum that no longer matches its migration
    body (as if an already-applied migration was edited after shipping) → the
    boot migration path REFUSES the DB → the verify exit code aborts the deploy."""
    db = _fresh_db(tmp_path)
    conn = sqlite3.connect(str(db))
    # Corrupt the recorded checksum of the FIRST applied migration — exactly
    # what an edit-after-ship does to the live-DB↔source relationship.
    conn.execute(
        "UPDATE schema_migrations SET checksum = 'deadbeefdeadbeef' "
        "WHERE version = (SELECT MIN(version) FROM schema_migrations)"
    )
    conn.commit()
    conn.close()

    rc, msg = _verify_migrations_on_copy(db, encrypted=False, master_key=None)
    assert rc == _VERIFY_MIGRATIONS_FAILED, (
        f"the checksum tamper-guard must fire pre-swap; got rc={rc} msg={msg!r}"
    )
    assert "REFUSE" in msg


def test_verify_is_non_destructive(tmp_path):
    """The live DB file is byte-identical after a verify — it only ever migrates
    a throwaway copy."""
    db = _fresh_db(tmp_path)
    before = db.read_bytes()
    _verify_migrations_on_copy(db, encrypted=False, master_key=None)
    assert db.read_bytes() == before, "verify-migrations mutated the live DB"


def test_missing_db_is_infra_not_a_false_failure(tmp_path):
    """A copy failure (DB absent) returns the INFRA code, not the FAILED code —
    so deploy.sh degrades to the boot+rollback net instead of falsely aborting
    a good deploy."""
    rc, _msg = _verify_migrations_on_copy(
        tmp_path / "does-not-exist.db", encrypted=False, master_key=None,
    )
    assert rc == _VERIFY_MIGRATIONS_INFRA
    assert rc != _VERIFY_MIGRATIONS_FAILED
