"""Embedding-reindex background job (#180 C)."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace
from pathlib import Path

import pytest

from email_triage.jobs.embedding_reindex import (
    needs_reindex, enqueue_embedding_reindex, run_embedding_reindex_job,
)
from email_triage.web.db import (
    create_email_account, get_triage_job,
)


def test_needs_reindex_dimension_change_triggers():
    """Different dim → reindex needed."""
    assert needs_reindex(
        current_backend={"backend_type": "sentence_transformers",
                         "model": "all-MiniLM-L6-v2",
                         "dimension": 384},
        target_backend={"backend_type": "sentence_transformers",
                        "model": "nomic-embed-text",
                        "dimension": 768},
    ) is True


def test_needs_reindex_same_backend_no_trigger():
    """Same backend + model + dim → no reindex needed."""
    assert needs_reindex(
        current_backend={"backend_type": "sentence_transformers",
                         "model": "all-MiniLM-L6-v2", "dimension": 384},
        target_backend={"backend_type": "sentence_transformers",
                        "model": "all-MiniLM-L6-v2", "dimension": 384},
    ) is False


def test_needs_reindex_missing_fields_no_false_positive():
    """None values shouldn't trigger reindex (only positive mismatch)."""
    assert needs_reindex(
        current_backend={},
        target_backend={"backend_type": "sentence_transformers"},
    ) is False


def test_enqueue_embedding_reindex_creates_job(test_db: sqlite3.Connection):
    """enqueue_embedding_reindex writes a triage_jobs row with the
    correct kind discriminator."""
    # Need a real account for the FK
    acct_id = create_email_account(
        test_db, user_id=1, name="x@example.com",
        provider_type="imap", config={"host": "imap.example.com"},
    )
    job_id = enqueue_embedding_reindex(
        test_db, account_id=acct_id, actor_user_id=1,
    )
    job = get_triage_job(test_db, job_id)
    assert job is not None
    assert job["kind"] == "embedding_reindex"
    assert job["account_id"] == acct_id
    assert job["status"] == "queued"


@pytest.mark.asyncio
async def test_run_reindex_refuses_when_runtime_not_ready(
    test_db: sqlite3.Connection, monkeypatch,
):
    """If is_runtime_ready() is False → job finishes 'failed' with
    explanatory error_text."""
    acct_id = create_email_account(
        test_db, user_id=1, name="x@example.com",
        provider_type="imap", config={"host": "imap.example.com"},
    )
    job_id = enqueue_embedding_reindex(
        test_db, account_id=acct_id, actor_user_id=1,
    )

    monkeypatch.setattr(
        "email_triage.jobs.embedding_reindex.is_runtime_ready",
        lambda: False,
    )

    fake_app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=None,
    ))
    # Mark as 'running' (claim_next_queued_triage_job normally does this)
    test_db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?",
        (job_id,),
    )
    test_db.commit()

    job_row = get_triage_job(test_db, job_id)
    await run_embedding_reindex_job(fake_app, test_db, job_row)

    after = get_triage_job(test_db, job_id)
    assert after["status"] == "failed"
    assert "not installed" in (after["error_text"] or "")


@pytest.mark.asyncio
async def test_run_reindex_hipaa_account_trivially_done(
    test_db: sqlite3.Connection, monkeypatch,
):
    """HIPAA account → status='done' (no rows by construction)."""
    acct_id = create_email_account(
        test_db, user_id=1, name="hipaa@example.com",
        provider_type="imap", config={"host": "imap.example.com"},
        hipaa=True,
    )
    job_id = enqueue_embedding_reindex(
        test_db, account_id=acct_id, actor_user_id=1,
    )

    monkeypatch.setattr(
        "email_triage.jobs.embedding_reindex.is_runtime_ready",
        lambda: True,
    )

    class _StubBackend:
        backend_type = "sentence_transformers"
        async def embed_text(self, text):
            return [0.1] * 384

    fake_app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=_StubBackend(),
        embedding_model="all-MiniLM-L6-v2",
    ))
    test_db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?",
        (job_id,),
    )
    test_db.commit()

    job_row = get_triage_job(test_db, job_id)
    await run_embedding_reindex_job(fake_app, test_db, job_row)

    after = get_triage_job(test_db, job_id)
    assert after["status"] == "done"
