"""Embedding-reindex background job."""

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
        provider_type="imap", config={"host": "imap.example.invalid"},
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
        provider_type="imap", config={"host": "imap.example.invalid"},
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
        provider_type="imap", config={"host": "imap.example.invalid"},
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


# ---------------------------------------------------------------------------
#  reliability gates — lock fairness + high-error-rate threshold
# ---------------------------------------------------------------------------


def test_inter_batch_sleep_is_nonzero():
    """ lock-fairness: the inter-batch yield MUST be > 0 so a multi-account
    reindex (sustained heavy SQLCipher writes) lets concurrent live-triage
    audit writers acquire the write lock between heavy lock-holds (2026-05-31
    lock-storm class). A regression to 0.0 re-opens that starvation window."""
    from email_triage.jobs import embedding_reindex as _er
    assert _er.INTER_BATCH_SLEEP_SECS > 0


def _seed_rows(conn: sqlite3.Connection, account_id: int, n: int, *, model: str):
    """Seed n sent_mail_index rows at ``model`` with non-empty bodies so the
    reindex attempts (not skips) every one."""
    for i in range(n):
        conn.execute(
            "INSERT INTO sent_mail_index (account_id, message_id, sent_at, "
            "subject, body_excerpt, embedding_model, indexed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (account_id, f"m{i}", "2026-06-13T00:00:00+00:00",
             f"subject {i}", f"body excerpt {i}", model, "2026-06-13T00:00:00+00:00"),
        )
    conn.commit()


@pytest.mark.asyncio
async def test_run_reindex_high_error_rate_fails_not_done(
    test_db: sqlite3.Connection, monkeypatch,
):
    """: a reindex where a HIGH fraction of attempted rows errors finishes
    'failed', NOT 'done' — silent partial-embedding of PHI-derived vectors must
    not pass as success (the read path would silently return degraded recall)."""
    acct_id = create_email_account(
        test_db, user_id=1, name="x@example.com",
        provider_type="imap", config={"host": "imap.example.invalid"},
    )
    _seed_rows(test_db, acct_id, 6, model="OLD-MODEL")
    job_id = enqueue_embedding_reindex(test_db, account_id=acct_id, actor_user_id=1)
    monkeypatch.setattr(
        "email_triage.jobs.embedding_reindex.is_runtime_ready", lambda: True,
    )

    calls = {"n": 0}

    class _FlakyBackend:
        backend_type = "sentence_transformers"
        async def embed_text(self, text):
            calls["n"] += 1
            if calls["n"] % 3 != 0:          # ~2/3 of rows error
                raise RuntimeError("embed boom")
            return [0.1] * 384

    fake_app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=_FlakyBackend(), embedding_model="NEW-MODEL",
    ))
    test_db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?", (job_id,),
    )
    test_db.commit()
    await run_embedding_reindex_job(fake_app, test_db, get_triage_job(test_db, job_id))

    after = get_triage_job(test_db, job_id)
    assert after["status"] == "failed", after["status"]
    assert "threshold" in (after["error_text"] or "").lower()


@pytest.mark.asyncio
async def test_run_reindex_low_error_rate_stays_done(
    test_db: sqlite3.Connection, monkeypatch,
):
    """A reindex with a SMALL error fraction (below the threshold) stays 'done'
    — a partial success is not a failure; only a HIGH error rate flips it."""
    acct_id = create_email_account(
        test_db, user_id=1, name="y@example.com",
        provider_type="imap", config={"host": "imap.example.invalid"},
    )
    _seed_rows(test_db, acct_id, 6, model="OLD-MODEL")
    job_id = enqueue_embedding_reindex(test_db, account_id=acct_id, actor_user_id=1)
    monkeypatch.setattr(
        "email_triage.jobs.embedding_reindex.is_runtime_ready", lambda: True,
    )

    calls = {"n": 0}

    class _MostlyOkBackend:
        backend_type = "sentence_transformers"
        async def embed_text(self, text):
            calls["n"] += 1
            if calls["n"] == 1:              # only the first row errors (1/6)
                raise RuntimeError("one-off boom")
            return [0.1] * 384

    fake_app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=_MostlyOkBackend(), embedding_model="NEW-MODEL",
    ))
    test_db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?", (job_id,),
    )
    test_db.commit()
    await run_embedding_reindex_job(fake_app, test_db, get_triage_job(test_db, job_id))

    after = get_triage_job(test_db, job_id)
    assert after["status"] == "done", after["status"]


@pytest.mark.asyncio
async def test_run_reindex_exactly_half_error_fails(
    test_db: sqlite3.Connection, monkeypatch,
):
    """Boundary: a clean 50/50 split is AT the threshold (gate is `>= 0.5`),
    so it finishes 'failed' — pins the boundary the two coarser tests bracket
    (devils-advocate  SME-panel should-fix)."""
    acct_id = create_email_account(
        test_db, user_id=1, name="z@example.com",
        provider_type="imap", config={"host": "imap.example.invalid"},
    )
    _seed_rows(test_db, acct_id, 4, model="OLD-MODEL")
    job_id = enqueue_embedding_reindex(test_db, account_id=acct_id, actor_user_id=1)
    monkeypatch.setattr(
        "email_triage.jobs.embedding_reindex.is_runtime_ready", lambda: True,
    )

    calls = {"n": 0}

    class _HalfBackend:
        backend_type = "sentence_transformers"
        async def embed_text(self, text):
            calls["n"] += 1
            if calls["n"] % 2 == 0:          # exactly 2 of 4 error → 0.5
                raise RuntimeError("half boom")
            return [0.1] * 384

    fake_app = SimpleNamespace(state=SimpleNamespace(
        embedding_backend=_HalfBackend(), embedding_model="NEW-MODEL",
    ))
    test_db.execute(
        "UPDATE triage_jobs SET status='running' WHERE job_id=?", (job_id,),
    )
    test_db.commit()
    await run_embedding_reindex_job(fake_app, test_db, get_triage_job(test_db, job_id))

    after = get_triage_job(test_db, job_id)
    assert after["status"] == "failed", after["status"]
