"""Tests for the  embedding-model-change save handler.

POST /config/ai-backends/save with a CHANGED embedding model must:

* refuse the change unless ``embedding_reindex_confirm`` is set (so a
  non-JS / programmatic submit can't silently swap the model and zero
  out retrieval recall — the existing vectors keep the OLD
  ``embedding_stamp`` until re-embedded);
* on a confirmed change: update the in-memory config, write an
  ``embedding_model_change`` audit row (via the chain-safe
  ``record_auth_event`` path, not a direct insert), and auto-enqueue a
  background ``embedding_reindex`` triage_job for every ACTIVE account;
* leave a no-op save (same model) untouched — no audit, no jobs.

See AskUserQuestion 2026-06-06: operator chose confirm-gate +
auto-reindex.
"""

from __future__ import annotations

import email_triage.embedding_bits as embedding_bits
from email_triage.config import EmbeddingConfig
from email_triage.db.accounts import (
    create_email_account,
    set_account_active,
)


def _set_embedding(app, *, backend: str, model: str) -> None:
    """Seed the in-memory embedding config the handler reads/writes."""
    app.state.config.embedding = EmbeddingConfig(
        backend=backend, model_name=model,
    )


def _count_reindex_jobs(db) -> int:
    row = db.execute(
        "SELECT COUNT(*) AS n FROM triage_jobs "
        "WHERE kind = 'embedding_reindex'",
    ).fetchone()
    return row["n"] if hasattr(row, "keys") else row[0]


def _count_model_change_audit(db) -> int:
    row = db.execute(
        "SELECT COUNT(*) AS n FROM auth_events "
        "WHERE event_type = 'embedding_model_change'",
    ).fetchone()
    return row["n"] if hasattr(row, "keys") else row[0]


class TestEmbeddingModelChangeGate:
    def test_change_without_confirm_keeps_old_model(
        self, client, app, db, admin_cookies,
    ):
        _set_embedding(
            app, backend="sentence_transformers",
            model="all-MiniLM-L6-v2",
        )
        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "sentence_transformers",
                "embedding_model_name": "intfloat/multilingual-e5-base",
                # NO embedding_reindex_confirm
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        # Model left UNCHANGED — recall cannot break silently.
        assert app.state.config.embedding.model_name == "all-MiniLM-L6-v2"
        assert _count_reindex_jobs(db) == 0
        assert _count_model_change_audit(db) == 0

    def test_no_change_does_not_reindex(
        self, client, app, db, admin_cookies,
    ):
        _set_embedding(
            app, backend="sentence_transformers",
            model="all-MiniLM-L6-v2",
        )
        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "sentence_transformers",
                "embedding_model_name": "all-MiniLM-L6-v2",
                "embedding_reindex_confirm": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert app.state.config.embedding.model_name == "all-MiniLM-L6-v2"
        assert _count_reindex_jobs(db) == 0
        assert _count_model_change_audit(db) == 0


class TestEmbeddingModelChangeApplied:
    def test_confirmed_change_updates_audits_and_enqueues(
        self, client, app, db, admin_user, admin_cookies, monkeypatch,
    ):
        # No config YAML exists in the test env; neutralize the persist
        # step so the handler reaches the reindex block (YAML write is
        # covered by the config-save suite). The reindex/audit is
        # deliberately gated on a successful persist in production.
        monkeypatch.setattr(
            "email_triage.web.routers.ui._write_config_yaml",
            lambda config: None,
        )
        # Force the runtime-ready gate so the enqueue path runs.
        monkeypatch.setattr(
            embedding_bits, "is_runtime_ready", lambda: True,
        )
        _set_embedding(
            app, backend="sentence_transformers",
            model="all-MiniLM-L6-v2",
        )
        # One ACTIVE account + one INACTIVE account: only the active
        # one should get a reindex job.
        active_id = create_email_account(
            db, admin_user["id"], "Active", "imap", {},
        )
        set_account_active(db, active_id, True)
        inactive_id = create_email_account(
            db, admin_user["id"], "Inactive", "imap", {},
        )
        set_account_active(db, inactive_id, False)

        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "sentence_transformers",
                "embedding_model_name": "intfloat/multilingual-e5-base",
                "embedding_reindex_confirm": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        # Model applied.
        assert (
            app.state.config.embedding.model_name
            == "intfloat/multilingual-e5-base"
        )
        # Audit row written.
        assert _count_model_change_audit(db) == 1
        # Exactly one reindex job — for the ACTIVE account only.
        jobs = db.execute(
            "SELECT account_id FROM triage_jobs "
            "WHERE kind = 'embedding_reindex'",
        ).fetchall()
        acct_ids = {
            (r["account_id"] if hasattr(r, "keys") else r[0]) for r in jobs
        }
        assert acct_ids == {active_id}

    def test_confirmed_change_runtime_not_ready_audits_no_jobs(
        self, client, app, db, admin_user, admin_cookies, monkeypatch,
    ):
        # Runtime not installed: audit the swap but don't queue doomed
        # jobs.
        monkeypatch.setattr(
            "email_triage.web.routers.ui._write_config_yaml",
            lambda config: None,
        )
        monkeypatch.setattr(
            embedding_bits, "is_runtime_ready", lambda: False,
        )
        _set_embedding(
            app, backend="sentence_transformers",
            model="all-MiniLM-L6-v2",
        )
        aid = create_email_account(
            db, admin_user["id"], "Active", "imap", {},
        )
        set_account_active(db, aid, True)

        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "sentence_transformers",
                "embedding_model_name": "intfloat/multilingual-e5-base",
                "embedding_reindex_confirm": "1",
            },
            cookies=admin_cookies,
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert (
            app.state.config.embedding.model_name
            == "intfloat/multilingual-e5-base"
        )
        # Audited, but no jobs queued.
        assert _count_model_change_audit(db) == 1
        assert _count_reindex_jobs(db) == 0


class TestBackendTypeChangeAndIdempotency:
    """D-A2 + D-A3 (2am audit 2026-06-07)."""

    def test_backend_type_change_same_model_triggers_reindex(
        self, client, app, db, admin_user, admin_cookies, monkeypatch,
    ):
        """D-A2: switching the backend TYPE while keeping the SAME model
        name must trigger the confirm-gate + audit + reindex (it didn't
        before — only the model name was compared, so a same-name backend
        swap silently served stale cross-space vectors)."""
        monkeypatch.setattr(
            "email_triage.web.routers.ui._write_config_yaml",
            lambda config: None,
        )
        monkeypatch.setattr(embedding_bits, "is_runtime_ready", lambda: True)
        _set_embedding(
            app, backend="sentence_transformers", model="shared-model-name",
        )
        aid = create_email_account(db, admin_user["id"], "Active", "imap", {})
        set_account_active(db, aid, True)

        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "ollama",            # TYPE changed
                "embedding_model_name": "shared-model-name",  # name SAME
                "embedding_reindex_confirm": "1",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert app.state.config.embedding.backend == "ollama"
        assert _count_model_change_audit(db) == 1
        assert _count_reindex_jobs(db) == 1

    def test_backend_change_without_confirm_reverts_both(
        self, client, app, db, admin_cookies, monkeypatch,
    ):
        """D-A2: an unconfirmed backend-type change reverts BOTH backend
        and model (not just model) so retrieval can't break unnoticed."""
        monkeypatch.setattr(embedding_bits, "is_runtime_ready", lambda: True)
        _set_embedding(
            app, backend="sentence_transformers", model="shared-model-name",
        )
        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "ollama",
                "embedding_model_name": "shared-model-name",
                # NO confirm
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        assert app.state.config.embedding.backend == "sentence_transformers"
        assert app.state.config.embedding.model_name == "shared-model-name"
        assert _count_reindex_jobs(db) == 0
        assert _count_model_change_audit(db) == 0

    def test_reindex_enqueue_is_idempotent(
        self, client, app, db, admin_user, admin_cookies, monkeypatch,
    ):
        """D-A3: if a non-terminal embedding_reindex job already exists for
        an account, a fresh confirmed model change does NOT queue a second
        one for that account."""
        from email_triage.jobs.embedding_reindex import enqueue_embedding_reindex
        monkeypatch.setattr(
            "email_triage.web.routers.ui._write_config_yaml",
            lambda config: None,
        )
        monkeypatch.setattr(embedding_bits, "is_runtime_ready", lambda: True)
        _set_embedding(
            app, backend="sentence_transformers", model="all-MiniLM-L6-v2",
        )
        aid = create_email_account(db, admin_user["id"], "Active", "imap", {})
        set_account_active(db, aid, True)
        # Pre-seed a queued reindex job for this account.
        enqueue_embedding_reindex(db, account_id=aid, actor_user_id=admin_user["id"])

        resp = client.post(
            "/config/ai-backends/save",
            data={
                "embedding_backend": "sentence_transformers",
                "embedding_model_name": "intfloat/multilingual-e5-base",
                "embedding_reindex_confirm": "1",
            },
            cookies=admin_cookies, follow_redirects=False,
        )
        assert resp.status_code in (302, 303)
        # Still exactly ONE job for this account — the dedup skipped it.
        n = db.execute(
            "SELECT COUNT(*) AS n FROM triage_jobs "
            "WHERE kind = 'embedding_reindex' AND account_id = ?",
            (aid,),
        ).fetchone()
        assert (n["n"] if hasattr(n, "keys") else n[0]) == 1
