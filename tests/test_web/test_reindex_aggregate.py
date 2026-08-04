""" — cross-account aggregate embedding-reindex progress.

`aggregate_reindex_progress` rolls up the current reindex WAVE (one bar + per-
account rows) across the accounts a user manages; the `/triage/jobs/
reindex-progress` HTMX fragment renders it on the Bulk runs page while active
and empty otherwise (so the self-poll stops).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from email_triage.web.auth import SESSION_COOKIE_NAME
from email_triage.jobs.embedding_reindex import (
    aggregate_reindex_progress,
    enqueue_embedding_reindex,
)


def _seed_account(db, *, user_id: int, name: str) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "imap", json.dumps({"account": f"{name}@x"}), now, now),
    )
    db.commit()
    return cur.lastrowid


def _seed_reindex_job(
    db, *, account_id, status="running", processed=0, total=100,
    created_at=None, actor_user_id=None,
) -> str:
    job_id = enqueue_embedding_reindex(db, account_id, actor_user_id)
    sets = ["status = ?", "total_processed = ?", "cursor = ?"]
    vals: list = [status, processed, str(total)]
    if created_at is not None:
        sets.append("created_at = ?")
        vals.append(created_at)
    vals.append(job_id)
    db.execute(f"UPDATE triage_jobs SET {', '.join(sets)} WHERE job_id = ?", vals)
    db.commit()
    return job_id


class TestAggregateHelper:
    def test_no_jobs_inactive(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"], name="a1")
        agg = aggregate_reindex_progress(db, account_ids={aid})
        assert agg["active"] is False
        assert agg["rows"] == []

    def test_all_terminal_inactive(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"], name="a1")
        _seed_reindex_job(db, account_id=aid, status="done", processed=100, total=100)
        agg = aggregate_reindex_progress(db, account_ids={aid})
        # No non-terminal job -> no live wave.
        assert agg["active"] is False

    def test_single_running_job(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"], name="a1")
        _seed_reindex_job(db, account_id=aid, status="running", processed=30, total=120)
        agg = aggregate_reindex_progress(db, account_ids={aid})
        assert agg["active"] is True
        assert agg["accounts"] == 1
        assert agg["processed"] == 30
        assert agg["total"] == 120
        assert agg["pct"] == 25  # 30/120
        assert agg["rows"][0]["account_id"] == aid
        assert agg["rows"][0]["status"] == "running"

    def test_wave_rolls_up_done_plus_running(self, db, admin_user):
        a1 = _seed_account(db, user_id=admin_user["id"], name="a1")
        a2 = _seed_account(db, user_id=admin_user["id"], name="a2")
        a3 = _seed_account(db, user_id=admin_user["id"], name="a3")
        ts = "2026-06-13T10:00:00+00:00"
        _seed_reindex_job(db, account_id=a1, status="done", processed=100, total=100, created_at=ts)
        _seed_reindex_job(db, account_id=a2, status="running", processed=50, total=100, created_at=ts)
        _seed_reindex_job(db, account_id=a3, status="queued", processed=0, total=200, created_at=ts)
        agg = aggregate_reindex_progress(db, account_ids={a1, a2, a3})
        assert agg["active"] is True
        assert agg["accounts"] == 3
        assert agg["done"] == 1
        assert agg["processed"] == 150          # 100 + 50 + 0
        assert agg["total"] == 400              # 100 + 100 + 200
        assert agg["pct"] == 38                 # round(150/400*100)
        assert agg["status_counts"]["done"] == 1
        assert agg["status_counts"]["running"] == 1
        assert agg["status_counts"]["queued"] == 1

    def test_previous_wave_excluded(self, db, admin_user):
        """A fully-finished OLDER wave (earlier created_at) is NOT counted into
        the current wave."""
        a1 = _seed_account(db, user_id=admin_user["id"], name="a1")
        a2 = _seed_account(db, user_id=admin_user["id"], name="a2")
        # Old, done, from a previous wave.
        _seed_reindex_job(db, account_id=a1, status="done", processed=10, total=10,
                          created_at="2020-01-01T00:00:00+00:00")
        # Current wave: one running, recent.
        _seed_reindex_job(db, account_id=a2, status="running", processed=5, total=10,
                          created_at="2026-06-13T12:00:00+00:00")
        agg = aggregate_reindex_progress(db, account_ids={a1, a2})
        assert agg["active"] is True
        assert agg["accounts"] == 1             # only the current-wave account
        assert agg["total"] == 10
        assert agg["processed"] == 5

    def test_dedupe_keeps_newest_per_account(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"], name="a1")
        _seed_reindex_job(db, account_id=aid, status="failed", processed=10, total=100,
                          created_at="2026-06-13T10:00:00+00:00")
        _seed_reindex_job(db, account_id=aid, status="running", processed=40, total=100,
                          created_at="2026-06-13T11:00:00+00:00")  # newer
        agg = aggregate_reindex_progress(db, account_ids={aid})
        assert agg["accounts"] == 1
        assert agg["rows"][0]["status"] == "running"
        assert agg["rows"][0]["processed"] == 40

    def test_account_scope_excludes_other_accounts(self, db, admin_user):
        a1 = _seed_account(db, user_id=admin_user["id"], name="a1")
        a2 = _seed_account(db, user_id=admin_user["id"], name="a2")
        _seed_reindex_job(db, account_id=a1, status="running", processed=1, total=10)
        _seed_reindex_job(db, account_id=a2, status="running", processed=9, total=10)
        # Scope to a1 only — a2's job must not leak in.
        agg = aggregate_reindex_progress(db, account_ids={a1})
        assert agg["accounts"] == 1
        assert agg["rows"][0]["account_id"] == a1


class TestReindexAggregateRoute:
    def test_anon_blocked(self, client, db):
        resp = client.get("/triage/jobs/reindex-progress", follow_redirects=False)
        assert resp.status_code in (401, 303, 307)

    def test_active_wave_renders_fragment(self, client, db, admin_user, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        aid = _seed_account(db, user_id=admin_user["id"], name="Research")
        _seed_reindex_job(db, account_id=aid, status="running", processed=20, total=100)
        resp = client.get("/triage/jobs/reindex-progress", follow_redirects=False)
        assert resp.status_code == 200, resp.text
        body = resp.text
        assert "Updating the mail search index" in body
        assert "Research" in body                 # account by name
        assert "every 3s" in body                 # the self-poll keeps it live

    def test_no_wave_renders_empty(self, client, db, admin_user, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        aid = _seed_account(db, user_id=admin_user["id"], name="Research")
        _seed_reindex_job(db, account_id=aid, status="done", processed=100, total=100)
        resp = client.get("/triage/jobs/reindex-progress", follow_redirects=False)
        assert resp.status_code == 200
        # No active wave -> empty fragment, no self-poll trigger.
        assert "Updating the mail search index" not in resp.text
        assert "every 3s" not in resp.text

    def test_static_route_not_shadowed_by_job_id(
        self, client, db, admin_user, admin_cookies,
    ):
        """The static path resolves to the aggregate fragment, NOT the
        per-job page treating 'reindex-progress' as a job_id (which would
        404 'Job not found')."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/triage/jobs/reindex-progress", follow_redirects=False)
        assert resp.status_code == 200
        assert "Job not found" not in resp.text
