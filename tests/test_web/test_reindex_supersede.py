""" (N-91a) — pin the reindex target + supersede a stale in-flight job.

The old auto-enqueue dedupe SKIPPED an account that already had a non-terminal
reindex job. So a model change WHILE a reindex was running left the account
stranded at the start-time stamp (the running job kept its old target; nothing
re-triggered it). The fix pins the intended target into the job payload and,
on a model change, SUPERSEDES (cancels) an in-flight job whose pinned target is
stale, enqueuing a fresh pinned job — the worker's cancel-check stops the old
one. Both the model-change fan-out and the manual reindex route through the one
``supersede_or_enqueue_reindex`` funnel.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from email_triage.jobs.embedding_reindex import (
    _job_pinned_target,
    enqueue_embedding_reindex,
    supersede_or_enqueue_reindex,
)

T_B = {"backend_type": "ollama", "model": "e5-B"}
T_C = {"backend_type": "ollama", "model": "e5-C"}


def _seed_account(db, *, user_id, name="a1"):
    now = datetime.now(timezone.utc).isoformat()
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, name, "imap", json.dumps({"account": f"{name}@x"}), now, now),
    )
    db.commit()
    return cur.lastrowid


def _reindex_jobs(db, account_id):
    rows = db.execute(
        "SELECT job_id, status, query FROM triage_jobs "
        "WHERE account_id=? AND kind='embedding_reindex' ORDER BY created_at",
        (account_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _set_status(db, job_id, status):
    db.execute("UPDATE triage_jobs SET status=? WHERE job_id=?", (status, job_id))
    db.commit()


class TestEnqueuePinsTarget:
    def test_target_pinned_in_payload(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"])
        enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)
        payload = json.loads(_reindex_jobs(db, aid)[0]["query"])
        assert payload["target"] == {"backend_type": "ollama", "model": "e5-B"}

    def test_no_target_is_back_compatible(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"])
        enqueue_embedding_reindex(db, aid, admin_user["id"])
        payload = json.loads(_reindex_jobs(db, aid)[0]["query"])
        assert "target" not in payload


class TestPinnedTargetParse:
    def test_extracts_target(self):
        row = {"query": json.dumps({"target": {"backend_type": "ollama", "model": "m"}})}
        assert _job_pinned_target(row) == {"backend_type": "ollama", "model": "m"}

    def test_legacy_unpinned_is_empty(self):
        assert _job_pinned_target({"query": json.dumps({"account_id": 1})}) == {}

    def test_bad_json_is_empty(self):
        assert _job_pinned_target({"query": "not json"}) == {}
        assert _job_pinned_target({"query": None}) == {}


class TestSupersedeOrEnqueue:
    def test_no_existing_enqueues(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"])
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_B,
        )
        assert out == "enqueued"
        jobs = _reindex_jobs(db, aid)
        assert len(jobs) == 1
        assert json.loads(jobs[0]["query"])["target"]["model"] == "e5-B"

    def test_queued_in_flight_skips_self_corrects(self, db, admin_user):
        """A QUEUED in-flight job is left alone even on a DIFFERENT target — it
        reads the live model when it starts, so it self-corrects (the D-A3
        idempotency this preserves)."""
        aid = _seed_account(db, user_id=admin_user["id"])
        enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)  # queued
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_C,
        )
        assert out == "skipped"
        assert len(_reindex_jobs(db, aid)) == 1  # no duplicate; queued one stays

    def test_running_same_target_skips(self, db, admin_user):
        """A RUNNING job already targeting the new model is left alone."""
        aid = _seed_account(db, user_id=admin_user["id"])
        jid = enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)
        _set_status(db, jid, "running")
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_B,
        )
        assert out == "skipped"
        assert len(_reindex_jobs(db, aid)) == 1

    def test_different_target_supersedes(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"])
        jid = enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)
        _set_status(db, jid, "running")
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_C,
        )
        assert out == "superseded"
        jobs = {j["job_id"]: j for j in _reindex_jobs(db, aid)}
        assert jobs[jid]["status"] == "cancelled"          # old one stopped
        fresh = [j for j in jobs.values() if j["job_id"] != jid]
        assert len(fresh) == 1
        assert json.loads(fresh[0]["query"])["target"]["model"] == "e5-C"
        assert fresh[0]["status"] == "queued"

    def test_legacy_unpinned_in_flight_is_superseded(self, db, admin_user):
        """An old job with no pinned target (unknown) is treated as stale on a
        model change — we can't prove it targets the new model."""
        aid = _seed_account(db, user_id=admin_user["id"])
        jid = enqueue_embedding_reindex(db, aid, admin_user["id"])  # no target
        _set_status(db, jid, "running")
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_C,
        )
        assert out == "superseded"
        jobs = {j["job_id"]: j for j in _reindex_jobs(db, aid)}
        assert jobs[jid]["status"] == "cancelled"

    def test_terminal_job_does_not_block(self, db, admin_user):
        aid = _seed_account(db, user_id=admin_user["id"])
        jid = enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)
        _set_status(db, jid, "done")  # terminal — not in-flight
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_C,
        )
        assert out == "enqueued"
        assert len(_reindex_jobs(db, aid)) == 2

    def test_n91a_mid_run_model_change(self, db, admin_user):
        """The documented N-91a: model A->B job is RUNNING, model changes B->C.
        The running B job is superseded (cancelled) and a fresh C job enqueued —
        the account is NOT stranded at B."""
        aid = _seed_account(db, user_id=admin_user["id"])
        jid_b = enqueue_embedding_reindex(db, aid, admin_user["id"], target=T_B)
        _set_status(db, jid_b, "running")
        out = supersede_or_enqueue_reindex(
            db, account_id=aid, actor_user_id=admin_user["id"], target=T_C,
        )
        assert out == "superseded"
        jobs = {j["job_id"]: j for j in _reindex_jobs(db, aid)}
        assert jobs[jid_b]["status"] == "cancelled"
        fresh = [j for j in jobs.values() if j["job_id"] != jid_b]
        assert len(fresh) == 1
        assert fresh[0]["status"] == "queued"
        assert json.loads(fresh[0]["query"])["target"]["model"] == "e5-C"
