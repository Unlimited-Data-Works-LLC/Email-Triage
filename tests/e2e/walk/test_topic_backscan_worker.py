"""Walk — Topic back-scan JOB worker (run_topic_backscan_job) — Actions sketch .

Feature: ``email_triage.jobs.topic_backscan`` — the user-triggered back-scan
that matches HISTORICAL mail against ONE Topic and PERSISTS the matches as
``topic_hits`` (source='backscan'). ``enqueue_topic_backscan`` queues it (with
the  install-wide single-flight guard); ``run_topic_backscan_job`` drains it.
The fetch is thin + injectable, so the whole job runs with NO live IMAP / NO
live Ollama.

This walk drives the WORKER path end-to-end (distinct from Drive-5's route-level
retriage walks):

  * worker KICK + CHECKPOINT — enqueue, drain a synthetic 2-message batch with a
    mock classifier, assert 2 backscan hits land, the job finishes ``done``, and
    the per-batch counter heartbeat advanced ``total_seen`` (liveness, per
    feedback_long_running_check_in);
  * CANCEL — a job flipped to ``cancelled`` is observed at the batch boundary;
    the drain flushes + exits WITHOUT finishing ``done`` and writes no hits;
  * PHI-visibility gate on the progress fragment — the owner sees the status
    fragment (200), but a WRONG topic_id in the URL is fail-closed (404, PD#9 —
    the install-wide dedup makes a cross-topic read reachable for a user who
    owns both topics; the route gates at the actuator).

``db_call`` falls through to the shared-conn RLock path (no single-writer in the
lifespan-off e2e harness), so ``asyncio.run`` drives the drain directly.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tests.e2e.walk._helpers import sync_run_in_thread

pytestmark = pytest.mark.e2e


@pytest.fixture
def backscan_topic(e2e_server):
    """Seed ONE admin-owned Topic on the (non-HIPAA) research account."""
    from email_triage.actions.topic_configs import TopicConfig, upsert_topic

    conn = e2e_server["conn"]
    user_id = e2e_server["user_id"]
    research_id = e2e_server["research_account_id"]

    tid = upsert_topic(
        conn,
        TopicConfig(
            id=0, user_id=user_id, name="BackscanWorkerWalk",
            subjects=["walk-backscan"], selected_account_ids=[research_id],
            retention_days=90,
        ),
    ).id
    conn.commit()

    yield {"topic_id": tid, "account_id": research_id, "user_id": user_id}

    conn.execute("DELETE FROM topics WHERE id=?", (tid,))
    conn.commit()


class _MockClassifier:
    """Matches every message (returns one matched verdict) via the classify
    layer's topic-match seam — no live Ollama."""

    async def classify_with_topics_safe(
        self, message, categories, list_hints, *, topic_block, model=None,
    ):
        return SimpleNamespace(topic_verdicts=[
            {"topic_id": None, "matched": True, "confidence": 0.9,
             "reason_terms": ["walk-backscan"]},
        ])


def _msg(mid: str):
    return SimpleNamespace(
        headers={"Message-ID": mid, "Subject": "walk-backscan hit",
                 "From": "sender@lab.test"},
        folder="INBOX",
        sender="sender@lab.test",
        provider_uid="uid-" + mid,
        uidvalidity=1,
        body_keywords=["walk-backscan"],
    )


async def _two_message_fetcher():
    yield [_msg("<bk-1@test.local>"), _msg("<bk-2@test.local>")]


def _hit_count(conn, topic_id: int) -> int:
    return int(
        conn.execute(
            "SELECT COUNT(*) AS n FROM topic_hits "
            "WHERE topic_id=? AND source='backscan'",
            (topic_id,),
        ).fetchone()["n"]
    )


def test_backscan_worker_kick_inserts_hits_and_checkpoints(
    e2e_server, backscan_topic, monkeypatch,
):
    """PRIMARY — enqueue + drain: 2 synthetic messages both match, land as
    backscan hits, the job finishes ``done``, and the per-batch counter
    heartbeat advanced ``total_seen`` (the liveness checkpoint).

    Uses ``sync_run_in_thread`` (see _helpers.py) — the e2e session's outer
    loop makes both ``asyncio.run`` (sync test) and ``await`` (async test)
    unreliable; a private loop in a fresh thread is the robust shape.
    """
    from email_triage.jobs.topic_backscan import (
        enqueue_topic_backscan, run_topic_backscan_job,
    )
    from email_triage.web.db import get_triage_job

    conn = e2e_server["conn"]
    app = e2e_server["app"]
    tid = backscan_topic["topic_id"]

    monkeypatch.setattr(app.state, "classifier", _MockClassifier(), raising=False)

    job_id = enqueue_topic_backscan(
        conn, topic_id=tid, account_id=backscan_topic["account_id"],
        actor_user_id=backscan_topic["user_id"], window_days=30,
    )
    assert job_id, "enqueue returned None — a topic_backscan was unexpectedly in flight"

    job_row = get_triage_job(conn, job_id)
    sync_run_in_thread(
        run_topic_backscan_job(
            app, conn, job_row, fetcher_batches=_two_message_fetcher(),
        )
    )

    assert _hit_count(conn, tid) == 2, "both matched messages should persist as backscan hits"
    finished = get_triage_job(conn, job_id)
    assert finished["status"] == "done", finished["status"]
    # Checkpoint heartbeat — the per-batch counter bump advanced total_seen.
    assert int(finished["total_seen"]) >= 2, (
        f"total_seen did not advance (got {finished['total_seen']}) — the "
        "liveness checkpoint bump did not fire."
    )


def test_backscan_worker_observes_cancellation(
    e2e_server, backscan_topic, monkeypatch,
):
    """CANCEL — a job flipped to ``cancelled`` is observed at the first batch
    boundary; the drain exits WITHOUT finishing ``done`` and writes no hits."""
    from email_triage.jobs.topic_backscan import (
        enqueue_topic_backscan, run_topic_backscan_job,
    )
    from email_triage.web.db import get_triage_job

    conn = e2e_server["conn"]
    app = e2e_server["app"]
    tid = backscan_topic["topic_id"]

    monkeypatch.setattr(app.state, "classifier", _MockClassifier(), raising=False)

    job_id = enqueue_topic_backscan(
        conn, topic_id=tid, account_id=backscan_topic["account_id"],
        actor_user_id=backscan_topic["user_id"], window_days=30,
    )
    assert job_id, "enqueue returned None — a topic_backscan was unexpectedly in flight"

    # Flip to cancelled BEFORE the drain runs — the batch-boundary check catches it.
    conn.execute(
        "UPDATE triage_jobs SET status='cancelled' WHERE job_id=?", (job_id,)
    )
    conn.commit()

    job_row = get_triage_job(conn, job_id)
    sync_run_in_thread(
        run_topic_backscan_job(
            app, conn, job_row, fetcher_batches=_two_message_fetcher(),
        )
    )

    assert _hit_count(conn, tid) == 0, "a cancelled scan must not persist hits"
    after = get_triage_job(conn, job_id)
    assert after["status"] == "cancelled", (
        f"cancelled scan must NOT be flipped to done (status={after['status']})"
    )


def test_retriage_progress_fragment_owner_renders(
    authed_page, base_url, e2e_server, backscan_topic,
):
    """PHI-visibility gate (positive) — the owner GETs the live status fragment
    for their own topic's job (200)."""
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan

    conn = e2e_server["conn"]
    tid = backscan_topic["topic_id"]
    job_id = enqueue_topic_backscan(
        conn, topic_id=tid, account_id=backscan_topic["account_id"],
        actor_user_id=backscan_topic["user_id"], window_days=30,
    )
    if not job_id:
        pytest.xfail("a topic_backscan was already in flight; cannot enqueue a fresh one")

    authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    resp = authed_page.request.get(
        f"{base_url}/profile/topic-digest/{tid}/retriage/{job_id}/progress"
    )
    assert resp.status == 200, (
        f"owner progress poll returned {resp.status}; expected the rendered "
        f"status fragment. body={resp.text()[:200]!r}"
    )
    assert (resp.text() or "").strip(), "status fragment rendered empty"


def test_retriage_progress_fragment_wrong_topic_refuses(
    authed_page, base_url, e2e_server, backscan_topic,
):
    """PD#9 — a WRONG topic_id in the URL (with a real job_id) is fail-closed:
    a topic-scoped route must not read another topic's scan even for a user who
    owns both. Route returns 404 (not-found), never the fragment."""
    from email_triage.jobs.topic_backscan import enqueue_topic_backscan

    conn = e2e_server["conn"]
    tid = backscan_topic["topic_id"]
    job_id = enqueue_topic_backscan(
        conn, topic_id=tid, account_id=backscan_topic["account_id"],
        actor_user_id=backscan_topic["user_id"], window_days=30,
    )
    if not job_id:
        pytest.xfail("a topic_backscan was already in flight; cannot enqueue a fresh one")

    wrong_topic_id = tid + 100_000  # a topic id that is NOT the job's topic
    authed_page.goto(f"{base_url}/profile?tab=topic-digest")
    resp = authed_page.request.get(
        f"{base_url}/profile/topic-digest/{wrong_topic_id}/retriage/{job_id}/progress"
    )
    assert resp.status in (403, 404), (
        f"cross-topic progress read returned {resp.status}; PD#9 topic-scope "
        "gate must fail closed (404/403), never leak the fragment."
    )
