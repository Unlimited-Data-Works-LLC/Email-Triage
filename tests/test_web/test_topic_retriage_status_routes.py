"""Smoke tests for the Topic Re-Triage live-status + cancel routes (,
2026-06-11). The retriage handler now returns a self-polling status fragment;
these pin the two endpoints it polls/posts: GET .../progress (owner-gated,
topic_backscan-pinned) and POST .../cancel (flips the job to cancelled via the
single-writer ``request_triage_job_cancel``)."""

from __future__ import annotations

import json

from email_triage.web.db import create_triage_job, get_triage_job

from .test_topic_digest_router import _make_account


def _seed_backscan_job(db, acct_id: int, uid: int) -> str:
    return create_triage_job(
        db, account_id=acct_id, actor_user_id=uid,
        query=json.dumps({"topic_id": 1, "window_days": 30}),
        rate_msg_per_min=600, concurrency=1, kind="topic_backscan",
    )


class TestTopicRetriageStatusRoutes:
    def test_progress_returns_status_fragment_for_owner(
        self, client, user_cookies, regular_user, db,
    ):
        acct = _make_account(db, regular_user["id"], "primary")
        jid = _seed_backscan_job(db, acct, regular_user["id"])
        resp = client.get(
            f"/profile/topic-digest/1/retriage/{jid}/progress",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert 'id="topic-retriage-status"' in resp.text
        assert "scanned" in resp.text

    def test_progress_shows_ceiling_banner_when_hit(
        self, client, user_cookies, regular_user, db,
    ):
        """ — when the back-scan hit the enumeration ceiling, the progress
        fragment surfaces the user-facing 'narrow the window / re-run' banner.
        Test the VIEW (the rendered fragment), not just the flag."""
        from email_triage.web.db import set_triage_job_ceiling_hit
        acct = _make_account(db, regular_user["id"], "primary")
        jid = _seed_backscan_job(db, acct, regular_user["id"])
        set_triage_job_ceiling_hit(db, jid)
        resp = client.get(
            f"/profile/topic-digest/1/retriage/{jid}/progress",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "more mail than a single scan can reach" in resp.text
        # the re-run advice is honest because  resumes into the tail
        assert "picks up where this scan left off" in resp.text

    def test_progress_no_ceiling_banner_when_not_hit(
        self, client, user_cookies, regular_user, db,
    ):
        """A normal back-scan (no ceiling) shows NO banner."""
        acct = _make_account(db, regular_user["id"], "primary")
        jid = _seed_backscan_job(db, acct, regular_user["id"])
        resp = client.get(
            f"/profile/topic-digest/1/retriage/{jid}/progress",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "more mail than a single scan can reach" not in resp.text

    def test_progress_404_for_non_backscan_job(
        self, client, user_cookies, regular_user, db,
    ):
        """The topic-scoped endpoint must not read an unrelated triage job
        (PD#9 — gate at the actuator; kind-pinned)."""
        acct = _make_account(db, regular_user["id"], "primary")
        jid = create_triage_job(
            db, account_id=acct, actor_user_id=regular_user["id"],
            query="{}", rate_msg_per_min=600, concurrency=1, kind="triage",
        )
        resp = client.get(
            f"/profile/topic-digest/1/retriage/{jid}/progress",
            cookies=user_cookies,
        )
        assert resp.status_code == 404

    def test_cancel_flips_job_to_cancelled(
        self, client, user_cookies, regular_user, db,
    ):
        acct = _make_account(db, regular_user["id"], "primary")
        jid = _seed_backscan_job(db, acct, regular_user["id"])
        resp = client.post(
            f"/profile/topic-digest/1/retriage/{jid}/cancel",
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert get_triage_job(db, jid)["status"] == "cancelled"

    def test_progress_404_for_other_topics_job(
        self, client, user_cookies, regular_user, db,
    ):
        """A job for topic 2 must NOT be readable via the topic-1 route — the
        install-wide  dedup makes cross-topic reachable for a user who owns
        both topics (PD#9 topic-scope gate)."""
        acct = _make_account(db, regular_user["id"], "primary")
        jid = create_triage_job(
            db, account_id=acct, actor_user_id=regular_user["id"],
            query=json.dumps({"topic_id": 2, "window_days": 30}),
            rate_msg_per_min=600, concurrency=1, kind="topic_backscan",
        )
        resp = client.get(
            f"/profile/topic-digest/1/retriage/{jid}/progress",
            cookies=user_cookies,
        )
        assert resp.status_code == 404
        resp2 = client.post(
            f"/profile/topic-digest/1/retriage/{jid}/cancel",
            cookies=user_cookies,
        )
        assert resp2.status_code == 404
        assert get_triage_job(db, jid)["status"] != "cancelled"
