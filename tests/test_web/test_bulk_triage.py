"""Tests for whole-mailbox triage feature (#101).

Covers:
- triage_jobs schema + helpers
- bulk_triage_runner queue-drain lifecycle
- TokenBucket rate-limit timing
- /triage/jobs UI auth + cancel + per-account-singleton enforcement
- /config save persists + clamps the bulk knobs
"""

from __future__ import annotations

import asyncio
import time
import types

import pytest

from email_triage.web.db import (
    bump_triage_job_counters,
    claim_next_queued_triage_job,
    count_active_triage_jobs_for_account,
    count_processed_messages_in_job,
    create_triage_job,
    finish_triage_job,
    get_triage_job,
    is_message_processed_in_job,
    list_triage_jobs,
    record_processed_message,
    request_triage_job_cancel,
    requeue_orphaned_triage_jobs,
    update_triage_job_cursor,
)


# ---------------------------------------------------------------------------
# Helpers + fixtures
# ---------------------------------------------------------------------------

def _mk_account(db, *, owner_id: int, name: str = "acct1"):
    """Insert an active IMAP account row + return its id."""
    import json
    cursor = db.execute(
        "INSERT INTO email_accounts "
        "(name, provider_type, config_json, is_active, "
        " created_at, updated_at, user_id) "
        "VALUES (?, 'imap', ?, 1, ?, ?, ?)",
        (
            name,
            json.dumps({"username": "u@example.com", "host": "h", "port": 993}),
            "2026-01-01T00:00:00",
            "2026-01-01T00:00:00",
            owner_id,
        ),
    )
    db.commit()
    return cursor.lastrowid


# ---------------------------------------------------------------------------
# Schema + helper round-trip
# ---------------------------------------------------------------------------

class TestTriageJobsHelpers:
    def test_create_and_get(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="is:unread", rate_msg_per_min=30, concurrency=2,
        )
        assert job_id.startswith("tjob_")
        row = get_triage_job(db, job_id)
        assert row is not None
        assert row["status"] == "queued"
        assert row["account_id"] == acct_id
        assert row["query"] == "is:unread"
        assert row["rate_msg_per_min"] == 30
        assert row["concurrency"] == 2
        assert row["total_seen"] == 0
        assert row["started_at"] is None

    def test_list_filters_by_account_and_status(self, db, regular_user):
        a1 = _mk_account(db, owner_id=regular_user["id"], name="a1")
        a2 = _mk_account(db, owner_id=regular_user["id"], name="a2")
        j1 = create_triage_job(db, account_id=a1, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        j2 = create_triage_job(db, account_id=a2, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        finish_triage_job(db, j1, status="done")
        # By account
        assert {r["job_id"] for r in list_triage_jobs(db, account_id=a1)} == {j1}
        assert {r["job_id"] for r in list_triage_jobs(db, account_id=a2)} == {j2}
        # By status
        done_rows = list_triage_jobs(db, status="done")
        assert {r["job_id"] for r in done_rows} == {j1}

    def test_count_active_excludes_terminal(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        assert count_active_triage_jobs_for_account(db, acct_id) == 0
        j1 = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        assert count_active_triage_jobs_for_account(db, acct_id) == 1
        finish_triage_job(db, j1, status="done")
        assert count_active_triage_jobs_for_account(db, acct_id) == 0

    def test_claim_atomic_flip_then_empty(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        j1 = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        claimed = claim_next_queued_triage_job(db)
        assert claimed is not None
        assert claimed["job_id"] == j1
        assert claimed["status"] == "running"
        assert claimed["started_at"] is not None
        # Second claim returns None — only one queued job existed.
        assert claim_next_queued_triage_job(db) is None

    def test_bump_counters_accumulate(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        j1 = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        bump_triage_job_counters(db, j1, seen=10)
        bump_triage_job_counters(db, j1, processed=3, errors=1, skipped=2)
        bump_triage_job_counters(db, j1, processed=5)
        row = get_triage_job(db, j1)
        assert row["total_seen"] == 10
        assert row["total_processed"] == 8
        assert row["total_errors"] == 1
        assert row["total_skipped"] == 2
        assert row["last_progress_at"] is not None

    def test_finish_refuses_non_terminal(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        j1 = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        with pytest.raises(ValueError, match="terminal"):
            finish_triage_job(db, j1, status="running")
        with pytest.raises(ValueError):
            finish_triage_job(db, j1, status="queued")

    def test_request_cancel_flips_running(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        j1 = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                               query="x", rate_msg_per_min=1, concurrency=1)
        # queued -> cancelled
        assert request_triage_job_cancel(db, j1) is True
        assert get_triage_job(db, j1)["status"] == "cancelled"
        # second cancel on terminal row is a no-op (returns False)
        assert request_triage_job_cancel(db, j1) is False

    def test_requeue_orphans_only_running_no_ended(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        # Orphan: running, no ended_at.
        j_orphan = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                                     query="x", rate_msg_per_min=1, concurrency=1)
        db.execute(
            "UPDATE triage_jobs SET status='running' WHERE job_id=?",
            (j_orphan,),
        )
        # Done: should NOT requeue.
        j_done = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                                   query="x", rate_msg_per_min=1, concurrency=1)
        finish_triage_job(db, j_done, status="done")
        # Queued: should NOT requeue (already queued).
        j_queued = create_triage_job(db, account_id=acct_id, actor_user_id=1,
                                     query="x", rate_msg_per_min=1, concurrency=1)
        db.commit()
        n = requeue_orphaned_triage_jobs(db)
        assert n == 1
        assert get_triage_job(db, j_orphan)["status"] == "queued"
        assert get_triage_job(db, j_done)["status"] == "done"
        assert get_triage_job(db, j_queued)["status"] == "queued"


# ---------------------------------------------------------------------------
# Dedup: triage_job_messages table + helpers (#101 step 8)
# ---------------------------------------------------------------------------

class TestTriageJobMessagesDedup:
    def test_record_then_lookup(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        assert is_message_processed_in_job(db, job_id, "m1") is False
        record_processed_message(db, job_id, "m1", "p")
        assert is_message_processed_in_job(db, job_id, "m1") is True

    def test_record_is_idempotent(self, db, regular_user):
        """A second insert for the same (job_id, message_id) is a
        no-op — INSERT OR IGNORE on the composite PK. Resume after
        a partial-write crash must not double-count."""
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        record_processed_message(db, job_id, "m1", "p")
        record_processed_message(db, job_id, "m1", "p")
        record_processed_message(db, job_id, "m1", "p")
        counts = count_processed_messages_in_job(db, job_id)
        assert counts == {"p": 1, "s": 0, "e": 0}

    def test_dedup_isolated_per_job(self, db, regular_user):
        """Two jobs touching the same Gmail thread must not see
        each other's dedup state — each run is independent."""
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        j1 = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        j2 = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        record_processed_message(db, j1, "msg-A", "p")
        assert is_message_processed_in_job(db, j1, "msg-A") is True
        # Second job sees msg-A as fresh.
        assert is_message_processed_in_job(db, j2, "msg-A") is False

    def test_count_aggregates_by_status(self, db, regular_user):
        """count_processed_messages_in_job sums per-status —
        runner pre-bumps counters from this on resume."""
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        for i in range(7):
            record_processed_message(db, job_id, f"m{i}", "p")
        for i in range(2):
            record_processed_message(db, job_id, f"s{i}", "s")
        record_processed_message(db, job_id, "err1", "e")
        counts = count_processed_messages_in_job(db, job_id)
        assert counts == {"p": 7, "s": 2, "e": 1}

    def test_count_empty_job_returns_zeroes(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        assert count_processed_messages_in_job(db, job_id) == {
            "p": 0, "s": 0, "e": 0,
        }


# ---------------------------------------------------------------------------
# High-water-mark cursor (#101 step 9)
# ---------------------------------------------------------------------------

class TestTriageJobCursor:
    def test_update_cursor_persists(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        # Fresh row: cursor is NULL.
        assert get_triage_job(db, job_id).get("cursor") is None
        update_triage_job_cursor(db, job_id, "12345")
        row = get_triage_job(db, job_id)
        assert row["cursor"] == "12345"
        # last_progress_at gets bumped along with the cursor write.
        assert row["last_progress_at"] is not None

    def test_update_cursor_overwrites(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        update_triage_job_cursor(db, job_id, "100")
        update_triage_job_cursor(db, job_id, "200")
        update_triage_job_cursor(db, job_id, "300")
        assert get_triage_job(db, job_id)["cursor"] == "300"

    def test_update_cursor_none_clears(self, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        update_triage_job_cursor(db, job_id, "abc123")
        update_triage_job_cursor(db, job_id, None)
        assert get_triage_job(db, job_id)["cursor"] is None

    def test_default_search_iter_yields_cursor_none(self):
        """The base-class fallback for providers without paged
        support must yield (ids, None) so the runner's cursor
        persist is a no-op (None overwrites None)."""
        import asyncio
        from email_triage.providers.base import EmailProvider

        class _Stub(EmailProvider):
            @property
            def name(self): return "stub"
            async def search(self, query, limit=50):
                return ["m1", "m2", "m3"]
            async def fetch_message(self, message_id, *, headers_only=False, folder=None):
                raise NotImplementedError

        async def _drive():
            stub = _Stub()
            batches = []
            async for batch, cursor in stub.search_iter("q"):
                batches.append((batch, cursor))
            return batches

        result = asyncio.run(_drive())
        assert result == [(["m1", "m2", "m3"], None)]

    def test_imap_search_iter_cursor_clauses(self):
        """IMAP search_iter must splice ``UID <cursor+1>:*`` into the
        query when resume_cursor is set, so the SEARCH skips
        already-processed UIDs."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from email_triage.providers.imap import ImapProvider

        async def _drive():
            # Stub the provider's _connect + _search_in_current_mailbox
            # to capture the query string passed to SEARCH. We don't
            # need a real IMAP server for the unit-level cursor test.
            provider = ImapProvider.__new__(ImapProvider)
            provider._connect = AsyncMock(return_value=MagicMock())
            captured: list[str] = []

            async def _fake_search(client, q, limit, filter):
                captured.append(q)
                # Return three UIDs ascending after sort.
                return ["100", "200", "300"]

            provider._search_in_current_mailbox = _fake_search

            # Run with cursor=150 — search query should carry
            # "UID 151:*".
            batches = []
            async for batch, cursor in provider.search_iter(
                "UNSEEN", batch_size=10, resume_cursor="150",
            ):
                batches.append((batch, cursor))
            return captured, batches

        captured, batches = asyncio.run(_drive())
        assert any("UID 151:*" in q for q in captured), captured
        # Single batch (3 < batch_size=10), max UID = 300.
        assert batches == [(["100", "200", "300"], "300")]

    def test_imap_search_iter_no_cursor_skips_clause(self):
        """Fresh runs must not splice a UID range — keeps existing
        non-resume callers working."""
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        from email_triage.providers.imap import ImapProvider

        async def _drive():
            provider = ImapProvider.__new__(ImapProvider)
            provider._connect = AsyncMock(return_value=MagicMock())
            captured: list[str] = []

            async def _fake_search(client, q, limit, filter):
                captured.append(q)
                return ["1", "2", "3"]

            provider._search_in_current_mailbox = _fake_search
            async for _ in provider.search_iter(
                "UNSEEN", batch_size=10, resume_cursor=None,
            ):
                pass
            return captured

        captured = asyncio.run(_drive())
        assert all("UID " not in q for q in captured), captured


# ---------------------------------------------------------------------------
# TokenBucket rate-limit
# ---------------------------------------------------------------------------

class TestTokenBucket:
    def test_burst_then_rate(self):
        from email_triage.web.triage_runner_bulk import TokenBucket

        async def run():
            # 600/min = 10/sec, burst=2 → first 2 instant, next 3 over ~0.3 s.
            bucket = TokenBucket(rate_per_min=600, burst=2)
            t0 = time.monotonic()
            for _ in range(5):
                await bucket.acquire()
            return time.monotonic() - t0

        elapsed = asyncio.run(run())
        # 5 tokens at 10/sec with burst 2 = ~0.30 s. Generous bounds
        # for test-runner jitter.
        assert 0.20 < elapsed < 0.6, f"unexpected timing: {elapsed:.2f}"

    def test_parallel_acquire_does_not_speed_up(self):
        """Token bucket is single-source-of-truth — gather doesn't
        parallelise its cadence."""
        from email_triage.web.triage_runner_bulk import TokenBucket

        async def run():
            bucket = TokenBucket(rate_per_min=600, burst=2)
            t0 = time.monotonic()
            await asyncio.gather(*[bucket.acquire() for _ in range(5)])
            return time.monotonic() - t0

        elapsed = asyncio.run(run())
        assert 0.20 < elapsed < 0.6, f"unexpected timing: {elapsed:.2f}"

    def test_burst_5_allows_5_immediate_then_throttles(self):
        """#145.2 — operator-tunable burst depth. burst=5 must let
        five acquires fire immediately at any rate (the bucket starts
        full at burst capacity), then the 6th waits for the configured
        per-second cadence. Validates the burst knob is honoured."""
        from email_triage.web.triage_runner_bulk import TokenBucket

        async def run():
            bucket = TokenBucket(rate_per_min=60, burst=5)
            t0 = time.monotonic()
            for _ in range(5):
                await bucket.acquire()
            five_done = time.monotonic() - t0
            await bucket.acquire()  # 6th — must wait ~1 s at 60/min.
            six_done = time.monotonic() - t0
            return five_done, six_done

        five_done, six_done = asyncio.run(run())
        # First five fire essentially immediately.
        assert five_done < 0.1, (
            f"burst=5 should fire 5 immediately, took {five_done:.2f}s"
        )
        # Sixth waits ~1 s (60/min = 1/sec) for the next refill.
        assert six_done > 0.9, (
            f"6th acquire should have waited for refill, total {six_done:.2f}s"
        )


# ---------------------------------------------------------------------------
# Runner lifecycle
# ---------------------------------------------------------------------------

class TestBulkTriageRunner:
    def test_orphan_requeued_then_claimed_then_completed(self, db, regular_user):
        """End-to-end smoke: pre-flip a row to 'running' (orphan
        from a prior process), start the runner, verify it
        requeues + claims + completes via the placeholder body
        (which the lifecycle test relies on; the real body is
        exercised in higher-level integration tests).
        """
        from email_triage.web import triage_runner_bulk as bulk

        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="is:unread", rate_msg_per_min=1, concurrency=1,
        )
        # Orphan: running, no ended_at.
        db.execute("UPDATE triage_jobs SET status='running' WHERE job_id=?", (job_id,))
        db.commit()

        # Stub run_triage_all so the test doesn't need a real
        # provider/classifier/etc. The runner contract only
        # requires the body to write a terminal status; this stub
        # mirrors that contract.
        async def _fake_runner(app, conn, job):
            finish_triage_job(conn, job["job_id"], status="done")

        original = bulk.run_triage_all
        original_poll = bulk.POLL_INTERVAL_SECS
        bulk.run_triage_all = _fake_runner
        bulk.POLL_INTERVAL_SECS = 0.05
        app_obj = types.SimpleNamespace()
        app_obj.state = types.SimpleNamespace(db=db)
        try:
            async def _drive():
                task = asyncio.create_task(bulk.bulk_triage_runner(app_obj))
                # Give the loop time to: requeue → claim → fake-run → terminal.
                await asyncio.sleep(0.4)
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
            asyncio.run(_drive())
        finally:
            bulk.run_triage_all = original
            bulk.POLL_INTERVAL_SECS = original_poll

        final = get_triage_job(db, job_id)
        assert final["status"] == "done"

    def test_run_triage_all_calls_build_classifier_with_one_arg(self):
        """Regression: ``triage_runner_bulk.run_triage_all`` had a
        stale call site passing ``(config, secrets)`` to
        ``_build_classifier_from_config(config)`` — 2-args vs 1-arg
        signature mismatch. Surfaced as
        ``setup: TypeError: _build_classifier_from_config() takes 1
        positional argument but 2 were given`` on every bulk job at
        worker startup. Pin the arity here so a future refactor that
        adds a second positional arg trips a test before shipping.
        """
        import inspect
        from email_triage.web.routers.ui._shared import (
            _build_classifier_from_config,
        )
        from email_triage.web import triage_runner_bulk

        # Function arity: exactly one required parameter.
        sig = inspect.signature(_build_classifier_from_config)
        required = [
            p for p in sig.parameters.values()
            if p.default is inspect.Parameter.empty
            and p.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        assert len(required) == 1, (
            f"_build_classifier_from_config should take exactly one "
            f"required arg; signature is {sig}"
        )

        # Source-grep: ensure no call site in the bulk runner passes
        # a second positional arg. Brittle but catches the regression
        # shape directly.
        src = inspect.getsource(triage_runner_bulk)
        assert "_build_classifier_from_config(app.state.config, " not in src, (
            "triage_runner_bulk.py contains a 2-arg call to "
            "_build_classifier_from_config — would TypeError at "
            "worker startup."
        )


# ---------------------------------------------------------------------------
# /config — admin knobs persist + clamp
# ---------------------------------------------------------------------------

class TestBulkConfigKnobs:
    def test_admin_save_persists_rate_and_concurrency(
        self, client, admin_cookies,
    ):
        # Save with valid values.
        resp = client.post(
            "/config/save",
            data={
                "log_level": "INFO",
                "bulk_triage_rate_msg_per_min": "60",
                "bulk_triage_concurrency": "4",
            },
            cookies=admin_cookies,
        )
        # Either redirect or 200; just check it didn't 4xx.
        assert resp.status_code < 400
        # Reload /config and confirm rendered values.
        page = client.get("/config", cookies=admin_cookies)
        assert page.status_code == 200
        assert 'name="bulk_triage_rate_msg_per_min"' in page.text
        assert 'value="60"' in page.text
        assert 'value="4"' in page.text

    def test_clamp_concurrency_above_max(self, client, admin_cookies):
        # 99 should clamp to 8 (the documented max).
        resp = client.post(
            "/config/save",
            data={
                "log_level": "INFO",
                "bulk_triage_rate_msg_per_min": "30",
                "bulk_triage_concurrency": "99",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code < 400
        page = client.get("/config", cookies=admin_cookies)
        assert 'value="8"' in page.text  # clamped

    def test_clamp_rate_above_max(self, client, admin_cookies):
        resp = client.post(
            "/config/save",
            data={
                "log_level": "INFO",
                "bulk_triage_rate_msg_per_min": "999999",
                "bulk_triage_concurrency": "1",
            },
            cookies=admin_cookies,
        )
        assert resp.status_code < 400
        page = client.get("/config", cookies=admin_cookies)
        assert 'value="600"' in page.text  # clamped to ceiling


# ---------------------------------------------------------------------------
# /triage/jobs/* UI auth + behaviour
# ---------------------------------------------------------------------------

class TestTriageJobsUI:
    def test_progress_page_requires_login(self, client, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        resp = client.get(f"/triage/jobs/{job_id}",
                          follow_redirects=False)
        # No cookie → 303 to /login.
        assert resp.status_code == 303
        assert "/login" in resp.headers.get("location", "")

    def test_progress_404_unknown_job(self, client, user_cookies):
        resp = client.get("/triage/jobs/tjob_doesnotexist",
                          cookies=user_cookies,
                          follow_redirects=False)
        assert resp.status_code == 404

    def test_progress_renders_when_authorised(
        self, client, db, regular_user, user_cookies,
    ):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="is:unread", rate_msg_per_min=30, concurrency=1,
        )
        resp = client.get(f"/triage/jobs/{job_id}", cookies=user_cookies)
        assert resp.status_code == 200
        assert job_id in resp.text
        assert "is:unread" in resp.text

    def test_cancel_flips_status(
        self, client, db, regular_user, user_cookies,
    ):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        resp = client.post(f"/triage/jobs/{job_id}/cancel",
                           cookies=user_cookies,
                           follow_redirects=False)
        assert resp.status_code == 303
        assert get_triage_job(db, job_id)["status"] == "cancelled"

    def test_progress_fragment_polls_terminal_stops(
        self, client, db, regular_user, user_cookies,
    ):
        """Fragment for a terminal job omits hx-get attrs so the
        client-side polling stops without a final empty roundtrip."""
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        job_id = create_triage_job(
            db, account_id=acct_id, actor_user_id=regular_user["id"],
            query="x", rate_msg_per_min=1, concurrency=1,
        )
        finish_triage_job(db, job_id, status="done")
        resp = client.get(f"/triage/jobs/{job_id}/progress",
                          cookies=user_cookies)
        assert resp.status_code == 200
        assert "DONE" in resp.text
        # Terminal fragment should NOT carry hx-trigger=every
        assert "hx-trigger" not in resp.text


# ---------------------------------------------------------------------------
# /triage/preview — read-only smoke test of a query
# ---------------------------------------------------------------------------

class TestTriagePreview:
    @staticmethod
    def _stub_provider_search(monkeypatch, ids, headers):
        """Replace _create_provider_from_account so the route's
        provider.search + fetch_message return canned data without
        a real provider connection."""
        from unittest.mock import AsyncMock
        from email_triage.web.routers import ui as ui_mod

        class _StubProvider:
            async def search(self, query, limit=50):
                return list(ids)[:limit]
            async def fetch_message(self, message_id, *, headers_only=False, folder=None):
                from email_triage.engine.models import EmailMessage
                from datetime import datetime, timezone
                h = headers.get(message_id, {})
                return EmailMessage(
                    message_id=message_id,
                    provider="imap",
                    sender=h.get("sender", ""),
                    recipients=[],
                    subject=h.get("subject", ""),
                    body_text="",
                    date=h.get("date", datetime(2026, 5, 1, tzinfo=timezone.utc)),
                )
            async def close(self):
                pass

        monkeypatch.setattr(
            ui_mod, "_create_provider_from_account",
            lambda acct, secrets: _StubProvider(),
        )

    def test_preview_unauthenticated(self, client, db, regular_user):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        resp = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 401

    def test_preview_returns_table(
        self, client, db, regular_user, user_cookies, monkeypatch,
    ):
        from datetime import datetime, timezone
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        ids = ["m1", "m2", "m3"]
        headers = {
            "m1": {"sender": "alice@example.com", "subject": "Hi",
                   "date": datetime(2026, 5, 1, 9, 0, tzinfo=timezone.utc)},
            "m2": {"sender": "bob@example.com", "subject": "Status",
                   "date": datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)},
            "m3": {"sender": "carol@example.com", "subject": "Re: Status",
                   "date": datetime(2026, 5, 1, 11, 0, tzinfo=timezone.utc)},
        }
        self._stub_provider_search(monkeypatch, ids, headers)

        resp = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        assert "alice@example.com" in resp.text
        assert "Re: Status" in resp.text
        assert "Preview" in resp.text

    def test_preview_rate_limit_blocks_second(
        self, client, db, regular_user, user_cookies, monkeypatch,
    ):
        acct_id = _mk_account(db, owner_id=regular_user["id"])
        self._stub_provider_search(monkeypatch, ["m1"], {})

        resp1 = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            cookies=user_cookies,
        )
        assert resp1.status_code == 200
        # Second request within 10 s should hit cooldown.
        resp2 = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            cookies=user_cookies,
        )
        assert resp2.status_code == 200
        assert "cooling down" in resp2.text.lower()

    def test_preview_owner_hipaa_does_not_audit(
        self, client, db, regular_user, user_cookies, monkeypatch,
    ):
        """Owner running preview on their own HIPAA account is
        first-party access; no hipaa_access_event row."""
        acct_id = self._mk_hipaa_account(db, regular_user["id"])
        self._stub_provider_search(monkeypatch, ["m1"], {})

        resp = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            cookies=user_cookies,
        )
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'triage_preview'"
        ).fetchall()
        assert len(rows) == 0

    def test_preview_admin_on_user_hipaa_audits(
        self, client, db, admin_user, regular_user, admin_cookies, monkeypatch,
    ):
        """Admin previewing a non-self HIPAA account writes a
        hipaa_access_event row (event_type=triage_preview)."""
        acct_id = self._mk_hipaa_account(db, regular_user["id"])
        self._stub_provider_search(monkeypatch, ["m1"], {})

        resp = client.post(
            "/triage/preview",
            data={"account_id": acct_id, "search_preset": "unread", "query": ""},
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT * FROM hipaa_access_events "
            "WHERE operation = 'triage_preview'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["actor_user_id"] == admin_user["id"]
        assert rows[0]["account_id"] == acct_id

    @staticmethod
    def _mk_hipaa_account(db, owner_id: int):
        """Account with hipaa=True. Mirrors _mk_account but flags
        the per-account HIPAA bit on."""
        import json
        cursor = db.execute(
            "INSERT INTO email_accounts "
            "(name, provider_type, config_json, is_active, "
            " created_at, updated_at, user_id, hipaa) "
            "VALUES (?, 'imap', ?, 1, ?, ?, ?, 1)",
            (
                "hipaa-acct",
                json.dumps({"username": "u@example.com", "host": "h", "port": 993}),
                "2026-01-01T00:00:00",
                "2026-01-01T00:00:00",
                owner_id,
            ),
        )
        db.commit()
        return cursor.lastrowid
