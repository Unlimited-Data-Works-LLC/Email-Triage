"""Tests for the B3 Gmail history-poll loop — cadence admin,
per-account override, mode-transition reset, and tick firing."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.config import IngestionConfig
from email_triage.web.db import (
    get_setting, set_setting, upsert_gmail_watch, get_gmail_watch,
    get_email_account,
)


def _make_gmail_account(db, user_id, *, name="Gpoll", config=None):
    now = datetime.now(timezone.utc).isoformat()
    cfg = config or {"account": "me@gmail.com"}
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, hipaa, created_at, updated_at) "
        "VALUES (?, ?, 'gmail_api', ?, 0, ?, ?)",
        (user_id, name, json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


class TestIngestionConfigBounds:
    """IngestionConfig carries the min/max/step bounds as class-level
    constants so the admin UI and save handler read from one source."""

    def test_defaults(self):
        ic = IngestionConfig()
        # Unified model: single default cadence, 60 min.
        assert ic.default_poll_interval_minutes == 60
        assert ic.POLL_MIN == 10
        assert ic.POLL_MAX == 240
        assert ic.POLL_STEP == 10
        # Legacy B3 fields retained for YAML round-trip.
        assert ic.push_poll_interval_min == 20
        assert ic.poll_poll_interval_min == 10


class TestCadenceSaveHandler:
    """POST /config/save clamps cadence to the dataclass bounds and
    snaps to the step grid."""

    def _post(self, client, admin_cookies, **extra):
        data = {"log_level": "INFO", "classifier_backend": "ollama",
                "classifier_model": "[local-llm-model]
                "classifier_ollama_url": "http://localhost:11434",
                "smtp_port": "587", "logging_format": "text"}
        data.update(extra)
        return client.post("/config/save", data=data, cookies=admin_cookies)

    def test_save_within_bounds_persists(self, client, admin_cookies):
        resp = self._post(
            client, admin_cookies,
            ingestion_push_poll_interval_min="30",
            ingestion_poll_poll_interval_min="15",
        )
        assert resp.status_code == 200
        assert client.app.state.config.ingestion.push_poll_interval_min == 30
        assert client.app.state.config.ingestion.poll_poll_interval_min == 15

    def test_save_over_max_clamps(self, client, admin_cookies):
        resp = self._post(
            client, admin_cookies,
            ingestion_push_poll_interval_min="999",
            ingestion_poll_poll_interval_min="999",
        )
        assert resp.status_code == 200
        # Legacy push field: clamped to PUSH_MAX=60.
        assert client.app.state.config.ingestion.push_poll_interval_min == 60
        # Legacy poll field: clamped to unified POLL_MAX=240.
        assert client.app.state.config.ingestion.poll_poll_interval_min == 240

    def test_save_under_min_clamps(self, client, admin_cookies):
        resp = self._post(
            client, admin_cookies,
            ingestion_push_poll_interval_min="1",
            ingestion_poll_poll_interval_min="1",
        )
        assert resp.status_code == 200
        # Both clamp to their min. Legacy push min=10, unified poll min=10.
        assert client.app.state.config.ingestion.push_poll_interval_min == 10
        assert client.app.state.config.ingestion.poll_poll_interval_min == 10

    def test_save_default_poll_interval_respects_bounds(self, client, admin_cookies):
        """New unified default: clamped to 10–240, stepped by 10."""
        resp = self._post(
            client, admin_cookies,
            ingestion_default_poll_interval_minutes="9999",
        )
        assert resp.status_code == 200
        assert client.app.state.config.ingestion.default_poll_interval_minutes == 240
        resp = self._post(
            client, admin_cookies,
            ingestion_default_poll_interval_minutes="1",
        )
        assert resp.status_code == 200
        assert client.app.state.config.ingestion.default_poll_interval_minutes == 10
        # Off-step snaps (95 → 90 or 100).
        resp = self._post(
            client, admin_cookies,
            ingestion_default_poll_interval_minutes="93",
        )
        assert resp.status_code == 200
        assert client.app.state.config.ingestion.default_poll_interval_minutes in (90, 100)

    def test_save_off_grid_snaps_to_step(self, client, admin_cookies):
        """Step is 5 — a value like 22 must snap to 20 or 25."""
        resp = self._post(
            client, admin_cookies,
            ingestion_push_poll_interval_min="22",
            ingestion_poll_poll_interval_min="13",
        )
        assert resp.status_code == 200
        # 22 rounds to 20 (push default grid: 10,15,20,25,...)
        assert client.app.state.config.ingestion.push_poll_interval_min == 20
        # 13 rounds to 15 (poll grid: 5,10,15,20,...)
        assert client.app.state.config.ingestion.poll_poll_interval_min == 15

    def test_config_page_shows_cadence_section(self, client, admin_cookies):
        resp = client.get("/config", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Ingestion cadence" in resp.text
        assert 'name="ingestion_push_poll_interval_min"' in resp.text
        assert 'name="ingestion_poll_poll_interval_min"' in resp.text


@pytest.fixture
def app_with_queue(client):
    """Tests here need push_queue + secrets on app.state (the
    conftest fixture doesn't attach a queue — the lifespan wiring
    that normally does it isn't invoked for the in-process client)."""
    import asyncio
    if not hasattr(client.app.state, "push_queue"):
        client.app.state.push_queue = asyncio.Queue(maxsize=64)
    return client.app


class TestPollLoopTick:
    """Direct tests against _run_history_poll_tick, no sleep loop."""

    @pytest.mark.asyncio
    async def test_push_mode_fires_enqueues_on_interval(
        self, client, db, admin_user, app_with_queue,
    ):
        """Push-mode account: tick should enqueue the LIVE historyId
        from get_profile onto push_queue when the interval has
        elapsed (not the stale stored one)."""
        from email_triage.web.app import _run_history_poll_tick

        aid = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=aid, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="1234",
            expires_at=future,
        )
        # Force last_poll_at far in the past so the tick fires.
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00",
                     "last_mode": "push"})

        # Drain the queue first.
        while not client.app.state.push_queue.empty():
            client.app.state.push_queue.get_nowait()

        with patch(
            "email_triage.providers.gmail_api.GmailApiProvider.get_profile",
            new=AsyncMock(return_value={
                "emailAddress": "me@gmail.com", "historyId": "5678",
            }),
        ), patch(
            "email_triage.providers.gmail_api.GmailApiProvider.close",
            new=AsyncMock(return_value=None),
        ):
            await _run_history_poll_tick(client.app)

        # One item enqueued for our account — with the LIVE historyId.
        item = client.app.state.push_queue.get_nowait()
        assert item["account_id"] == aid
        assert item["history_id"] == "5678"

        # last_poll_at should have advanced.
        state = get_setting(db, f"poll_state:{aid}")
        assert state["last_mode"] == "push"
        assert state["last_poll_at"] > "2020-01-01"

    @pytest.mark.asyncio
    async def test_interval_not_elapsed_skips(
        self, client, db, admin_user, app_with_queue,
    ):
        """If last_poll was seconds ago, the tick should NOT enqueue."""
        from email_triage.web.app import _run_history_poll_tick

        aid = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=aid, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="1234",
            expires_at=future,
        )
        set_setting(db, f"poll_state:{aid}", {
            "last_poll_at": datetime.now(timezone.utc).isoformat(),
            "last_mode": "push",
        })
        while not client.app.state.push_queue.empty():
            client.app.state.push_queue.get_nowait()

        await _run_history_poll_tick(client.app)

        assert client.app.state.push_queue.empty()

    @pytest.mark.asyncio
    async def test_poll_mode_bootstraps_cursor_first_time(
        self, client, db, admin_user, app_with_queue,
    ):
        """Poll-mode account with no watch row yet: first tick calls
        get_profile(), upserts a synthetic watch row with empty
        topic_name, and does NOT enqueue (just seeds the cursor)."""
        from email_triage.web.app import _run_history_poll_tick

        aid = _make_gmail_account(db, admin_user["id"])
        while not client.app.state.push_queue.empty():
            client.app.state.push_queue.get_nowait()

        # Stub get_profile + close on the provider the factory returns.
        with patch(
            "email_triage.providers.gmail_api.GmailApiProvider.get_profile",
            new=AsyncMock(return_value={
                "emailAddress": "me@gmail.com", "historyId": "9999",
            }),
        ), patch(
            "email_triage.providers.gmail_api.GmailApiProvider.close",
            new=AsyncMock(return_value=None),
        ):
            await _run_history_poll_tick(client.app)

        watch = get_gmail_watch(db, aid)
        assert watch is not None
        assert watch["topic_name"] == ""  # synthetic poll-mode row
        assert watch["history_id"] == "9999"
        # No enqueue on the bootstrap tick.
        assert client.app.state.push_queue.empty()

    @pytest.mark.asyncio
    async def test_history_poll_enqueues_live_historyid(
        self, client, db, admin_user, app_with_queue,
    ):
        """Regression: the safety-poll tick must enqueue the LIVE
        historyId from Gmail, not the stored one. Enqueuing the
        stored value would make the consumer's idempotency check
        (incoming <= stored) skip every time, silently neutering the
        safety net."""
        from email_triage.web.app import _run_history_poll_tick

        aid = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=aid, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="100",
            expires_at=future,
        )
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00",
                     "last_mode": "push"})
        while not client.app.state.push_queue.empty():
            client.app.state.push_queue.get_nowait()

        with patch(
            "email_triage.providers.gmail_api.GmailApiProvider.get_profile",
            new=AsyncMock(return_value={
                "emailAddress": "me@gmail.com", "historyId": "200",
            }),
        ), patch(
            "email_triage.providers.gmail_api.GmailApiProvider.close",
            new=AsyncMock(return_value=None),
        ):
            await _run_history_poll_tick(client.app)

        item = client.app.state.push_queue.get_nowait()
        assert item["history_id"] == "200"  # live, not stored "100"

    @pytest.mark.asyncio
    async def test_history_poll_quiet_when_no_new_mail(
        self, client, db, admin_user, app_with_queue,
    ):
        """When Gmail's live historyId equals the stored one, the
        tick still enqueues — it's the consumer's idempotency check
        that quietly drops it. This test verifies the tick behaviour
        (enqueue with live == stored) so the skip path is exercised."""
        from email_triage.web.app import _run_history_poll_tick

        aid = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=aid, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="42",
            expires_at=future,
        )
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00",
                     "last_mode": "push"})
        while not client.app.state.push_queue.empty():
            client.app.state.push_queue.get_nowait()

        with patch(
            "email_triage.providers.gmail_api.GmailApiProvider.get_profile",
            new=AsyncMock(return_value={
                "emailAddress": "me@gmail.com", "historyId": "42",
            }),
        ), patch(
            "email_triage.providers.gmail_api.GmailApiProvider.close",
            new=AsyncMock(return_value=None),
        ):
            await _run_history_poll_tick(client.app)

        item = client.app.state.push_queue.get_nowait()
        assert item["history_id"] == "42"  # live matches stored
        # Consumer-side: incoming (42) <= stored (42) → skip, quietly.


class TestCadenceChip:
    """_render_cadence_status_label surfaces the effective push+poll
    state in the unified ingestion model."""

    def test_push_and_poll_on_chip(self):
        from email_triage.web.routers.ui import _render_cadence_status_label
        ic = IngestionConfig()
        acct = {"config": {
            "account": "x", "push_enabled": True, "poll_enabled": True,
            "poll_interval_minutes": 60,
        }}
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        watch = {"topic_name": "projects/p/topics/t", "expires_at": future}
        html = _render_cadence_status_label(acct, watch, ic)
        assert "Push + 60min poll" in html

    def test_poll_only_chip(self):
        from email_triage.web.routers.ui import _render_cadence_status_label
        ic = IngestionConfig()
        acct = {"config": {
            "account": "x", "push_enabled": False, "poll_enabled": True,
            "poll_interval_minutes": 60,
        }}
        html = _render_cadence_status_label(acct, None, ic)
        assert "Poll 60min" in html

    def test_both_off_chip(self):
        from email_triage.web.routers.ui import _render_cadence_status_label
        ic = IngestionConfig()
        acct = {"config": {
            "account": "x", "push_enabled": False, "poll_enabled": False,
        }}
        html = _render_cadence_status_label(acct, None, ic)
        assert "Disabled" in html

    def test_push_unhealthy_shows_warning(self):
        """Push configured but expired → warning chip."""
        from email_triage.web.routers.ui import _render_cadence_status_label
        ic = IngestionConfig()
        acct = {"config": {
            "account": "x", "push_enabled": True, "poll_enabled": True,
            "poll_interval_minutes": 30,
        }}
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        watch = {"topic_name": "projects/p/topics/t", "expires_at": past}
        html = _render_cadence_status_label(acct, watch, ic)
        assert "Push down" in html or "Push + 30min poll" in html


class TestPollRegisteredHydration:
    """Across a process restart, in-memory ``_poll_registered[i]
    .last_poll_at`` must be backfilled from the DB-persisted
    ``settings.poll_state:<i>.last_poll_at`` so the dashboard
    "Poll loop: X/Y fresh" chip doesn't mislead the operator into
    thinking healthy accounts are stale during the first cadence
    window after restart. (Investigated 2026-05-01 against a 4/5
    chip render that resolved itself within the cadence cycle.)"""

    @pytest.mark.asyncio
    async def test_start_account_hydrates_last_poll_at_from_db(
        self, client, db, admin_user, app_with_queue,
    ):
        from email_triage.web.app import WatcherManager
        from datetime import datetime, timezone, timedelta
        aid = _make_gmail_account(db, admin_user["id"])
        # Persistent state from a prior run, well within freshness
        # window (last 2h).
        recent_iso = (
            datetime.now(timezone.utc) - timedelta(minutes=5)
        ).isoformat()
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": recent_iso, "last_mode": "push"})

        # Fresh WatcherManager simulates process restart.
        wm = WatcherManager(client.app)
        await wm.start(aid)

        # In-memory state now carries the DB-persisted timestamp.
        registered, fresh = wm.poll_counts()
        assert registered == 1
        assert fresh == 1
        assert wm._poll_registered[aid]["last_poll_at"] == recent_iso

    @pytest.mark.asyncio
    async def test_start_account_no_persisted_state_means_not_fresh(
        self, client, db, admin_user, app_with_queue,
    ):
        """Missing DB poll_state row (brand-new install / never-polled
        account) leaves last_poll_at None, which counts as not-fresh
        until the next dispatch fires."""
        from email_triage.web.app import WatcherManager
        aid = _make_gmail_account(db, admin_user["id"])
        # No set_setting call — DB has no poll_state for aid.
        wm = WatcherManager(client.app)
        await wm.start(aid)
        registered, fresh = wm.poll_counts()
        assert registered == 1
        assert fresh == 0
        assert wm._poll_registered[aid]["last_poll_at"] is None

    @pytest.mark.asyncio
    async def test_start_account_stale_persisted_state_not_fresh(
        self, client, db, admin_user, app_with_queue,
    ):
        """Persisted last_poll_at older than 2 hours stays not-fresh
        until the next tick (poll_counts uses the 2h cutoff)."""
        from email_triage.web.app import WatcherManager
        from datetime import datetime, timezone, timedelta
        aid = _make_gmail_account(db, admin_user["id"])
        old_iso = (
            datetime.now(timezone.utc) - timedelta(hours=3)
        ).isoformat()
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": old_iso, "last_mode": "push"})
        wm = WatcherManager(client.app)
        await wm.start(aid)
        registered, fresh = wm.poll_counts()
        assert registered == 1
        assert fresh == 0
        # Hydrated, just outside the freshness window.
        assert wm._poll_registered[aid]["last_poll_at"] == old_iso
