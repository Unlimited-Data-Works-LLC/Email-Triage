"""Regression tests for the unified push + poll ingestion model.

Every account gets three independent knobs — ``push_enabled``,
``poll_enabled``, and ``poll_interval_minutes`` (default 60, range
10–240, step 10). IMAP and Gmail converge on the same shape; Office 365
is a placeholder until Graph subscriptions land.

These tests cover:
  * defaults for fresh accounts
  * back-compat migration from legacy ``watch:{id}`` / ``gmail_watches``
  * save-handler clamping + step snapping
  * the unified poll loop's per-provider dispatch
  * IMAP ``poll_once`` behaviour (cheap no-op vs new-mail fetch)
  * watcher bounce when push/poll flags or cadence change
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME, create_session_token
from email_triage.web.db import (
    apply_ingestion_back_compat,
    clamp_poll_interval_minutes,
    get_email_account,
    get_setting,
    set_setting,
    upsert_gmail_watch,
)


TEST_SECRET = "test-session-secret-for-signing"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_imap_account(db, user_id: int, config: dict | None = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cfg = config if config is not None else {
        "host": "mail.test.com", "port": 993,
        "username": "u", "use_ssl": True, "mailbox": "INBOX",
    }
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, 'imap', ?, 1, ?, ?)",
        (user_id, "Imap", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


def _make_gmail_account(db, user_id: int, config: dict | None = None) -> int:
    now = datetime.now(timezone.utc).isoformat()
    cfg = config if config is not None else {"account": "me@gmail.com"}
    cur = db.execute(
        "INSERT INTO email_accounts "
        "(user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, 'gmail_api', ?, 1, ?, ?)",
        (user_id, "Gmail", json.dumps(cfg), now, now),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# 1. Defaults on read
# ---------------------------------------------------------------------------

class TestDefaults:
    """New accounts read with push_enabled/poll_enabled/poll_interval_minutes
    materialised by the DB back-compat shim."""

    def test_new_account_defaults_to_push_and_poll_enabled_60min(
        self, db, admin_user,
    ):
        acct_id = _make_imap_account(db, admin_user["id"], config={
            "host": "m", "username": "u", "mailboxes": ["INBOX"],
        })
        acct = get_email_account(db, acct_id)
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is True
        assert acct["config"]["poll_interval_minutes"] == 60

    def test_gmail_account_defaults(self, db, admin_user):
        acct_id = _make_gmail_account(db, admin_user["id"])
        acct = get_email_account(db, acct_id)
        # No gmail_watches row yet → push_enabled defaults to True for
        # fresh accounts so the Start-watch button lights up by default.
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is True
        assert acct["config"]["poll_interval_minutes"] == 60


# ---------------------------------------------------------------------------
# 2. Back-compat migration
# ---------------------------------------------------------------------------

class TestBackCompat:
    """Legacy accounts with ``watch:{id}`` settings or existing
    gmail_watches rows migrate to the new shape on read without DB
    changes — the shim is read-side only."""

    def test_legacy_imap_with_watch_true_migrates_to_push_and_poll(
        self, db, admin_user,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        set_setting(db, f"watch:{acct_id}", {"enabled": True})
        acct = get_email_account(db, acct_id)
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is True
        assert acct["config"]["poll_interval_minutes"] == 60

    def test_legacy_imap_with_watch_false_migrates_to_poll_only(
        self, db, admin_user,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        set_setting(db, f"watch:{acct_id}", {"enabled": False})
        acct = get_email_account(db, acct_id)
        # Alex's decision: previously-dormant accounts come back as
        # poll-only. Operators opt out explicitly via the edit form.
        assert acct["config"]["push_enabled"] is False
        assert acct["config"]["poll_enabled"] is True
        assert acct["config"]["poll_interval_minutes"] == 60

    def test_legacy_imap_without_watch_setting_defaults_to_both_enabled(
        self, db, admin_user,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        # No watch:{id} setting recorded at all.
        acct = get_email_account(db, acct_id)
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is True

    def test_legacy_gmail_with_active_watch_row_migrates_to_push_on(
        self, db, admin_user,
    ):
        acct_id = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=acct_id, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="1",
            expires_at=future,
        )
        acct = get_email_account(db, acct_id)
        assert acct["config"]["push_enabled"] is True
        assert acct["config"]["poll_enabled"] is True

    def test_legacy_gmail_with_synthetic_poll_watch_row_is_push_off(
        self, db, admin_user,
    ):
        """B3 bootstrap rows have empty topic_name + epoch expires_at —
        they're not "push on". Back-compat treats them as push_off."""
        acct_id = _make_gmail_account(db, admin_user["id"])
        upsert_gmail_watch(
            db, account_id=acct_id, email_address="me@gmail.com",
            topic_name="",  # synthetic poll-mode row
            history_id="42",
            expires_at="1970-01-01T00:00:00+00:00",
        )
        acct = get_email_account(db, acct_id)
        assert acct["config"]["push_enabled"] is False
        assert acct["config"]["poll_enabled"] is True


# ---------------------------------------------------------------------------
# 3. Clamp + step-snap
# ---------------------------------------------------------------------------

class TestClampAndSnap:
    def test_poll_interval_clamped_to_10_240_range(self):
        assert clamp_poll_interval_minutes(0) == 10
        assert clamp_poll_interval_minutes(5) == 10
        assert clamp_poll_interval_minutes(9999) == 240

    def test_poll_interval_snapped_to_step_10(self):
        # 27 snaps to 30, 23 snaps to 20, 15 snaps to either 10 or 20.
        assert clamp_poll_interval_minutes(27) == 30
        assert clamp_poll_interval_minutes(23) == 20
        # Exact-step values stay put.
        assert clamp_poll_interval_minutes(60) == 60
        assert clamp_poll_interval_minutes(120) == 120

    def test_back_compat_honours_legacy_override(self, db, admin_user):
        """An existing B3 ``poll_interval_override`` carries forward
        into the new ``poll_interval_minutes`` field."""
        acct_id = _make_gmail_account(
            db, admin_user["id"],
            config={"account": "x", "poll_interval_override": 45},
        )
        acct = get_email_account(db, acct_id)
        # 45 snaps to 50 (step 10 from 10).
        assert acct["config"]["poll_interval_minutes"] in (40, 50)


# ---------------------------------------------------------------------------
# 4. Unified poll loop dispatch
# ---------------------------------------------------------------------------

class TestUnifiedPollLoop:
    @pytest.mark.asyncio
    async def test_unified_poll_skips_accounts_with_poll_disabled(
        self, client, db, admin_user,
    ):
        from email_triage.web.app import _run_unified_poll_tick
        import asyncio
        if not hasattr(client.app.state, "push_queue"):
            client.app.state.push_queue = asyncio.Queue(maxsize=16)

        aid = _make_gmail_account(db, admin_user["id"])
        # Turn poll off explicitly + set an ancient last_poll.
        from email_triage.web.db import update_email_account_config
        update_email_account_config(db, aid, {
            "account": "me@gmail.com",
            "push_enabled": True, "poll_enabled": False,
            "poll_interval_minutes": 60,
        })
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00"})

        with patch(
            "email_triage.providers.gmail_api.GmailApiProvider.get_profile",
            new=AsyncMock(return_value={"historyId": "1"}),
        ):
            await _run_unified_poll_tick(client.app)

        # Nothing enqueued — poll_enabled=False short-circuited.
        assert client.app.state.push_queue.empty()

    @pytest.mark.asyncio
    async def test_unified_poll_dispatches_gmail_via_existing_path(
        self, client, db, admin_user,
    ):
        from email_triage.web.app import _run_unified_poll_tick
        import asyncio
        if not hasattr(client.app.state, "push_queue"):
            client.app.state.push_queue = asyncio.Queue(maxsize=16)

        aid = _make_gmail_account(db, admin_user["id"])
        future = (datetime.now(timezone.utc) + timedelta(days=6)).isoformat()
        upsert_gmail_watch(
            db, account_id=aid, email_address="me@gmail.com",
            topic_name="projects/p/topics/t", history_id="100",
            expires_at=future,
        )
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00"})
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
            await _run_unified_poll_tick(client.app)

        item = client.app.state.push_queue.get_nowait()
        assert item["account_id"] == aid
        assert item["history_id"] == "200"  # live, not stored

    @pytest.mark.asyncio
    async def test_unified_poll_dispatches_imap_provider(
        self, client, db, admin_user,
    ):
        """IMAP account hitting the poll loop invokes provider.poll_once
        with the stored HWM. We stub the provider factory to sidestep
        the aioimaplib optional-dep requirement."""
        from email_triage.web.app import _run_unified_poll_tick

        aid = _make_imap_account(db, admin_user["id"], config={
            "host": "m", "username": "u", "mailboxes": ["INBOX"],
        })
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00"})
        from email_triage.web.db import set_mailbox_hwm
        set_mailbox_hwm(db, aid, "INBOX", {"uid": 100, "updated_at": "x"})

        fake_provider = MagicMock()
        fake_provider.poll_once = AsyncMock(return_value=[])
        fake_provider.close = AsyncMock(return_value=None)
        fake_provider.get_latest_uid = AsyncMock(return_value=0)

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            await _run_unified_poll_tick(client.app)

        assert fake_provider.poll_once.await_count == 1
        args = fake_provider.poll_once.await_args
        assert args.args[0] == "INBOX"
        assert args.args[1] == 100

    @pytest.mark.asyncio
    async def test_unified_poll_o365_is_noop_without_crash(
        self, client, db, admin_user,
    ):
        from email_triage.web.app import _run_unified_poll_tick

        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts "
            "(user_id, name, provider_type, config_json, is_active, "
            " created_at, updated_at) VALUES (?, ?, 'office365', ?, 1, ?, ?)",
            (admin_user["id"], "O365", json.dumps({
                "client_id": "cid", "tenant_id": "common",
            }), now, now),
        )
        db.commit()
        aid = cur.lastrowid
        set_setting(db, f"poll_state:{aid}",
                    {"last_poll_at": "2020-01-01T00:00:00+00:00"})

        # Should not raise.
        await _run_unified_poll_tick(client.app)

        # last_poll_at advanced, proving we ticked without crashing.
        state = get_setting(db, f"poll_state:{aid}")
        assert state["last_poll_at"] > "2020-01-01"


# ---------------------------------------------------------------------------
# 5. IMAP poll_once
# ---------------------------------------------------------------------------

class TestImapPollOnce:
    """Direct tests against ``ImapProvider.poll_once``. The aioimaplib
    client is mocked."""

    def _make_provider_with_client(self, client_mock):
        import sys as _sys
        _mock_aioimaplib = MagicMock()
        _mock_aioimaplib.IMAP4_SSL = MagicMock
        _mock_aioimaplib.IMAP4 = MagicMock
        _sys.modules["aioimaplib"] = _mock_aioimaplib
        import email_triage.providers.imap as imap_mod
        imap_mod.HAS_AIOIMAPLIB = True
        p = imap_mod.ImapProvider(
            host="m", username="u", password="p", mailbox="INBOX",
        )
        p._client = client_mock
        return p

    @pytest.mark.asyncio
    async def test_poll_once_empty_result_when_no_new_messages(self):
        client = MagicMock()
        client.select = AsyncMock(return_value=("OK", [b""]))
        client.search = AsyncMock(return_value=("OK", [b""]))
        p = self._make_provider_with_client(client)
        result = await p.poll_once("INBOX", since_uid=1000)
        assert result == []
        # Plain SEARCH was invoked (NOT uid("search", ...) — aioimaplib
        # 2.0 blocks UID+SEARCH with "command UID only possible with
        # COPY, FETCH, EXPUNGE (w/UIDPLUS) or STORE (was SEARCH)").
        call = client.search.await_args
        assert "UID 1001:*" in " ".join(str(a) for a in call.args)

    @pytest.mark.asyncio
    async def test_poll_once_seeds_from_zero_returns_empty(self):
        """since_uid=0 means fresh HWM — return [] and let the caller
        seed the HWM from get_latest_uid. Prevents the poll from
        dumping the entire backlog."""
        client = MagicMock()
        p = self._make_provider_with_client(client)
        result = await p.poll_once("INBOX", since_uid=0)
        assert result == []
        # No IMAP call was even issued.
        client.select.assert_not_called() if hasattr(
            client.select, "assert_not_called",
        ) else None

    @pytest.mark.asyncio
    async def test_poll_once_returns_new_messages_since_hwm(self):
        """SEARCH returns seq numbers; FETCH maps to UIDs; each is
        parsed into an EmailMessage."""
        from email_triage.engine.models import EmailMessage
        client = MagicMock()
        client.select = AsyncMock(return_value=("OK", [b""]))
        # SEARCH returns sequence numbers "5 6".
        client.search = AsyncMock(return_value=("OK", [b"5 6"]))
        # FETCH (UID) maps sequence numbers to UIDs 101 and 102.
        client.fetch = AsyncMock(return_value=(
            "OK",
            [b"5 FETCH (UID 101)", b"6 FETCH (UID 102)"],
        ))
        p = self._make_provider_with_client(client)

        fake_msg = EmailMessage(
            message_id="101", provider="imap",
            sender="a@b", recipients=["c@d"], subject="s",
            body_text="b", date=datetime.now(timezone.utc),
            labels=[], attachments=[],
        )
        with patch.object(
            p, "fetch_message",
            new=AsyncMock(return_value=fake_msg),
        ):
            messages = await p.poll_once("INBOX", since_uid=100)
        # Two UIDs resolved from SEARCH+FETCH → two fetches.
        assert len(messages) == 2

    @pytest.mark.asyncio
    async def test_poll_once_uses_plain_search_not_uid_search(self):
        """Regression for the Apr 22 live error:
            command UID only possible with COPY, FETCH, EXPUNGE
            (w/UIDPLUS) or STORE (was SEARCH)
        The poll_once implementation must call client.search(), NOT
        client.uid('search', ...) — aioimaplib 2.0 rejects UID+SEARCH.
        """
        client = MagicMock()
        client.select = AsyncMock(return_value=("OK", [b""]))
        client.search = AsyncMock(return_value=("OK", [b""]))
        client.uid = AsyncMock(return_value=("OK", [b""]))
        p = self._make_provider_with_client(client)
        await p.poll_once("INBOX", since_uid=1000)
        # Plain SEARCH must be used.
        client.search.assert_awaited_once()
        # uid() must NOT be used for the search (only for STORE/COPY
        # elsewhere in the provider, not in poll_once).
        for call in client.uid.await_args_list:
            assert call.args[0] != "search", (
                "poll_once called client.uid('search', ...) — aioimaplib "
                "2.0 rejects this. Use client.search() instead."
            )


# ---------------------------------------------------------------------------
# 6. WatcherManager push/poll gating
# ---------------------------------------------------------------------------

class TestWatcherStart:
    @pytest.mark.asyncio
    async def test_push_disabled_skips_imap_idle_start(
        self, app, db, admin_user,
    ):
        """When push_enabled=False, WatcherManager.start() does NOT
        spin up the IDLE coroutine, but still registers for poll."""
        from email_triage.web.db import update_email_account_config
        aid = _make_imap_account(db, admin_user["id"])
        update_email_account_config(db, aid, {
            "host": "m", "username": "u", "mailboxes": ["INBOX"],
            "push_enabled": False, "poll_enabled": True,
            "poll_interval_minutes": 60,
        })

        mgr = app.state.watcher_manager
        msg = await mgr.start(aid)
        try:
            assert "Poll enabled" in msg
            assert mgr.is_poll_running(aid)
            assert not mgr.is_push_running(aid)
        finally:
            await mgr.stop(aid, persist=False)

    @pytest.mark.asyncio
    async def test_both_disabled_returns_disabled(
        self, app, db, admin_user,
    ):
        from email_triage.web.db import update_email_account_config
        aid = _make_imap_account(db, admin_user["id"])
        update_email_account_config(db, aid, {
            "host": "m", "username": "u", "mailboxes": ["INBOX"],
            "push_enabled": False, "poll_enabled": False,
            "poll_interval_minutes": 60,
        })
        mgr = app.state.watcher_manager
        msg = await mgr.start(aid)
        assert "disabled" in msg.lower()
        assert not mgr.is_running(aid)

    @pytest.mark.asyncio
    async def test_poll_enabled_runs_safety_net_when_push_healthy(
        self, app, db, admin_user,
    ):
        """Both push_enabled and poll_enabled True: both arms register
        (poll registration is cheap; push start is a no-op here since
        we don't exercise the actual IDLE coroutine)."""
        from email_triage.web.db import update_email_account_config
        aid = _make_gmail_account(db, admin_user["id"])
        update_email_account_config(db, aid, {
            "account": "me@gmail.com",
            "push_enabled": True, "poll_enabled": True,
            "poll_interval_minutes": 60,
        })
        mgr = app.state.watcher_manager
        msg = await mgr.start(aid)
        try:
            assert mgr.is_poll_running(aid)
        finally:
            await mgr.stop(aid, persist=False)


# ---------------------------------------------------------------------------
# 7. Save handler + watcher bounce
# ---------------------------------------------------------------------------

class TestAccountUpdateBounce:
    @pytest.mark.asyncio
    async def test_account_update_bounces_watcher_when_flags_change(
        self, client, db, admin_user, admin_cookies,
    ):
        """Flipping push_enabled on the edit form should stop + restart
        the account's watcher so the change takes effect immediately."""
        from email_triage.web.db import update_email_account_config
        aid = _make_imap_account(db, admin_user["id"])
        update_email_account_config(db, aid, {
            "host": "m", "username": "u", "mailboxes": ["INBOX"],
            "push_enabled": True, "poll_enabled": True,
            "poll_interval_minutes": 60,
        })
        mgr = client.app.state.watcher_manager
        # Register for poll so we can observe the bounce clearing + re-adding.
        await mgr.start(aid)
        assert mgr.is_poll_running(aid)

        stop_mock = AsyncMock(side_effect=mgr.stop)
        start_mock = AsyncMock(side_effect=mgr.start)
        with patch.object(mgr, "stop", new=stop_mock), \
             patch.object(mgr, "start", new=start_mock):
            resp = client.put(
                f"/accounts/{aid}", cookies=admin_cookies,
                data={
                    "name": "Imap", "provider_type": "imap",
                    "is_active": "1",
                    "host": "m", "port": "993", "username": "u",
                    "use_ssl": "1", "mailboxes": ["INBOX"],
                    # Flip push off.
                    "__ingestion_fields_present": "1",
                    "poll_enabled": "1",
                    "poll_interval_minutes": "60",
                    # no push_enabled = unchecked
                },
            )
        assert resp.status_code == 200
        assert stop_mock.await_count >= 1
        assert start_mock.await_count >= 1

    def test_account_update_clamps_out_of_range_interval(
        self, client, db, admin_user, admin_cookies,
    ):
        """Save with poll_interval_minutes=9999 must clamp to POLL_MAX=240."""
        aid = _make_imap_account(db, admin_user["id"])
        resp = client.put(
            f"/accounts/{aid}", cookies=admin_cookies,
            data={
                "name": "Imap", "provider_type": "imap",
                "is_active": "1",
                "host": "m", "port": "993", "username": "u",
                "use_ssl": "1", "mailboxes": ["INBOX"],
                "__ingestion_fields_present": "1",
                "push_enabled": "1", "poll_enabled": "1",
                "poll_interval_minutes": "9999",
            },
        )
        assert resp.status_code == 200
        acct = get_email_account(db, aid)
        assert acct["config"]["poll_interval_minutes"] == 240

    def test_account_update_snaps_off_grid_interval(
        self, client, db, admin_user, admin_cookies,
    ):
        """Save with poll_interval_minutes=27 must snap to 30."""
        aid = _make_imap_account(db, admin_user["id"])
        resp = client.put(
            f"/accounts/{aid}", cookies=admin_cookies,
            data={
                "name": "Imap", "provider_type": "imap",
                "is_active": "1",
                "host": "m", "port": "993", "username": "u",
                "use_ssl": "1", "mailboxes": ["INBOX"],
                "__ingestion_fields_present": "1",
                "push_enabled": "1", "poll_enabled": "1",
                "poll_interval_minutes": "27",
            },
        )
        assert resp.status_code == 200
        acct = get_email_account(db, aid)
        assert acct["config"]["poll_interval_minutes"] == 30
