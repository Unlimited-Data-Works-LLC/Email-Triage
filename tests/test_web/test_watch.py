"""Tests for the IMAP IDLE watch system.

Tests the watcher manager, watch endpoints (start/stop/status),
and watcher state persistence via the settings table.
"""

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from email_triage.web.app import WatcherManager
from email_triage.web.db import get_setting, set_setting


def _make_imap_account(db, user_id: int, name: str = "Test IMAP") -> int:
    """Helper: create an IMAP account in the database."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, "imap", json.dumps({
            "host": "mail.test.com",
            "port": 993,
            "username": "test@test.com",
            "use_ssl": True,
            "mailbox": "INBOX",
        }), 1, now, now),
    )
    db.commit()
    return cursor.lastrowid


def _make_office365_account(db, user_id: int, name: str = "Test O365") -> int:
    """Helper: create an office365 account (no IMAP IDLE watch support;
    uses Graph webhooks instead — still valid for routes-page gating)."""
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.execute(
        "INSERT INTO email_accounts (user_id, name, provider_type, config_json, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, name, "office365", json.dumps({
            "client_id": "cid", "tenant_id": "common",
        }), 1, now, now),
    )
    db.commit()
    return cursor.lastrowid


# ---------------------------------------------------------------------------
# WatcherManager unit tests
# ---------------------------------------------------------------------------

class TestWatcherManager:
    """Test the WatcherManager state tracking."""

    def test_initial_status_is_stopped(self, app, db):
        mgr = app.state.watcher_manager
        status = mgr.status(999)
        assert status["status"] == "stopped"
        assert status["processed"] == 0
        assert status["errors"] == 0

    def test_is_running_false_initially(self, app, db):
        mgr = app.state.watcher_manager
        assert mgr.is_running(999) is False

    def test_all_statuses_empty(self, app, db):
        mgr = app.state.watcher_manager
        assert mgr.all_statuses() == {}


# ---------------------------------------------------------------------------
# Watch endpoint tests
# ---------------------------------------------------------------------------

class TestWatchEndpoints:
    """Test the watch start/stop/status HTTP endpoints."""

    def test_watch_status_requires_auth(self, client):
        resp = client.get("/accounts/1/watch/status")
        assert resp.status_code == 401

    def test_watch_start_requires_auth(self, client):
        resp = client.post("/accounts/1/watch/start")
        assert resp.status_code == 401

    def test_watch_stop_requires_auth(self, client):
        resp = client.post("/accounts/1/watch/stop")
        assert resp.status_code == 401

    def test_watch_status_account_not_found(self, client, admin_cookies):
        resp = client.get("/accounts/999/watch/status", cookies=admin_cookies)
        assert resp.status_code == 404

    def test_watch_start_account_not_found(self, client, admin_cookies):
        resp = client.post("/accounts/999/watch/start", cookies=admin_cookies)
        # The endpoint returns HTML with error message, not 404
        assert resp.status_code in (200, 404)

    def test_watch_stop_account_not_found(self, client, admin_cookies):
        resp = client.post("/accounts/999/watch/stop", cookies=admin_cookies)
        assert resp.status_code in (200, 404)

    def test_watch_status_forbidden_for_other_user(
        self, client, db, admin_user, regular_user, user_cookies,
    ):
        """Regular user can't see watch status of admin's account."""
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/watch/status", cookies=user_cookies)
        assert resp.status_code == 403

    def test_watch_status_shows_stopped(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(f"/accounts/{acct_id}/watch/status", cookies=admin_cookies)
        assert resp.status_code == 200
        assert "Stopped" in resp.text

    def test_watch_stop_sets_setting(
        self, client, db, admin_user, admin_cookies,
    ):
        """Stopping a watch persists enabled=false in settings."""
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(f"/accounts/{acct_id}/watch/stop", cookies=admin_cookies)
        assert resp.status_code == 200
        cfg = get_setting(db, f"watch:{acct_id}")
        assert cfg is not None
        assert cfg["enabled"] is False

    def test_edit_watch_tab_shows_watch_section_for_imap(
        self, client, db, admin_user, admin_cookies,
    ):
        """Account-edit Watch tab shows the watch config knobs for IMAP.

        The Real-Time Watch fieldset moved off /routes onto the
        /accounts/{id}/edit?tab=watch tab — /routes was strictly the
        message-routing surface; live ingestion config belongs with
        the rest of per-account settings. The Start/Stop live-state
        UI is rendered via HTMX (``_watch_status.html``) into the
        page after load, not in initial HTML — assertions stick to
        the static fieldset content.
        """
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(
            f"/accounts/{acct_id}/edit?tab=watch", cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Real-Time Watch" in resp.text
        # Push + Poll config knobs are the static surface on this tab.
        assert 'name="push_enabled"' in resp.text
        assert 'name="poll_enabled"' in resp.text
        assert 'name="poll_interval_minutes"' in resp.text

    # Removed: test_routes_page_hides_watch_for_non_push_provider —
    # the original case (gmail_mcp with no push) no longer exists after
    # pulling the MCP provider. Gmail API + IMAP IDLE + Office 365 Graph
    # webhooks all support push today.


# ---------------------------------------------------------------------------
# #24a: /watch/start must dispatch on provider_type — Gmail is webhook /
# server-poll, not IDLE-generator. Starting the IMAP-IDLE watcher path for
# a Gmail account triggers NotImplementedError + a 5s reconnect loop.
# ---------------------------------------------------------------------------

def _make_gmail_account(db, user_id: int, name: str = "G", config: dict | None = None) -> int:
    from email_triage.web.db import create_email_account
    cfg = {"account": "user@gmail.com"}
    if config:
        cfg.update(config)
    return create_email_account(db, user_id, name, "gmail_api", cfg)


class TestWatchStartDispatch:
    """Provider-type dispatch in POST /accounts/{id}/watch/start."""

    def test_watch_start_gmail_poll_no_idle_call(
        self, client, db, admin_user, admin_cookies,
    ):
        """Gmail poll-mode account: /watch/start returns status describing
        the B3 poll cadence; WatcherManager.start must NOT be called."""
        from unittest.mock import AsyncMock, patch

        aid = _make_gmail_account(db, admin_user["id"])
        mgr = client.app.state.watcher_manager
        with patch.object(mgr, "start", new=AsyncMock()) as start_mock:
            resp = client.post(
                f"/accounts/{aid}/watch/start", cookies=admin_cookies,
            )

        assert resp.status_code == 200
        # Friendly status — mentions polling, not an IDLE watcher.
        assert "Polling" in resp.text
        # The Pub/Sub upsell hint should be visible.
        assert "Pub/Sub" in resp.text
        # Watcher manager start was never invoked for a gmail_api account.
        start_mock.assert_not_awaited()
        # And the page does NOT offer a "Start Watching" button anymore
        # for this status (non-IMAP providers have no IDLE to start).
        assert "Start Watching" not in resp.text

    def test_watch_start_gmail_push_active_mentions_renewal(
        self, client, db, admin_user, admin_cookies,
    ):
        """Gmail push-mode account: status reports the active watch and
        does not call into the IDLE watcher path."""
        from unittest.mock import AsyncMock, patch
        from datetime import datetime, timedelta, timezone
        from email_triage.web.db import upsert_gmail_watch

        aid = _make_gmail_account(db, admin_user["id"])
        upsert_gmail_watch(
            db, account_id=aid, email_address="user@gmail.com",
            topic_name="projects/test/topics/push",
            history_id="1",
            expires_at=(datetime.now(timezone.utc) + timedelta(days=5)).isoformat(),
        )

        mgr = client.app.state.watcher_manager
        with patch.object(mgr, "start", new=AsyncMock()) as start_mock:
            resp = client.post(
                f"/accounts/{aid}/watch/start", cookies=admin_cookies,
            )

        assert resp.status_code == 200
        assert "Push active" in resp.text or "Gmail push: active" in resp.text
        assert "auto-renewed" in resp.text
        start_mock.assert_not_awaited()

    def test_watch_start_imap_still_uses_watcher_manager(
        self, client, db, admin_user, admin_cookies,
    ):
        """Regression guard — IMAP accounts still go through WatcherManager."""
        from unittest.mock import AsyncMock, patch

        aid = _make_imap_account(db, admin_user["id"])
        mgr = client.app.state.watcher_manager
        with patch.object(
            mgr, "start", new=AsyncMock(return_value="Watching started"),
        ) as start_mock:
            resp = client.post(
                f"/accounts/{aid}/watch/start", cookies=admin_cookies,
            )
        assert resp.status_code == 200
        start_mock.assert_awaited_once_with(aid)


# ---------------------------------------------------------------------------
# #24b: WatcherManager loop must treat NotImplementedError as a permanent
# failure — mark status "unsupported", log once, stop retrying.
# ---------------------------------------------------------------------------

class TestWatcherPermanentFailure:
    """The _watch_account loop must not spin on NotImplementedError."""

    async def test_watcher_handles_notimplementederror_as_permanent(
        self, app, db, admin_user,
    ):
        """Provider whose watch() raises NotImplementedError → status
        transitions to 'unsupported' and the task exits without retrying.

        If the handler regresses into the generic ``except Exception``
        branch, the watcher sleeps for ``backoff`` seconds before
        retrying forever. The test uses an ``asyncio.wait_for`` timeout
        guard to catch that regression deterministically.
        """
        import asyncio
        from unittest.mock import patch, MagicMock

        aid = _make_imap_account(db, admin_user["id"])

        class _FakeProvider:
            async def get_latest_uid(self):
                return 0

            async def watch(self):
                raise NotImplementedError(
                    "Real-time watch is not supported on this provider via "
                    "the generator path."
                )
                yield ""  # pragma: no cover

            async def close(self):
                return None

        mgr = app.state.watcher_manager
        # Seed the per-(account, mailbox) state dict the same way
        # mgr.start() would — the watcher coroutine reads
        # _mb_state[(account_id, mailbox)] as it advances.
        from datetime import datetime, timezone
        mgr._mb_state[(aid, "INBOX")] = {
            "status": "starting",
            "processed": 0,
            "errors": 0,
            "last_message": None,
            "last_error": None,
            "started_at": datetime.now(timezone.utc).isoformat(),
        }

        from email_triage.web import app as app_module
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=_FakeProvider(),
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=MagicMock(),
        ), patch(
            "email_triage.web.routers.ui._get_categories_from_db",
            return_value=[],
        ):
            # If the watcher regresses to the reconnect path, it would
            # sleep for 5s then loop — wait_for kills it at 2s.
            await asyncio.wait_for(
                app_module._watch_account(mgr, aid), timeout=2.0,
            )

        status = mgr.status(aid)
        assert status["status"] == "unsupported", (
            f"expected 'unsupported', got {status['status']!r} "
            f"(last_error={status.get('last_error')!r})"
        )
        assert status["last_error"]
        assert "not supported" in status["last_error"].lower()

        # And the persisted watch:enabled flag was cleared so a
        # process restart doesn't resurrect the same hopeless task.
        cfg = get_setting(db, f"watch:{aid}")
        assert cfg is not None
        assert cfg["enabled"] is False

    async def test_gmail_api_watch_error_message_is_neutral(self):
        """Error message from gmail_api.watch() must not leak the API
        contract (``generator``, ``webhooks endpoint``) to operators."""
        from email_triage.providers.gmail_api import GmailApiProvider

        provider = GmailApiProvider(client_id="x", refresh_token="y")
        msg = ""
        try:
            async for _ in provider.watch():  # pragma: no cover
                break
        except NotImplementedError as e:
            msg = str(e)

        # Operator-facing message stays neutral — no "/webhooks/gmail"
        # or "Call register_watch()" jargon.
        assert "/webhooks/gmail" not in msg
        assert "register_watch" not in msg
        assert "not supported" in msg.lower()


# ---------------------------------------------------------------------------
# Settings persistence tests
# ---------------------------------------------------------------------------

class TestWatchSettings:
    """Test watch-enabled setting persistence."""

    def test_setting_roundtrip(self, db):
        set_setting(db, "watch:42", {"enabled": True})
        cfg = get_setting(db, "watch:42")
        assert cfg == {"enabled": True}

    def test_disable_setting(self, db):
        set_setting(db, "watch:42", {"enabled": True})
        set_setting(db, "watch:42", {"enabled": False})
        cfg = get_setting(db, "watch:42")
        assert cfg["enabled"] is False

    def test_no_setting_returns_none(self, db):
        cfg = get_setting(db, "watch:999")
        assert cfg is None


# ---------------------------------------------------------------------------
# High-water mark tests
# ---------------------------------------------------------------------------

class TestHighWaterMark:
    """Test the watcher high-water mark (last processed UID) persistence."""

    def test_hwm_default_is_zero(self, db):
        """No HWM setting means UID 0 — process everything."""
        hwm = get_setting(db, "watch_hwm:1")
        assert hwm is None

    def test_hwm_roundtrip(self, db):
        set_setting(db, "watch_hwm:1", {"uid": 12345, "updated_at": "2026-04-16T12:00:00Z"})
        hwm = get_setting(db, "watch_hwm:1")
        assert hwm["uid"] == 12345

    def test_hwm_advances(self, db):
        """Simulates what the watcher does: advance the HWM after processing."""
        set_setting(db, "watch_hwm:1", {"uid": 100})
        set_setting(db, "watch_hwm:1", {"uid": 200})
        hwm = get_setting(db, "watch_hwm:1")
        assert hwm["uid"] == 200

    def test_reset_hwm_endpoint_requires_auth(self, client):
        resp = client.post("/accounts/1/watch/reset-hwm")
        assert resp.status_code == 401

    def test_reset_hwm_endpoint_clears_mark(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        set_setting(db, f"watch_hwm:{acct_id}", {"uid": 5000})
        assert get_setting(db, f"watch_hwm:{acct_id}") is not None

        resp = client.post(
            f"/accounts/{acct_id}/watch/reset-hwm",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "reset" in resp.text.lower()
        assert get_setting(db, f"watch_hwm:{acct_id}") is None

    def test_reset_hwm_forbidden_for_other_user(
        self, client, db, admin_user, regular_user, user_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/watch/reset-hwm",
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_watch_status_shows_hwm(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        set_setting(db, f"watch_hwm:{acct_id}", {"uid": 8888, "updated_at": "2026-04-16T12:00:00Z"})
        resp = client.get(
            f"/accounts/{acct_id}/watch/status",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "8888" in resp.text

    def test_watch_status_no_hwm_shown_when_zero(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(
            f"/accounts/{acct_id}/watch/status",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Last processed UID" not in resp.text

    def test_reset_button_shown_when_stopped_with_hwm(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        set_setting(db, f"watch_hwm:{acct_id}", {"uid": 1234})
        resp = client.get(
            f"/accounts/{acct_id}/watch/status",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Reset Position" in resp.text

    def test_set_to_current_button_shown_when_stopped(
        self, client, db, admin_user, admin_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.get(
            f"/accounts/{acct_id}/watch/status",
            cookies=admin_cookies,
        )
        assert resp.status_code == 200
        assert "Set to Current" in resp.text

    def test_set_to_current_requires_auth(self, client):
        resp = client.post("/accounts/1/watch/set-hwm-current")
        assert resp.status_code == 401

    def test_set_to_current_forbidden_for_other_user(
        self, client, db, admin_user, regular_user, user_cookies,
    ):
        acct_id = _make_imap_account(db, admin_user["id"])
        resp = client.post(
            f"/accounts/{acct_id}/watch/set-hwm-current",
            cookies=user_cookies,
        )
        assert resp.status_code == 403

    def test_set_to_current_account_not_found(self, client, admin_cookies):
        resp = client.post(
            "/accounts/999/watch/set-hwm-current",
            cookies=admin_cookies,
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# stop_all shutdown hardening (Phase 5.x — bounded so a hung
# watcher can't block container SIGTERM beyond podman's grace.)
# ---------------------------------------------------------------------------

class TestStopAllBounded:
    """Stop_all parallelizes + bounds per-task wait at 3s."""

    async def test_stop_all_caps_a_hung_watcher_at_3_seconds(self, app, db):
        """A watcher whose finally block hangs must NOT block stop_all forever."""
        import asyncio
        import time
        mgr = app.state.watcher_manager

        async def hung_watcher():
            try:
                # Pretend to be a watcher in its main loop.
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                # Simulate a finally block that hangs (e.g. a stuck logout).
                # Suppress the cancel so wait_for has to time us out.
                try:
                    await asyncio.sleep(60)
                except asyncio.CancelledError:
                    # Re-raised by wait_for after its timeout fires; let it
                    # take us down so the test doesn't leak the task.
                    raise

        task = asyncio.create_task(hung_watcher())
        mgr._tasks[(42, "INBOX")] = task

        t0 = time.monotonic()
        await mgr.stop_all()
        elapsed = time.monotonic() - t0

        # Should bail in ~3s, definitely not 3600.
        assert elapsed < 5.0, f"stop_all hung for {elapsed:.1f}s"
        # Task is forced down by wait_for's cancel.
        assert task.done()

    async def test_stop_all_normal_path_is_fast(self, app, db):
        """A well-behaved watcher should stop within milliseconds."""
        import asyncio
        import time
        mgr = app.state.watcher_manager

        async def well_behaved():
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                return  # cooperatively shut down

        task = asyncio.create_task(well_behaved())
        mgr._tasks[(42, "INBOX")] = task

        t0 = time.monotonic()
        await mgr.stop_all()
        elapsed = time.monotonic() - t0

        assert elapsed < 0.5, f"stop_all took {elapsed:.2f}s for a clean exit"
        assert mgr._tasks == {}


# ---------------------------------------------------------------------------
# IMAP close() shutdown hardening (Phase 5.x — bounded logout so a
# stalled IDLE connection can't block shutdown past podman's grace.)
# ---------------------------------------------------------------------------

class TestImapCloseBounded:
    async def test_close_caps_logout_at_2s_and_force_closes_transport(self):
        """A logout that hangs must NOT block close() beyond ~2s."""
        import asyncio
        import time
        from unittest.mock import AsyncMock, MagicMock
        from email_triage.providers.imap import ImapProvider

        # Bypass __init__ — don't need aioimaplib installed to test close().
        provider = ImapProvider.__new__(ImapProvider)
        provider._client = None
        # Stand in a fake aioimaplib client whose logout never returns.
        fake = MagicMock()

        async def stuck_logout():
            await asyncio.sleep(60)

        fake.logout = AsyncMock(side_effect=stuck_logout)
        fake.protocol = MagicMock()
        fake.protocol.transport = MagicMock()
        fake.protocol.transport.close = MagicMock()
        provider._client = fake

        t0 = time.monotonic()
        await provider.close()
        elapsed = time.monotonic() - t0

        assert elapsed < 3.0, f"close() hung for {elapsed:.1f}s"
        # Transport was force-closed after the logout timed out.
        fake.protocol.transport.close.assert_called_once()
        assert provider._client is None

    async def test_close_clean_path_just_logs_out(self):
        """Happy path: logout completes quickly, transport still closed."""
        from unittest.mock import AsyncMock, MagicMock
        from email_triage.providers.imap import ImapProvider

        # Bypass __init__ — don't need aioimaplib installed to test close().
        provider = ImapProvider.__new__(ImapProvider)
        provider._client = None
        fake = MagicMock()
        fake.logout = AsyncMock(return_value=None)
        fake.protocol = MagicMock()
        fake.protocol.transport = MagicMock()
        fake.protocol.transport.close = MagicMock()
        provider._client = fake

        await provider.close()

        fake.logout.assert_awaited_once()
        # Belt-and-braces transport close runs even on the happy path.
        fake.protocol.transport.close.assert_called_once()
        assert provider._client is None

    async def test_close_no_client_is_noop(self):
        from email_triage.providers.imap import ImapProvider
        # Bypass __init__ — don't need aioimaplib installed to test close().
        provider = ImapProvider.__new__(ImapProvider)
        provider._client = None
        # No client attached — should not raise.
        await provider.close()
        assert provider._client is None


# ---------------------------------------------------------------------------
# Item #9 — multi-mailbox watch per IMAP account
# ---------------------------------------------------------------------------

class TestMultiMailboxBackCompat:
    """The DB layer must normalise legacy ``mailbox`` configs to ``mailboxes``."""

    def test_account_load_back_compat_mailbox_to_mailboxes(self, db, admin_user):
        """Legacy single-string ``mailbox`` config loads as a one-element
        ``mailboxes`` list. Old readers of ``mailbox`` keep working."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "legacy", "imap",
             json.dumps({
                 "host": "mail.test.com", "username": "u",
                 "mailbox": "INBOX.Legacy",
             }), now, now),
        )
        db.commit()
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, cur.lastrowid)
        assert acct["config"]["mailboxes"] == ["INBOX.Legacy"]
        # Legacy key is preserved so old readers keep working.
        assert acct["config"]["mailbox"] == "INBOX.Legacy"

    def test_account_load_empty_config_defaults_to_inbox_mailboxes_list(
        self, db, admin_user,
    ):
        """No ``mailbox`` and no ``mailboxes`` → back-compat helper leaves
        both absent. The watcher/provider-create helpers handle the
        absent case by defaulting to INBOX."""
        import json
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "empty", "imap",
             json.dumps({"host": "mail.test.com"}), now, now),
        )
        db.commit()
        from email_triage.web.db import get_email_account, _account_mailboxes
        acct = get_email_account(db, cur.lastrowid)
        # The shim only fires when ``mailbox`` is set — but the runtime
        # helper always falls back to ["INBOX"].
        assert _account_mailboxes(acct["config"]) == ["INBOX"]


class TestMultiMailboxSave:
    """Account-save flow must persist ``mailboxes`` and enforce the cap."""

    def test_account_save_writes_both_mailboxes_and_legacy_mailbox(
        self, client, db, admin_user, admin_cookies,
    ):
        """Save writes BOTH the canonical ``mailboxes`` list AND a
        legacy-compat ``mailbox = mailboxes[0]`` entry so older readers
        still see a value. The shim is a short-term belt so we can
        migrate readers later without a flag day."""
        acct_id = _make_imap_account(db, admin_user["id"])
        # Submit a multi-folder selection. httpx encodes a dict-of-list
        # into one ``mailboxes=<folder>`` repetition per value, which is
        # what HTML <input type=checkbox name=mailboxes> posts produce.
        resp = client.put(
            f"/accounts/{acct_id}",
            cookies=admin_cookies,
            data={
                "name": "Test IMAP",
                "provider_type": "imap",
                "is_active": "1",
                "host": "mail.test.com",
                "port": "993",
                "username": "u",
                "use_ssl": "1",
                "mailboxes": ["INBOX", "Spam", "Sent"],
            },
        )
        assert resp.status_code == 200
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, acct_id)
        assert acct["config"]["mailboxes"] == ["INBOX", "Spam", "Sent"]
        # Legacy key is kept in sync with the primary folder.
        assert acct["config"]["mailbox"] == "INBOX"

    def test_account_save_exceeds_cap_returns_form_error(
        self, client, db, admin_user, admin_cookies,
    ):
        """Selecting more than the install-wide cap returns a form
        error instead of silently truncating — operator must decide
        which folders matter."""
        # Force the cap to 2 for this test via the app config.
        client.app.state.config.provider.imap["max_mailboxes_per_account"] = 2
        acct_id = _make_imap_account(db, admin_user["id"])

        resp = client.put(
            f"/accounts/{acct_id}",
            cookies=admin_cookies,
            data={
                "name": "Test IMAP",
                "provider_type": "imap",
                "is_active": "1",
                "host": "mail.test.com",
                "port": "993",
                "username": "u",
                "use_ssl": "1",
                "mailboxes": ["INBOX", "Spam", "Sent"],
            },
        )
        assert resp.status_code == 200
        # The response renders the edit form with a visible error.
        assert "Too many folders selected" in resp.text
        # And the account was NOT updated — still has the original
        # single-mailbox config.
        from email_triage.web.db import get_email_account
        acct = get_email_account(db, acct_id)
        assert acct["config"]["mailboxes"] == ["INBOX"]
        # Restore default cap so other tests aren't affected.
        client.app.state.config.provider.imap.pop("max_mailboxes_per_account", None)

    async def test_account_save_new_mailboxes_list_bounces_watchers(
        self, app, db, admin_user,
    ):
        """When the mailbox list changes AND at least one watcher is
        running, the save handler stops + restarts to pick up the new
        folder set. No bounce happens otherwise."""
        from unittest.mock import AsyncMock
        acct_id = _make_imap_account(db, admin_user["id"])
        mgr = app.state.watcher_manager

        # Pretend a watcher is currently running.
        async def _never():
            while True:
                import asyncio
                await asyncio.sleep(10)
        import asyncio
        fake_task = asyncio.create_task(_never())
        mgr._tasks[(acct_id, "INBOX")] = fake_task
        mgr._mb_state[(acct_id, "INBOX")] = {"status": "watching"}

        start_mock = AsyncMock(return_value="Watching started on 2 mailboxes")
        stop_mock = AsyncMock(return_value="Watching stopped")
        mgr.start = start_mock  # type: ignore[assignment]
        mgr.stop = stop_mock  # type: ignore[assignment]

        # Call the update flow via an internal route simulation —
        # ensure the bounce actually fires by checking the helper that
        # the endpoint delegates to. Simplest check: directly patch the
        # DB to new mailboxes and invoke the relevant logic via a
        # TestClient PUT.
        from fastapi.testclient import TestClient
        client = TestClient(app, raise_server_exceptions=False)
        token_cookies = None
        # Need an admin session for the PUT — reuse the auth fixtures
        # via create_session_token.
        from email_triage.web.auth import (
            SESSION_COOKIE_NAME, create_session_token,
        )
        token_cookies = {
            SESSION_COOKIE_NAME: create_session_token(
                app.state.session_secret,
                admin_user["email"], admin_user["role"],
            ),
        }
        resp = client.put(
            f"/accounts/{acct_id}",
            cookies=token_cookies,
            data={
                "name": "Test IMAP",
                "provider_type": "imap",
                "is_active": "1",
                "host": "mail.test.com",
                "port": "993",
                "username": "test@test.com",
                "use_ssl": "1",
                "mailboxes": ["INBOX", "Spam"],
            },
        )
        assert resp.status_code == 200
        # Bounce fired: stop then start.
        stop_mock.assert_awaited_once_with(acct_id, persist=False)
        start_mock.assert_awaited_once_with(acct_id)

        # Cleanup the stale fake task.
        fake_task.cancel()
        try:
            await fake_task
        except asyncio.CancelledError:
            pass

    async def test_account_save_unchanged_mailboxes_does_not_bounce_watchers(
        self, app, db, admin_user,
    ):
        """If the mailbox list is identical before/after save (e.g. the
        user just toggled HIPAA), the running watchers must NOT be
        restarted — bouncing is a visible IDLE reconnection that costs
        real latency."""
        from unittest.mock import AsyncMock
        import asyncio
        acct_id = _make_imap_account(db, admin_user["id"])
        mgr = app.state.watcher_manager

        async def _never():
            while True:
                await asyncio.sleep(10)
        fake_task = asyncio.create_task(_never())
        mgr._tasks[(acct_id, "INBOX")] = fake_task
        mgr._mb_state[(acct_id, "INBOX")] = {"status": "watching"}

        start_mock = AsyncMock()
        stop_mock = AsyncMock()
        mgr.start = start_mock  # type: ignore[assignment]
        mgr.stop = stop_mock  # type: ignore[assignment]

        from fastapi.testclient import TestClient
        from email_triage.web.auth import (
            SESSION_COOKIE_NAME, create_session_token,
        )
        client = TestClient(app, raise_server_exceptions=False)
        cookies = {
            SESSION_COOKIE_NAME: create_session_token(
                app.state.session_secret,
                admin_user["email"], admin_user["role"],
            ),
        }
        resp = client.put(
            f"/accounts/{acct_id}",
            cookies=cookies,
            data={
                "name": "Test IMAP",
                "provider_type": "imap",
                "is_active": "1",
                "host": "mail.test.com",
                "port": "993",
                "username": "test@test.com",
                "use_ssl": "1",
                "mailboxes": "INBOX",
            },
        )
        assert resp.status_code == 200
        start_mock.assert_not_awaited()
        stop_mock.assert_not_awaited()

        fake_task.cancel()
        try:
            await fake_task
        except asyncio.CancelledError:
            pass


class TestWatcherManagerMultiMailbox:
    """WatcherManager must track one task per (account, mailbox)."""

    async def test_watcher_manager_starts_one_per_mailbox(
        self, app, db, admin_user,
    ):
        """``start()`` with a multi-mailbox config spawns one task per
        folder. Each task carries its own mailbox kwarg into
        ``_watch_account()``."""
        import json
        from unittest.mock import AsyncMock, MagicMock, patch
        now = datetime.now(timezone.utc).isoformat()
        cur = db.execute(
            "INSERT INTO email_accounts (user_id, name, provider_type, "
            "config_json, is_active, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, 1, ?, ?)",
            (admin_user["id"], "multi", "imap",
             json.dumps({
                 "host": "mail.test.com", "username": "u",
                 "mailboxes": ["INBOX", "Spam", "Sent"],
             }), now, now),
        )
        acct_id = cur.lastrowid
        db.commit()

        mgr = app.state.watcher_manager

        # Stub _watch_account so we don't actually hit the network but
        # we do see one task per mailbox get created.
        started: list[tuple[int, str]] = []

        async def _fake_watch(manager, account_id, *, mailbox="INBOX"):
            started.append((account_id, mailbox))
            # Park forever so is_running observes us.
            import asyncio
            await asyncio.sleep(3600)

        # Patch a PushCapable provider so the capability probe passes.
        from email_triage.providers.base import PushCapable

        class _StubProvider(PushCapable):
            async def watch(self):
                yield "1"  # pragma: no cover
            async def close(self):
                return None

        with patch("email_triage.web.app._watch_account", new=_fake_watch), \
             patch(
                 "email_triage.web.routers.ui._create_provider_from_account",
                 return_value=_StubProvider(),
             ):
            msg = await mgr.start(acct_id)
            # Yield once so each spawned task gets a chance to run far
            # enough to append itself to ``started``.
            import asyncio as _asyncio
            await _asyncio.sleep(0)

        assert "3 mailboxes" in msg
        # One task per folder.
        keys = [k for k in mgr._tasks if k[0] == acct_id]
        assert sorted(k[1] for k in keys) == ["INBOX", "Sent", "Spam"]
        assert sorted(started, key=lambda t: t[1]) == [
            (acct_id, "INBOX"), (acct_id, "Sent"), (acct_id, "Spam"),
        ]

        # Cleanup.
        for k in list(keys):
            task = mgr._tasks.pop(k, None)
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except BaseException:
                    pass

    async def test_watcher_manager_stop_stops_all_mailboxes_for_account(
        self, app, db, admin_user,
    ):
        """``stop(account_id)`` must cancel every mailbox task — no
        orphan IDLE connections left behind."""
        import asyncio
        acct_id = _make_imap_account(db, admin_user["id"])
        mgr = app.state.watcher_manager

        async def _never():
            while True:
                await asyncio.sleep(10)
        for mb in ("INBOX", "Spam", "Sent"):
            mgr._tasks[(acct_id, mb)] = asyncio.create_task(_never())
            mgr._mb_state[(acct_id, mb)] = {"status": "watching"}

        await mgr.stop(acct_id)

        # All tasks gone for this account.
        remaining = [k for k in mgr._tasks if k[0] == acct_id]
        assert remaining == []

    def test_watcher_manager_is_running_true_when_any_mailbox_connected(
        self, app, db, admin_user,
    ):
        """``is_running`` is the aggregate: true if ANY mailbox still
        has a running task. Matches what the UI chip needs."""
        from unittest.mock import MagicMock
        acct_id = _make_imap_account(db, admin_user["id"])
        mgr = app.state.watcher_manager

        # No tasks: not running.
        assert mgr.is_running(acct_id) is False

        # Stub tasks that advertise done()-state without needing a
        # running event loop — the unit under test only calls task.done().
        live = MagicMock()
        live.done.return_value = False
        done = MagicMock()
        done.done.return_value = True

        mgr._tasks[(acct_id, "INBOX")] = live
        mgr._tasks[(acct_id, "Spam")] = done
        assert mgr.is_running(acct_id) is True

        # Flip the live one to done — now is_running is False.
        live.done.return_value = True
        assert mgr.is_running(acct_id) is False


class TestMultiMailboxHWM:
    """HWM must be per-(account, mailbox) because IMAP UIDs are per-mailbox."""

    def test_hwm_per_mailbox_not_shared_across_folders(self, db):
        """Writing a HWM to INBOX does not leak into Spam's HWM. UIDs
        are scoped to a mailbox in IMAP — a shared HWM would mean UID
        500 in Spam gets skipped just because we already processed UID
        500 in INBOX."""
        from email_triage.web.db import (
            set_mailbox_hwm, get_mailbox_hwm,
        )
        set_mailbox_hwm(db, 42, "INBOX", {"uid": 500})
        # Spam must read as "no HWM yet" — fresh folder, fresh counter.
        assert get_mailbox_hwm(db, 42, "Spam") is None

        set_mailbox_hwm(db, 42, "Spam", {"uid": 100})
        assert get_mailbox_hwm(db, 42, "INBOX")["uid"] == 500
        assert get_mailbox_hwm(db, 42, "Spam")["uid"] == 100

    def test_hwm_legacy_per_account_migrated_to_inbox_key_on_first_read(self, db):
        """Pre-#9 installs have a single ``watch_hwm:<id>`` key whose
        semantics are implicitly INBOX. The first read for INBOX copies
        that value into the new-shaped key so old state isn't lost."""
        from email_triage.web.db import (
            set_setting, get_mailbox_hwm, get_setting,
        )
        # Seed only the legacy key.
        set_setting(db, "watch_hwm:7", {"uid": 9999, "updated_at": "2026-04-16T12:00:00Z"})

        # First read against the INBOX-specific helper migrates the value.
        got = get_mailbox_hwm(db, 7, "INBOX")
        assert got is not None
        assert got["uid"] == 9999

        # Second read comes straight from the new-shaped key.
        assert get_setting(db, "watch_hwm:7:mailbox:INBOX")["uid"] == 9999

        # Non-INBOX folder does NOT inherit the legacy value.
        assert get_mailbox_hwm(db, 7, "Spam") is None


class TestFolderDiscoveryInEditForm:
    """The edit form must surface the IMAP folder list when available
    and degrade gracefully when it isn't."""

    def test_edit_form_renders_folder_checkboxes_with_inbox_prechecked(
        self, client, db, admin_user, admin_cookies,
    ):
        """When ``list_folders()`` returns a list, the edit form renders
        a checkbox per folder with INBOX pre-checked by default."""
        from unittest.mock import AsyncMock, patch
        acct_id = _make_imap_account(db, admin_user["id"])

        # Stub a provider that returns a known folder list.
        class _FakeProvider:
            async def list_folders(self):
                return ["INBOX", "INBOX.Sent", "Spam"]
            async def close(self):
                return None

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=_FakeProvider(),
        ):
            resp = client.get(
                f"/accounts/{acct_id}/edit", cookies=admin_cookies,
            )
        assert resp.status_code == 200
        # All three folders appear as checkbox values.
        for folder in ("INBOX", "INBOX.Sent", "Spam"):
            assert f'value="{folder}"' in resp.text
        # INBOX is pre-checked.
        assert 'value="INBOX"' in resp.text and "checked" in resp.text

    def test_edit_form_folder_discovery_failure_falls_back_to_text_input(
        self, client, db, admin_user, admin_cookies,
    ):
        """If the IMAP probe raises (auth not yet saved, network error,
        optional dep missing) the form MUST still render — with a
        comma-separated text input instead of checkboxes. A form stuck
        behind a network probe would be worse than no multi-select."""
        from unittest.mock import patch
        acct_id = _make_imap_account(db, admin_user["id"])

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            side_effect=RuntimeError("no auth yet"),
        ):
            resp = client.get(
                f"/accounts/{acct_id}/edit", cookies=admin_cookies,
            )
        assert resp.status_code == 200
        # Fallback input is present (by name).
        assert 'name="mailboxes_csv"' in resp.text
