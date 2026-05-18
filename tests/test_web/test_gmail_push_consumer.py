"""Tests for the Gmail Pub/Sub push consumer + watch renewer.

Exercises ``_process_push_item`` and ``_run_watch_renewal_sweep``
directly — pulling items off a live asyncio.Queue would make these
tests timing-sensitive.  The consumer's queue-drain loop itself is
covered indirectly by the webhook queue-enqueue tests.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.app import _process_push_item, _run_watch_renewal_sweep
from email_triage.web.db import (
    get_gmail_watch,
    list_hipaa_access_events,
    upsert_gmail_watch,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_account(db, *, hipaa=False, account_id=1, email="user@gmail.com"):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR REPLACE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, is_active, created_at, updated_at) "
        "VALUES (?, 1, 'Test Gmail', 'gmail_api', ?, ?, 1, ?, ?)",
        (account_id, json.dumps({"account": email, "client_id": "cid"}),
         1 if hipaa else 0, now, now),
    )
    db.commit()


def _seed_watch(db, *, account_id=1, email="user@gmail.com", history_id="100"):
    upsert_gmail_watch(
        db,
        account_id=account_id,
        email_address=email,
        topic_name="projects/test/topics/gmail-push",
        history_id=history_id,
        expires_at=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
    )


@pytest.fixture
def push_app(app, db, admin_user):
    """Configure the test app with push config + queue so the consumer can run."""
    app.state.db = db
    app.state.config.push.gmail_topic_name = "projects/test/topics/gmail-push"
    app.state.config.push.gmail_subscription_sa_email = "sa@project.iam.gserviceaccount.com"
    app.state.push_queue = asyncio.Queue(maxsize=8)
    return app


@pytest.fixture
def fake_provider():
    """A GmailApiProvider with its network methods replaced."""
    from email_triage.providers.gmail_api import GmailApiProvider

    provider = GmailApiProvider(client_id="cid", refresh_token="rt")
    provider.list_history = AsyncMock()
    provider.fetch_message = AsyncMock()
    provider.register_watch = AsyncMock()
    provider.search = AsyncMock(return_value=[])
    provider.close = AsyncMock()
    return provider


@pytest.fixture
def fake_classifier():
    from email_triage.engine.models import Classification

    classifier = MagicMock()
    classifier.classify = AsyncMock(return_value=Classification(
        category="action-required", confidence=0.9, reason="test",
    ))
    return classifier


def _fake_message(mid="m-1", hipaa=False):
    from email_triage.engine.models import EmailMessage
    return EmailMessage(
        message_id=mid,
        provider="gmail_api",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Hi",
        body_text="body",
        date=datetime.now(timezone.utc),
        hipaa=hipaa,
    )


# ---------------------------------------------------------------------------
# _process_push_item
# ---------------------------------------------------------------------------


class TestProcessPushItem:
    async def test_happy_path_processes_new_messages(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [
                {"messagesAdded": [{"message": {"id": "m-1"}}]},
                {"messagesAdded": [{"message": {"id": "m-2"}}]},
            ],
            "historyId": "150",
        }
        fake_provider.fetch_message.side_effect = [
            _fake_message("m-1"), _fake_message("m-2"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "150", "account_id": 1},
            )

        fake_provider.list_history.assert_awaited_once()
        assert fake_provider.fetch_message.await_count == 2
        assert fake_classifier.classify.await_count == 2
        # Cursor advanced to the latest delta historyId.
        assert get_gmail_watch(db, 1)["history_id"] == "150"

    async def test_stale_history_id_is_noop(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_watch(db, history_id="200")

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "100", "account_id": 1},
            )

        fake_provider.list_history.assert_not_awaited()
        fake_provider.fetch_message.assert_not_awaited()
        assert get_gmail_watch(db, 1)["history_id"] == "200"

    async def test_history_expired_falls_back_to_search(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        from email_triage.providers.gmail_api import GmailHistoryExpiredError

        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.side_effect = GmailHistoryExpiredError(
            404, "historyId is too old", "/users/me/history",
        )
        fake_provider.search.return_value = ["m-recent-1"]
        fake_provider.fetch_message.return_value = _fake_message("m-recent-1")

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "999", "account_id": 1},
            )

        # Bounded backfill widened to 7d / 200 (2026-04-29) so a
        # full week of messages can be recovered after Gmail's
        # cursor-retention window expires the start_history_id.
        fake_provider.search.assert_awaited_once_with("newer_than:7d", limit=200)
        assert fake_provider.fetch_message.await_count == 1
        # Cursor advanced to the incoming historyId after the resync.
        assert get_gmail_watch(db, 1)["history_id"] == "999"

    async def test_hipaa_account_writes_no_access_event(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """Watch-driven runs are opt-in; trail is triage_runs, not
        hipaa_access_events. This guards that scope decision."""
        _make_account(db, hipaa=True)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [{"messagesAdded": [{"message": {"id": "m-1"}}]}],
            "historyId": "150",
        }
        fake_provider.fetch_message.return_value = _fake_message("m-1", hipaa=True)

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "150", "account_id": 1},
            )

        assert list_hipaa_access_events(db) == []

    async def test_per_message_error_does_not_halt_delta(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [
                {"messagesAdded": [
                    {"message": {"id": "m-1"}},
                    {"message": {"id": "m-2"}},
                ]},
            ],
            "historyId": "200",
        }
        fake_provider.fetch_message.side_effect = [
            RuntimeError("transient"),
            _fake_message("m-2"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "200", "account_id": 1},
            )

        # Cursor still advanced — the delta was processed to completion.
        assert get_gmail_watch(db, 1)["history_id"] == "200"
        # m-2 reached the classifier.
        assert fake_classifier.classify.await_count == 1

    async def test_gmail_404_treats_message_as_vanished_not_error(
        self, push_app, db, fake_provider, fake_classifier, caplog,
    ):
        """Race condition: push fires for a message the user deleted /
        archived between the notification and our fetch. Treated as a
        benign skip (INFO log, no error counter), not an ERROR."""
        from email_triage.providers.gmail_api import GmailApiError

        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [
                {"messagesAdded": [
                    {"message": {"id": "m-vanished"}},
                    {"message": {"id": "m-2"}},
                ]},
            ],
            "historyId": "200",
        }
        fake_provider.fetch_message.side_effect = [
            GmailApiError(
                404, {"error": {"message": "Requested entity was not found."}},
                "/users/me/messages/m-vanished",
            ),
            _fake_message("m-2"),
        ]

        import logging
        with caplog.at_level(logging.INFO, logger="email_triage.web.app"), \
             patch(
                "email_triage.web.routers.ui._create_provider_from_account",
                return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "200", "account_id": 1},
            )

        # Vanished message does NOT count as an error.
        # m-2 still classified — the delta finished.
        assert fake_classifier.classify.await_count == 1
        # Cursor advanced — Pub/Sub consumed.
        assert get_gmail_watch(db, 1)["history_id"] == "200"
        # No ERROR log line for the 404; an INFO line announcing the
        # vanished skip should be present.
        error_lines = [r for r in caplog.records if r.levelname == "ERROR"]
        assert not any(
            "per-message error" in r.getMessage() for r in error_lines
        ), "404 race must not raise per-message error"
        assert any(
            "vanished before fetch" in r.getMessage()
            for r in caplog.records
        ), "404 race must log a vanished-skip INFO line"

    async def test_transient_network_error_retries_once(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """First fetch raises httpx.ReadTimeout; second succeeds.
        The message reaches the classifier without an error row."""
        import httpx

        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [{"messagesAdded": [{"message": {"id": "m-flaky"}}]}],
            "historyId": "200",
        }
        fake_provider.fetch_message.side_effect = [
            httpx.ReadTimeout(""),
            _fake_message("m-flaky"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ), patch(
            # Don't actually sleep 2s in tests.
            "email_triage.web.app.asyncio.sleep",
            new=AsyncMock(),
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "200", "account_id": 1},
            )

        # Two fetch attempts (first failed, second succeeded), one
        # classify (the retry succeeded, so the message reaches it).
        assert fake_provider.fetch_message.await_count == 2
        assert fake_classifier.classify.await_count == 1

    async def test_transient_network_error_propagates_after_retry(
        self, push_app, db, fake_provider, fake_classifier, caplog,
    ):
        """Both attempts raise httpx.ConnectError → falls through to
        the per-message-error path (ERROR log, error row recorded)."""
        import httpx, logging

        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {
            "history": [{"messagesAdded": [{"message": {"id": "m-dead"}}]}],
            "historyId": "200",
        }
        fake_provider.fetch_message.side_effect = [
            httpx.ConnectError("All connection attempts failed"),
            httpx.ConnectError("All connection attempts failed"),
        ]

        with caplog.at_level(logging.WARNING, logger="email_triage.web.app"), \
             patch(
                "email_triage.web.routers.ui._create_provider_from_account",
                return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ), patch(
            "email_triage.web.app.asyncio.sleep",
            new=AsyncMock(),
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "200", "account_id": 1},
            )

        # Two attempts at the same message — retry happened.
        assert fake_provider.fetch_message.await_count == 2
        # Per-message-error path took over after the retry exhausted.
        error_lines = [
            r for r in caplog.records
            if r.levelname == "ERROR"
            and "per-message error" in r.getMessage()
        ]
        assert error_lines, "exhausted-retry should log per-message error"

    async def test_empty_delta_still_advances_cursor(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_watch(db, history_id="100")

        fake_provider.list_history.return_value = {"history": [], "historyId": "150"}

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_push_item(
                push_app, {"email": "user@gmail.com", "history_id": "150", "account_id": 1},
            )

        assert get_gmail_watch(db, 1)["history_id"] == "150"
        fake_provider.fetch_message.assert_not_awaited()


# ---------------------------------------------------------------------------
# _run_watch_renewal_sweep
# ---------------------------------------------------------------------------


class TestWatchRenewalSweep:
    async def test_renews_expiring_watch(self, push_app, db, fake_provider):
        _make_account(db)
        # Expire in 12 hours — within the 48h window.
        soon = (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat()
        upsert_gmail_watch(
            db,
            account_id=1,
            email_address="user@gmail.com",
            topic_name="projects/test/topics/gmail-push",
            history_id="100",
            expires_at=soon,
        )

        new_exp_ms = int((datetime.now(timezone.utc) + timedelta(days=7)).timestamp() * 1000)
        fake_provider.register_watch.return_value = {
            "historyId": "200", "expiration": new_exp_ms,
        }

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            await _run_watch_renewal_sweep(push_app, window_hours=48)

        fake_provider.register_watch.assert_awaited_once_with("projects/test/topics/gmail-push")
        w = get_gmail_watch(db, 1)
        # history_id comes from the new register_watch response.
        assert w["history_id"] == "200"
        # expires_at moved forward past the original 12h mark.
        assert w["expires_at"] > soon

    async def test_skips_watches_outside_window(self, push_app, db, fake_provider):
        _make_account(db)
        far = (datetime.now(timezone.utc) + timedelta(days=5)).isoformat()
        upsert_gmail_watch(
            db,
            account_id=1,
            email_address="user@gmail.com",
            topic_name="projects/test/topics/gmail-push",
            history_id="100",
            expires_at=far,
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            await _run_watch_renewal_sweep(push_app, window_hours=48)

        fake_provider.register_watch.assert_not_awaited()
        assert get_gmail_watch(db, 1)["expires_at"] == far

    async def test_watch_renewal_skips_synthetic_poll_rows(
        self, push_app, db, fake_provider,
    ):
        """B3 seeds synthetic poll-mode rows with topic_name='' and
        an epoch sentinel expires_at. The renewer sweep must ignore
        them — they have no subscription to renew — rather than
        logging a warning every 30 min."""
        _make_account(db)
        upsert_gmail_watch(
            db,
            account_id=1,
            email_address="user@gmail.com",
            topic_name="",  # synthetic marker
            history_id="42",
            expires_at="1970-01-01T00:00:00+00:00",  # epoch sentinel
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            await _run_watch_renewal_sweep(push_app, window_hours=48)

        fake_provider.register_watch.assert_not_awaited()
        # Row untouched — still the synthetic sentinel.
        w = get_gmail_watch(db, 1)
        assert w["topic_name"] == ""
        assert w["history_id"] == "42"
