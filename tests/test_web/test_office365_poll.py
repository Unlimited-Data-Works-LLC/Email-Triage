"""Tests for the Office 365 unified-poll dispatch.

Before  the dispatcher's ``_o365_poll_once`` was a ``return None``
stub: an O365 account added via the UI received ZERO triage while
``_run_unified_poll_tick`` still recorded a poll tick, so the dashboard
showed it healthily polling.

``_poll_once_office365`` walks the Graph Inbox delta feed (the same
``poll_delta`` machinery the push consumer uses) and triages every
changed message through the standard ``triage_single_message`` body.
The delta cursor for a poll-only account (no ``office365_subscriptions``
row) lives in the ``office365_poll_cursor:<id>`` settings key.

These tests mirror ``test_office365_push_consumer.py`` — the two O365
ingestion paths share the same provider mocks + message fixtures.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.app import _poll_once_office365
from email_triage.web.db import get_setting
from email_triage.web.settings_keys import office365_poll_cursor


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_account(db, *, account_id=1, email="user@contoso.com"):
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO users (id, email, name, role, created_at) "
        "VALUES (1, 'seed@test.com', 'Seed', 'user', ?)",
        (now,),
    )
    db.execute(
        "INSERT OR REPLACE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, hipaa, "
        " is_active, created_at, updated_at) "
        "VALUES (?, 1, 'Test O365', 'office365', ?, 0, 1, ?, ?)",
        (
            account_id,
            json.dumps({
                "account": email,
                "client_id": "client-fixture-1",
                "tenant_id": "tenant-fixture-1",
            }),
            now, now,
        ),
    )
    db.commit()
    from email_triage.web.db import get_email_account
    return get_email_account(db, account_id)


@pytest.fixture
def poll_app(app, db, admin_user):
    app.state.db = db
    return app


@pytest.fixture
def fake_provider():
    from email_triage.providers import office365 as o365_mod
    from email_triage.providers.office365 import Office365Provider

    o365_mod.HAS_MSAL = True
    provider = Office365Provider(
        client_id="client-fixture-1",
        tenant_id="tenant-fixture-1",
        token_cache_path="/tmp/test_o365_poll_cache.json",
    )
    provider.poll_delta = AsyncMock()
    provider.fetch_message = AsyncMock()
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


def _fake_message(mid="msg-fixture-1"):
    from email_triage.engine.models import EmailMessage
    return EmailMessage(
        message_id=mid,
        provider="office365",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Hi",
        body_text="body",
        date=datetime.now(timezone.utc),
        hipaa=False,
        headers={},
    )


# ---------------------------------------------------------------------------
# _poll_once_office365
# ---------------------------------------------------------------------------


class TestPollOnceOffice365:
    @pytest.mark.asyncio
    async def test_first_tick_seeds_cursor_and_skips_backlog(
        self, poll_app, db, fake_provider, fake_classifier,
    ):
        """A poll-only account with no stored cursor: first tick seeds
        the cursor + triages nothing (no backlog dump)."""
        acct = _make_account(db)
        fake_provider.poll_delta.return_value = (
            ["msg-1", "msg-2"], "https://graph/initial-cursor",
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _poll_once_office365(poll_app, acct)

        # First walk: None cursor.
        fake_provider.poll_delta.assert_awaited_once_with(None)
        # Backlog NOT triaged on the bootstrap tick.
        assert fake_provider.fetch_message.await_count == 0
        # Cursor seeded for the next tick.
        cur = get_setting(db, office365_poll_cursor(acct["id"]))
        assert cur["delta_link"] == "https://graph/initial-cursor"

    @pytest.mark.asyncio
    async def test_second_tick_triages_new_messages(
        self, poll_app, db, fake_provider, fake_classifier,
    ):
        """With a stored cursor, the tick fetches + triages every
        changed message and advances the cursor."""
        acct = _make_account(db)
        # Seed a prior cursor (simulates a completed first tick).
        from email_triage.web.db import set_setting
        set_setting(
            db, office365_poll_cursor(acct["id"]),
            {"delta_link": "https://graph/old-cursor"},
        )
        fake_provider.poll_delta.return_value = (
            ["msg-1", "msg-2"], "https://graph/new-cursor",
        )
        fake_provider.fetch_message.side_effect = [
            _fake_message("msg-1"), _fake_message("msg-2"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _poll_once_office365(poll_app, acct)

        fake_provider.poll_delta.assert_awaited_once_with(
            "https://graph/old-cursor",
        )
        assert fake_provider.fetch_message.await_count == 2
        assert fake_classifier.classify.await_count == 2
        cur = get_setting(db, office365_poll_cursor(acct["id"]))
        assert cur["delta_link"] == "https://graph/new-cursor"

    @pytest.mark.asyncio
    async def test_empty_delta_advances_cursor_no_triage(
        self, poll_app, db, fake_provider, fake_classifier,
    ):
        acct = _make_account(db)
        from email_triage.web.db import set_setting
        set_setting(
            db, office365_poll_cursor(acct["id"]),
            {"delta_link": "https://graph/old-cursor"},
        )
        fake_provider.poll_delta.return_value = (
            [], "https://graph/empty-cursor",
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _poll_once_office365(poll_app, acct)

        assert fake_provider.fetch_message.await_count == 0
        cur = get_setting(db, office365_poll_cursor(acct["id"]))
        assert cur["delta_link"] == "https://graph/empty-cursor"

    @pytest.mark.asyncio
    async def test_non_o365_provider_returns_early(
        self, poll_app, db, fake_classifier,
    ):
        """A mis-typed account doesn't blow up the tick."""
        acct = _make_account(db)
        non_o365 = MagicMock()
        non_o365.close = AsyncMock()

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=non_o365,
        ):
            await _poll_once_office365(poll_app, acct)

        # No cursor written, provider closed.
        assert get_setting(db, office365_poll_cursor(acct["id"])) is None
        non_o365.close.assert_awaited_once()
