"""Tests for the Office 365 / Microsoft Graph push consumer.

Bundle F-followup F-3: ``_process_office365_push_item`` brought to
parity with the Gmail push consumer — direct fetch+classify on every
delivery, advancing the per-account ``@odata.deltaLink`` cursor on
``office365_subscriptions``. These tests mirror the shape of
``tests/test_web/test_gmail_push_consumer.py`` so the two providers
have parallel coverage.

Resync handling: Graph returns 410 (or "resyncRequired") when the
stored deltaLink is too stale. The consumer falls back to a bounded
``search()`` and re-seeds the cursor on the next walk — same shape as
Gmail's history-expired path.

HIPAA: watch-driven runs are opt-in (per the watch HIPAA decision —
push deliveries don't write ``hipaa_access_events``). The trail is
``triage_runs`` only.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.web.app import _process_office365_push_item
from email_triage.web.db import (
    get_o365_subscription,
    list_hipaa_access_events,
    upsert_o365_subscription,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_account(db, *, hipaa=False, account_id=1, email="user@contoso.com"):
    """Insert an O365 email_account row + its parent user."""
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
        "VALUES (?, 1, 'Test O365', 'office365', ?, ?, 1, ?, ?)",
        (
            account_id,
            json.dumps({
                "account": email,
                "client_id": "client-fixture-1",
                "tenant_id": "tenant-fixture-1",
            }),
            1 if hipaa else 0,
            now, now,
        ),
    )
    db.commit()


def _seed_subscription(
    db, *, account_id=1, subscription_id="subscription-fixture-1",
    delta_link: str | None = None,
):
    """Insert an o365 subscription row (and optionally seed a cursor)."""
    future = (
        datetime.now(timezone.utc) + timedelta(days=2)
    ).isoformat()
    upsert_o365_subscription(
        db,
        account_id=account_id,
        subscription_id=subscription_id,
        expiration_at=future,
    )
    if delta_link is not None:
        from email_triage.web.db import update_o365_subscription_delta_link
        update_o365_subscription_delta_link(
            db, account_id=account_id, delta_link=delta_link,
        )


@pytest.fixture
def push_app(app, db, admin_user):
    """Configure the test app for the O365 push consumer."""
    app.state.db = db
    return app


@pytest.fixture
def fake_provider():
    """An Office365Provider with its network methods replaced.

    HAS_MSAL is patched on so the constructor doesn't bail in test
    environments where the optional dependency isn't installed.
    """
    from email_triage.providers import office365 as o365_mod
    from email_triage.providers.office365 import Office365Provider

    o365_mod.HAS_MSAL = True
    provider = Office365Provider(
        client_id="client-fixture-1",
        tenant_id="tenant-fixture-1",
        token_cache_path="/tmp/test_o365_cache.json",
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


def _fake_message(mid="msg-fixture-1", *, hipaa=False, headers=None):
    from email_triage.engine.models import EmailMessage
    return EmailMessage(
        message_id=mid,
        provider="office365",
        sender="alice@example.com",
        recipients=["bob@example.com"],
        subject="Hi",
        body_text="body",
        date=datetime.now(timezone.utc),
        hipaa=hipaa,
        headers=headers or {},
    )


# ---------------------------------------------------------------------------
# _process_office365_push_item — happy path + cursor advance
# ---------------------------------------------------------------------------


class TestProcessOffice365PushItem:
    @pytest.mark.asyncio
    async def test_happy_path_processes_new_messages(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/old-cursor")

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
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        # Cursor passed back to Graph + advanced on the row.
        fake_provider.poll_delta.assert_awaited_once_with(
            "https://graph/old-cursor",
        )
        assert fake_provider.fetch_message.await_count == 2
        assert fake_classifier.classify.await_count == 2
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/new-cursor"

    @pytest.mark.asyncio
    async def test_first_walk_passes_none_cursor(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """No stored cursor → poll_delta(None) kicks off a fresh walk."""
        _make_account(db)
        _seed_subscription(db)  # no delta_link

        fake_provider.poll_delta.return_value = (
            [], "https://graph/initial-cursor",
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        fake_provider.poll_delta.assert_awaited_once_with(None)
        # Even on empty delta the cursor advances so the next webhook
        # picks up from a useful position.
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/initial-cursor"

    @pytest.mark.asyncio
    async def test_resync_required_falls_back_to_search(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """410 / resyncRequired → bounded backfill via search() +
        seed a fresh cursor for next time."""
        from email_triage.providers.office365 import (
            GraphDeltaResyncRequiredError,
        )

        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/dead-cursor")

        # First call: cursor expired. Second call (post-search): seeds
        # a fresh cursor for the next webhook.
        fake_provider.poll_delta.side_effect = [
            GraphDeltaResyncRequiredError(
                410, {"error": {"message": "resyncRequired"}}, "/delta",
            ),
            ([], "https://graph/fresh-cursor"),
        ]
        fake_provider.search.return_value = ["msg-recent-1"]
        fake_provider.fetch_message.return_value = _fake_message(
            "msg-recent-1",
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        fake_provider.search.assert_awaited_once()
        # The recent message reached the classifier.
        assert fake_classifier.classify.await_count == 1
        # Cursor advanced to the fresh seed.
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/fresh-cursor"

    @pytest.mark.asyncio
    async def test_per_message_error_does_not_halt_delta(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/old-cursor")

        fake_provider.poll_delta.return_value = (
            ["msg-1", "msg-2"], "https://graph/new-cursor",
        )
        fake_provider.fetch_message.side_effect = [
            RuntimeError("transient graph error"),
            _fake_message("msg-2"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        # Cursor still advanced — the delta finished processing.
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/new-cursor"
        # msg-2 reached the classifier despite msg-1 erroring.
        assert fake_classifier.classify.await_count == 1

    @pytest.mark.asyncio
    async def test_404_fetch_treated_as_vanished(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """Message deleted between delta walk + fetch → log + skip,
        don't bubble the GraphError up."""
        from email_triage.providers.office365 import GraphError

        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/old-cursor")

        fake_provider.poll_delta.return_value = (
            ["msg-vanished", "msg-still-there"], "https://graph/new-cursor",
        )
        fake_provider.fetch_message.side_effect = [
            GraphError(
                404,
                {"error": {"message": "ResourceNotFound"}},
                "/me/messages/msg-vanished",
            ),
            _fake_message("msg-still-there"),
        ]

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        # Only the surviving message reached the classifier.
        assert fake_classifier.classify.await_count == 1
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/new-cursor"

    @pytest.mark.asyncio
    async def test_x_email_triage_header_skipped(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """A message we generated ourselves shouldn't be re-triaged.

        ``X-Email-Triage`` header presence short-circuits the
        classify+act path; the message still counts toward the run
        as ``status="skipped"`` so the operator can see what got
        filtered out.
        """
        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/old-cursor")

        fake_provider.poll_delta.return_value = (
            ["msg-self"], "https://graph/new-cursor",
        )
        fake_provider.fetch_message.return_value = _fake_message(
            "msg-self",
            headers={"X-Email-Triage": "draft_reply"},
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        # Classifier was never called — the header skip happens before.
        assert fake_classifier.classify.await_count == 0

    @pytest.mark.asyncio
    async def test_hipaa_account_writes_no_access_event(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """Watch-driven runs are opt-in for HIPAA — same scope rule
        as the Gmail push consumer. Trail is triage_runs, not
        hipaa_access_events.
        """
        _make_account(db, hipaa=True)
        _seed_subscription(db, delta_link="https://graph/old-cursor")

        fake_provider.poll_delta.return_value = (
            ["msg-1"], "https://graph/new-cursor",
        )
        fake_provider.fetch_message.return_value = _fake_message(
            "msg-1", hipaa=True,
        )

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        assert list_hipaa_access_events(db) == []

    @pytest.mark.asyncio
    async def test_owner_disabled_skips_processing(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """Fail-closed: account whose owner is disabled doesn't trigger
        triage. The cursor is NOT advanced either — re-enable should
        see the backlog.
        """
        _make_account(db)
        _seed_subscription(db, delta_link="https://graph/old-cursor")
        # Disable the owner.
        db.execute(
            "UPDATE users SET disabled = 1 WHERE id = 1"
        )
        db.commit()

        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ), patch(
            "email_triage.web.routers.ui._build_classifier_from_config",
            return_value=fake_classifier,
        ):
            await _process_office365_push_item(
                push_app, {"account_id": 1, "subscription_id": "subscription-fixture-1"},
            )

        fake_provider.poll_delta.assert_not_awaited()
        # Cursor untouched.
        row = get_o365_subscription(db, 1)
        assert row["delta_link"] == "https://graph/old-cursor"

    @pytest.mark.asyncio
    async def test_missing_account_short_circuits(
        self, push_app, db, fake_provider, fake_classifier,
    ):
        """No account_id, or unknown account_id, returns cleanly without
        touching the provider."""
        with patch(
            "email_triage.web.routers.ui._create_provider_from_account",
            return_value=fake_provider,
        ):
            # Empty payload.
            await _process_office365_push_item(push_app, {})
            # Account_id that doesn't exist.
            await _process_office365_push_item(
                push_app, {"account_id": 9999},
            )
        fake_provider.poll_delta.assert_not_awaited()


# ---------------------------------------------------------------------------
# poll_delta provider unit
# ---------------------------------------------------------------------------


class TestPollDelta:
    @pytest.mark.asyncio
    async def test_first_walk_uses_initial_path(self):
        """No cursor → call /me/mailFolders('Inbox')/messages/delta
        with $select=id; surface the deltaLink as the new cursor."""
        from email_triage.providers import office365 as o365_mod
        from email_triage.providers.office365 import Office365Provider

        o365_mod.HAS_MSAL = True
        provider = Office365Provider(
            client_id="client-fixture-1", tenant_id="tenant-fixture-1",
            token_cache_path="/tmp/test_poll_delta_cache.json",
        )
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "value": [{"id": "msg-1"}, {"id": "msg-2"}],
                "@odata.deltaLink": "https://graph/delta?$deltatoken=fresh",
            }
            ids, cursor = await provider.poll_delta(None)
        assert ids == ["msg-1", "msg-2"]
        assert cursor == "https://graph/delta?$deltatoken=fresh"
        # Initial call must be relative + carry $select=id.
        call = mock_req.await_args_list[0]
        assert call.args[0] == "GET"
        assert call.args[1] == "/me/mailFolders('Inbox')/messages/delta"
        assert call.kwargs.get("params", {}).get("$select") == "id"

    @pytest.mark.asyncio
    async def test_subsequent_walk_uses_stored_link(self):
        """A stored deltaLink is passed back verbatim (absolute=True)."""
        from email_triage.providers import office365 as o365_mod
        from email_triage.providers.office365 import Office365Provider

        o365_mod.HAS_MSAL = True
        provider = Office365Provider(
            client_id="client-fixture-1", tenant_id="tenant-fixture-1",
            token_cache_path="/tmp/test_poll_delta_cache.json",
        )
        stored = "https://graph/delta?$deltatoken=stored"
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = {
                "value": [{"id": "msg-3"}],
                "@odata.deltaLink": "https://graph/delta?$deltatoken=fresh",
            }
            ids, cursor = await provider.poll_delta(stored)
        assert ids == ["msg-3"]
        assert cursor == "https://graph/delta?$deltatoken=fresh"
        call = mock_req.await_args_list[0]
        assert call.args[1] == stored
        assert call.kwargs.get("absolute") is True

    @pytest.mark.asyncio
    async def test_resync_410_raises(self):
        """410 Gone → GraphDeltaResyncRequiredError."""
        from email_triage.providers import office365 as o365_mod
        from email_triage.providers.office365 import (
            Office365Provider, GraphError, GraphDeltaResyncRequiredError,
        )

        o365_mod.HAS_MSAL = True
        provider = Office365Provider(
            client_id="client-fixture-1", tenant_id="tenant-fixture-1",
            token_cache_path="/tmp/test_poll_delta_cache.json",
        )
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.side_effect = GraphError(
                410, {"error": {"code": "resyncRequired"}}, "/delta",
            )
            with pytest.raises(GraphDeltaResyncRequiredError):
                await provider.poll_delta("https://graph/dead")

    @pytest.mark.asyncio
    async def test_walks_paginated_response(self):
        """nextLink intermediate pages are followed; final deltaLink
        is the cursor."""
        from email_triage.providers import office365 as o365_mod
        from email_triage.providers.office365 import Office365Provider

        o365_mod.HAS_MSAL = True
        provider = Office365Provider(
            client_id="client-fixture-1", tenant_id="tenant-fixture-1",
            token_cache_path="/tmp/test_poll_delta_cache.json",
        )
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.side_effect = [
                {
                    "value": [{"id": "msg-1"}],
                    "@odata.nextLink": "https://graph/delta?$skiptoken=p2",
                },
                {
                    "value": [{"id": "msg-2"}],
                    "@odata.deltaLink": "https://graph/delta?$deltatoken=fresh",
                },
            ]
            ids, cursor = await provider.poll_delta(None)
        assert ids == ["msg-1", "msg-2"]
        assert cursor == "https://graph/delta?$deltatoken=fresh"
        assert mock_req.await_count == 2
