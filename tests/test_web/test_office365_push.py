"""Tests for the Office 365 / Microsoft Graph push pipeline (#53 + #66).

Covers:

* DB helpers — upsert / lookup / list / expiring sweep / error record
* Webhook receiver `/webhooks/office365` (and back-compat `/webhooks/graph`):
    - validation handshake echoes the token
    - demux by subscription_id
    - clientState mismatch is dropped + counted
    - happy path queues onto push_queue + stamps last_notification_at
* Provider `create_subscription` round-trip (mocked Graph)
* /health surface includes the office365_push block
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import pytest

from email_triage.web.db import (
    delete_o365_subscription,
    get_o365_subscription,
    get_o365_subscription_by_subscription_id,
    list_o365_subscriptions,
    list_o365_subscriptions_expiring,
    record_o365_notification,
    record_o365_subscription_error,
    upsert_o365_subscription,
)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------

def _seed_account(db, account_id=1, name="Test O365"):
    """Insert a parent email_accounts row so the FK constraint is happy.

    Also seeds a placeholder user(id=1) when one isn't already there —
    tests that don't need ``admin_user`` still need the FK target.
    """
    now = datetime.now(timezone.utc).isoformat()
    db.execute(
        "INSERT OR IGNORE INTO users (id, email, name, role, created_at) "
        "VALUES (1, 'seed@test.com', 'Seed', 'user', ?)",
        (now,),
    )
    db.execute(
        "INSERT OR IGNORE INTO email_accounts "
        "(id, user_id, name, provider_type, config_json, created_at, updated_at) "
        "VALUES (?, 1, ?, 'office365', ?, ?, ?)",
        (account_id, name, json.dumps({"account": "u@contoso.com"}), now, now),
    )
    db.commit()


@pytest.fixture
def push_app(client):
    """Configure the queue + secret so the push handler can run."""
    app = client.app
    app.state.push_queue = asyncio.Queue(maxsize=4)
    app.state.metrics = {}
    return app


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------


class TestO365SubscriptionDb:
    def test_upsert_round_trip(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db,
            account_id=1,
            subscription_id="sub-1",
            expiration_at=future,
        )
        row = get_o365_subscription(db, 1)
        assert row is not None
        assert row["subscription_id"] == "sub-1"
        assert row["status"] == "active"
        assert row["error_count"] == 0
        assert row["error_last"] is None
        assert row["last_notification_at"] is None

    def test_upsert_replaces_existing_and_clears_errors(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-1",
            expiration_at=future,
        )
        record_o365_subscription_error(
            db, account_id=1, error_text="oops",
        )
        row = get_o365_subscription(db, 1)
        assert row["status"] == "errored"
        assert row["error_count"] == 1

        # A fresh upsert (e.g. successful renew) must reset errors.
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-2",
            expiration_at=future,
        )
        row = get_o365_subscription(db, 1)
        assert row["subscription_id"] == "sub-2"
        assert row["status"] == "active"
        assert row["error_count"] == 0
        assert row["error_last"] is None

    def test_lookup_by_subscription_id(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-abc",
            expiration_at=future,
        )
        row = get_o365_subscription_by_subscription_id(db, "sub-abc")
        assert row is not None
        assert row["account_id"] == 1
        assert get_o365_subscription_by_subscription_id(db, "missing") is None
        assert get_o365_subscription_by_subscription_id(db, "") is None

    def test_record_notification_stamps_heartbeat(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-1",
            expiration_at=future,
        )
        record_o365_notification(db, "sub-1")
        row = get_o365_subscription(db, 1)
        assert row["last_notification_at"] is not None
        # Unknown subscription_id is a no-op, not an error.
        record_o365_notification(db, "sub-other")

    def test_list_expiring(self, db):
        _seed_account(db, account_id=1)
        _seed_account(db, account_id=2, name="Other")
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=1)
        ).isoformat()
        far = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-1",
            expiration_at=soon,
        )
        upsert_o365_subscription(
            db, account_id=2, subscription_id="sub-2",
            expiration_at=far,
        )
        cutoff = (
            datetime.now(timezone.utc) + timedelta(hours=24)
        ).isoformat()
        expiring = list_o365_subscriptions_expiring(db, cutoff)
        ids = [r["subscription_id"] for r in expiring]
        assert "sub-1" in ids
        assert "sub-2" not in ids

    def test_delete(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-1",
            expiration_at=future,
        )
        delete_o365_subscription(db, 1)
        assert get_o365_subscription(db, 1) is None
        assert list_o365_subscriptions(db) == []

    def test_record_error_truncates(self, db):
        _seed_account(db)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=1, subscription_id="sub-1",
            expiration_at=future,
        )
        long_error = "x" * 1000
        record_o365_subscription_error(
            db, account_id=1, error_text=long_error,
        )
        row = get_o365_subscription(db, 1)
        assert len(row["error_last"]) == 500
        assert row["status"] == "errored"
        assert row["error_count"] == 1


# ---------------------------------------------------------------------------
# Webhook receiver
# ---------------------------------------------------------------------------


class TestO365WebhookReceiver:
    def test_validation_handshake_office365_path(self, client, db):
        resp = client.post(
            "/webhooks/office365?validationToken=hello-graph", json={},
        )
        assert resp.status_code == 200
        assert resp.text == "hello-graph"

    def test_validation_handshake_legacy_graph_path(self, client, db):
        # Back-compat alias.
        resp = client.post(
            "/webhooks/graph?validationToken=legacy", json={},
        )
        assert resp.status_code == 200
        assert resp.text == "legacy"

    def test_unknown_subscription_id_dropped_with_200(
        self, push_app, client, db,
    ):
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "never-registered",
                "clientState": "anything",
                "resource": "me/mailFolders('Inbox')/messages",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["queued"] == 0
        assert body["dropped_unknown"] == 1
        # No items queued.
        assert push_app.state.push_queue.qsize() == 0
        assert push_app.state.metrics.get(
            "office365_push.unknown_subscription"
        ) == 1

    def test_happy_path_queues_and_stamps_heartbeat(
        self, push_app, client, db,
    ):
        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )
        # Configure clientState shared secret (install-wide).
        push_app.state.secrets.set(
            "office365_clientstate", "shared-secret",
        )
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "clientState": "shared-secret",
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 200
        assert resp.json()["queued"] == 1
        # Queue should hold the demuxed item.
        item = push_app.state.push_queue.get_nowait()
        assert item["provider"] == "office365"
        assert item["account_id"] == 42
        assert item["subscription_id"] == "sub-42"
        assert item["message_id"] == "msg-1"
        # Heartbeat got stamped.
        row = get_o365_subscription(db, 42)
        assert row["last_notification_at"] is not None

    def test_client_state_mismatch_returns_401(self, push_app, client, db):
        """#132 — wrong clientState fails closed with HTTP 401, not a
        silent 200+drop. Bumps the mismatch counter and writes an
        ``o365_webhook_auth`` audit row so a flood of forged
        notifications is visible."""
        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )
        push_app.state.secrets.set(
            "office365_clientstate", "the-real-secret",
        )
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "clientState": "the-WRONG-secret",
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "clientstate_mismatch"
        assert push_app.state.push_queue.qsize() == 0
        assert push_app.state.metrics.get(
            "office365_push.client_state_mismatch"
        ) == 1
        # Audit row landed.
        row = db.execute(
            "SELECT event_type, outcome, detail FROM auth_events "
            "WHERE event_type = 'o365_webhook_auth' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        assert row["outcome"] == "failure"
        assert "clientstate_mismatch" in row["detail"]

    def test_missing_client_state_returns_401_when_secret_stored(
        self, push_app, client, db,
    ):
        """#132 — empty/missing clientState field on a delivery for an
        account that DOES have a stored secret is the unauthorized
        case. 401, not 200."""
        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )
        push_app.state.secrets.set(
            "office365_clientstate:42", "real-secret",
        )
        # No clientState field at all.
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "clientstate_mismatch"
        assert push_app.state.push_queue.qsize() == 0

    def test_no_secret_configured_returns_401(
        self, push_app, client, db,
    ):
        """#132 — pre-fix subscriptions registered before auto-generate
        landed have no stored clientState. Receiver MUST fail closed
        rather than skipping the compare; operator re-registers via
        Stop+Start to mint a fresh secret."""
        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )
        # No secret set anywhere.
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "clientState": "whatever",
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "clientstate_unset"
        assert push_app.state.push_queue.qsize() == 0
        assert push_app.state.metrics.get(
            "office365_push.client_state_unset"
        ) == 1

    def test_per_account_clientstate_overrides_install(
        self, push_app, client, db,
    ):
        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )
        push_app.state.secrets.set(
            "office365_clientstate", "install-default",
        )
        push_app.state.secrets.set(
            "office365_clientstate:42", "per-account-override",
        )
        # Install secret would have matched — per-account must win.
        # Delivery carrying install-default is rejected (401).
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "clientState": "install-default",
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 401
        assert resp.json()["reason"] == "clientstate_mismatch"

    def test_empty_value_list_returns_200(self, push_app, client, db):
        resp = client.post("/webhooks/office365", json={"value": []})
        assert resp.status_code == 200
        assert resp.json()["queued"] == 0

    def test_bad_json_returns_400(self, push_app, client, db):
        resp = client.post(
            "/webhooks/office365",
            content=b"not-valid-json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400

    def test_correct_clientstate_after_auto_gen_round_trips(
        self, push_app, client, db,
    ):
        """End-to-end check that the registration auto-gen path stores
        a value the receiver subsequently accepts.

        Mirrors what /accounts/<id>/o365-push/start does (without the
        Graph create_subscription call): generate via the helper, then
        send a webhook with the same value as clientState. Receiver
        must read the stored secret and queue the work."""
        from email_triage.web.routers.ui import (
            _o365_subscription_create_args,
        )

        _seed_account(db, account_id=42)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=42, subscription_id="sub-42",
            expiration_at=future,
        )

        # No clientstate seeded — helper must auto-generate AND store.
        # Build a minimal Request stub via the TestClient app state.
        class _Req:
            def __init__(self, app):
                self.app = app

        # ``_o365_subscription_create_args`` reads from get_config /
        # get_secrets which both read from request.app.state.
        push_app.state.config.push.public_url = "https://host.tailnet"
        webhook_url, client_state = _o365_subscription_create_args(
            _Req(push_app), 42,
        )
        assert webhook_url.endswith("/webhooks/office365")
        assert client_state, "auto-gen produced empty clientState"
        # Stored under per-account key.
        assert push_app.state.secrets.get(
            "office365_clientstate:42",
        ) == client_state

        # Now drive a delivery using that exact value — must queue.
        resp = client.post(
            "/webhooks/office365",
            json={"value": [{
                "subscriptionId": "sub-42",
                "clientState": client_state,
                "resource": "Users/u/Messages/msg-1",
                "changeType": "created",
                "resourceData": {"id": "msg-1"},
            }]},
        )
        assert resp.status_code == 200
        assert resp.json()["queued"] == 1

    def test_clientstate_helper_idempotent(self, push_app, client, db):
        """Calling the helper twice for the same account returns the
        same generated value — Stop+Start round-trips don't churn the
        secret. (If the operator wants a fresh value, they delete the
        per-account secret manually before Start.)"""
        from email_triage.web.routers.ui import (
            _o365_subscription_create_args,
        )

        class _Req:
            def __init__(self, app):
                self.app = app

        push_app.state.config.push.public_url = "https://host.tailnet"
        _, cs1 = _o365_subscription_create_args(_Req(push_app), 99)
        _, cs2 = _o365_subscription_create_args(_Req(push_app), 99)
        assert cs1 == cs2
        assert cs1, "auto-gen produced empty clientState"


# ---------------------------------------------------------------------------
# Provider create_subscription round-trip (mocked Graph)
# ---------------------------------------------------------------------------


def _make_provider():
    """Mirror the helper in tests/test_providers/test_office365.py.

    Local copy so this suite doesn't import a sibling package's
    private fixture. ``HAS_MSAL`` may be False in the test env;
    we patch it on so the constructor doesn't bail.
    """
    from email_triage.providers import office365 as o365_mod
    from email_triage.providers.office365 import Office365Provider

    o365_mod.HAS_MSAL = True
    return Office365Provider(
        client_id="test-client-id",
        tenant_id="test-tenant-id",
        token_cache_path="/tmp/test_cache.json",
    )


class TestO365SubscriptionRoundTrip:
    @pytest.mark.asyncio
    async def test_create_then_persist(self, db):
        """Calling create_subscription then upsert_o365_subscription is the
        wiring the Start-push handler will perform once UI lands. Mock the
        Graph POST and confirm the row stored matches the response."""
        _seed_account(db, account_id=7)

        provider = _make_provider()
        graph_response = {
            "id": "sub-graph-7",
            "expirationDateTime": "2026-05-10T10:00:00.0000000Z",
            "resource": "me/mailFolders('Inbox')/messages",
            "changeType": "created",
        }
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.return_value = graph_response
            data = await provider.create_subscription(
                webhook_url="https://host.tailnet/webhooks/office365",
                client_state="abc",
            )
        assert data["id"] == "sub-graph-7"

        # Persist to DB (mirrors what the route handler will do).
        upsert_o365_subscription(
            db,
            account_id=7,
            subscription_id=data["id"],
            expiration_at=data["expirationDateTime"],
        )
        row = get_o365_subscription(db, 7)
        assert row is not None
        assert row["subscription_id"] == "sub-graph-7"
        assert row["expiration_at"] == "2026-05-10T10:00:00.0000000Z"
        # Lookup-by-subscription_id is the demux key.
        by_id = get_o365_subscription_by_subscription_id(db, "sub-graph-7")
        assert by_id is not None
        assert by_id["account_id"] == 7

    @pytest.mark.asyncio
    async def test_renewal_failure_surfaces_error(self, db):
        """Failure on the renewer path bumps error_count + flips status,
        which is what the renewer / health surface reads."""
        _seed_account(db, account_id=9)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=9, subscription_id="sub-9",
            expiration_at=future,
        )

        provider = _make_provider()
        with patch.object(
            provider, "_request", new_callable=AsyncMock,
        ) as mock_req:
            mock_req.side_effect = RuntimeError("Graph 503")
            try:
                await provider.renew_subscription("sub-9")
            except RuntimeError as e:
                record_o365_subscription_error(
                    db, account_id=9, error_text=str(e),
                )
        row = get_o365_subscription(db, 9)
        assert row["status"] == "errored"
        assert row["error_count"] == 1
        assert "Graph 503" in (row["error_last"] or "")


# ---------------------------------------------------------------------------
# /health surfacing (#66)
# ---------------------------------------------------------------------------


class TestHealthSurfaceO365Push:
    def test_zero_subscriptions_block(self, client, db, admin_user):
        from email_triage.web.auth import (
            SESSION_COOKIE_NAME, create_session_token,
        )
        token = create_session_token(
            "test-session-secret-for-signing",
            admin_user["email"], admin_user["role"],
        )
        client.cookies.set(SESSION_COOKIE_NAME, token)
        resp = client.get("/health/detail")
        assert resp.status_code == 200
        body = resp.json()
        assert "office365_push" in body
        assert body["office365_push"]["total"] == 0
        assert (
            body["office365_push"]["accounts_with_active_subscriptions"]
            == 0
        )
        # Mirrored under watchers for back-compat.
        assert "office365_push" in body["watchers"]

    def test_active_and_expiring_counts(self, client, db, admin_user):
        from email_triage.web.auth import (
            SESSION_COOKIE_NAME, create_session_token,
        )
        # Three accounts: one healthy, one expiring soon, one expired.
        _seed_account(db, account_id=11, name="Healthy")
        _seed_account(db, account_id=12, name="Expiring")
        _seed_account(db, account_id=13, name="Expired")
        far = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        soon = (
            datetime.now(timezone.utc) + timedelta(hours=4)
        ).isoformat()
        past = (
            datetime.now(timezone.utc) - timedelta(hours=1)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=11, subscription_id="sub-11",
            expiration_at=far,
        )
        upsert_o365_subscription(
            db, account_id=12, subscription_id="sub-12",
            expiration_at=soon,
        )
        upsert_o365_subscription(
            db, account_id=13, subscription_id="sub-13",
            expiration_at=past,
        )

        token = create_session_token(
            "test-session-secret-for-signing",
            admin_user["email"], admin_user["role"],
        )
        client.cookies.set(SESSION_COOKIE_NAME, token)
        resp = client.get("/health/detail")
        # 503-on-degraded is fine; we just need the body shape.
        body = resp.json()
        block = body["office365_push"]
        assert block["total"] == 3
        # Healthy + expiring count as active (still in the future).
        assert block["accounts_with_active_subscriptions"] == 2
        assert block["expiring_in_24h"] == 1
        assert block["errored"] == 1

    def test_errored_status_surfaces_in_block(
        self, client, db, admin_user,
    ):
        from email_triage.web.auth import (
            SESSION_COOKIE_NAME, create_session_token,
        )
        _seed_account(db, account_id=21)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=21, subscription_id="sub-21",
            expiration_at=future,
        )
        record_o365_subscription_error(
            db, account_id=21, error_text="Graph 401",
        )
        token = create_session_token(
            "test-session-secret-for-signing",
            admin_user["email"], admin_user["role"],
        )
        client.cookies.set(SESSION_COOKIE_NAME, token)
        resp = client.get("/health/detail")
        body = resp.json()
        block = body["office365_push"]
        assert block["total"] == 1
        # Errored row shows up only in errored, never in active.
        assert block["errored"] == 1
        assert block["accounts_with_active_subscriptions"] == 0


# ---------------------------------------------------------------------------
# Daily-briefing digest line (#66)
# ---------------------------------------------------------------------------


class TestDailyDigestO365Line:
    def test_text_renderer_includes_o365_line(self, db, app):
        """The text-mode digest gets a 'Office 365 Graph subscriptions'
        line when at least one row exists."""
        from email_triage.config import TriageConfig
        from email_triage.web.daily_health import (
            _render_text, gather_health_state,
        )

        _seed_account(db, account_id=33)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=33, subscription_id="sub-33",
            expiration_at=future,
        )

        config = TriageConfig()
        config.health_email.include_pubsub = True
        state = gather_health_state(db, config, watcher_manager=None)
        assert "office365_push" in state
        assert state["office365_push"]["total"] == 1
        assert (
            state["office365_push"][
                "accounts_with_active_subscriptions"
            ]
            == 1
        )

        text = _render_text(state, config)
        assert "Office 365 Graph subscriptions" in text

    def test_errored_rows_bump_attention_reasons(self, db):
        from email_triage.config import TriageConfig
        from email_triage.web.daily_health import gather_health_state

        _seed_account(db, account_id=34)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=34, subscription_id="sub-34",
            expiration_at=future,
        )
        record_o365_subscription_error(
            db, account_id=34, error_text="Graph permission denied",
        )
        config = TriageConfig()
        config.health_email.include_pubsub = True
        state = gather_health_state(db, config, watcher_manager=None)
        joined = " ".join(state["attention_reasons"])
        assert "Office 365 push subscription" in joined
        assert "errored" in joined or "expired" in joined
        # Attention copy must surface the account name, not bare id —
        # see feedback_no_account_id_alone.md. Seeded name is
        # "Test O365" with id 34.
        assert "Test O365" in joined  # operator-readable name
        assert "id 34" in joined      # numeric id as tiebreaker


# ---------------------------------------------------------------------------
# Dashboard chip (#66)
# ---------------------------------------------------------------------------


class TestDashboardO365Chip:
    def test_chip_off_when_no_subscriptions(self, client, db):
        from email_triage.web.routers.ui import _dashboard_health_chips
        # No O365 rows.
        chips = _dashboard_health_chips(
            type("_R", (), {"app": client.app})(), db,
        )
        assert "office365_push" in chips
        assert chips["office365_push"]["total"] == 0
        assert chips["office365_push"]["ok"] is True

    def test_chip_active_when_healthy(self, client, db):
        from email_triage.web.routers.ui import _dashboard_health_chips
        _seed_account(db, account_id=51)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=51, subscription_id="sub-51",
            expiration_at=future,
        )
        chips = _dashboard_health_chips(
            type("_R", (), {"app": client.app})(), db,
        )
        block = chips["office365_push"]
        assert block["total"] == 1
        assert block["active"] == 1
        assert block["ok"] is True
        assert "Push active" in block["label"]

    def test_chip_warning_when_errored(self, client, db):
        from email_triage.web.routers.ui import _dashboard_health_chips
        _seed_account(db, account_id=52)
        future = (
            datetime.now(timezone.utc) + timedelta(days=2)
        ).isoformat()
        upsert_o365_subscription(
            db, account_id=52, subscription_id="sub-52",
            expiration_at=future,
        )
        record_o365_subscription_error(
            db, account_id=52, error_text="Graph 401",
        )
        chips = _dashboard_health_chips(
            type("_R", (), {"app": client.app})(), db,
        )
        block = chips["office365_push"]
        assert block["errored"] == 1
        assert block["ok"] is False
