"""Tests for outbound event webhooks with HMAC-SHA256 signing."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from email_triage.config import WebhookTarget
from email_triage.web.events import EventDispatcher, sign_payload, verify_signature


class TestSignature:
    def test_sign_and_verify(self):
        payload = b'{"event": "test"}'
        secret = "my-secret"
        sig = sign_payload(payload, secret)
        assert verify_signature(payload, secret, sig) is True

    def test_verify_bad_signature(self):
        payload = b'{"event": "test"}'
        assert verify_signature(payload, "secret", "bad-sig") is False

    def test_different_payloads_different_sigs(self):
        secret = "shared"
        s1 = sign_payload(b"payload-a", secret)
        s2 = sign_payload(b"payload-b", secret)
        assert s1 != s2

    def test_different_secrets_different_sigs(self):
        payload = b"same-payload"
        s1 = sign_payload(payload, "secret-1")
        s2 = sign_payload(payload, "secret-2")
        assert s1 != s2


class TestEventDispatcher:
    def test_no_targets(self):
        dispatcher = EventDispatcher(targets=[])
        # Should be empty — no matching targets.
        assert dispatcher._matching_targets("flow.classified") == []

    def test_matching_targets(self):
        # Non-local URLs require allow_external=True (#60 deny-by-default).
        targets = [
            WebhookTarget(url="http://a", events=["flow.classified", "flow.finished"]),
            WebhookTarget(url="http://b", events=["flow.failed"]),
            WebhookTarget(url="http://c", events=[]),  # Subscribe to all.
        ]
        dispatcher = EventDispatcher(targets=targets, allow_external=True)

        matched = dispatcher._matching_targets("flow.classified")
        urls = [t.url for t in matched]
        assert "http://a" in urls
        assert "http://c" in urls  # Empty events = all.
        assert "http://b" not in urls

    def test_matching_all_events(self):
        targets = [
            WebhookTarget(url="http://catch-all", events=[]),
        ]
        dispatcher = EventDispatcher(targets=targets, allow_external=True)

        for event in ["flow.classified", "flow.finished", "flow.failed", "push.received"]:
            matched = dispatcher._matching_targets(event)
            assert len(matched) == 1

    def test_external_url_dropped_by_default(self):
        """#60 — external URLs are filtered out unless allow_external=True.

        Cover three cases without depending on any operator-specific
        domain suffix:
          * external host (filtered out)
          * RFC1918 private IP (always-on local signal)
          * localhost (always-on local signal)
        Operator-extensible suffixes are exercised by
        ``test_external_url_local_suffix_extends_set`` below.
        """
        targets = [
            WebhookTarget(url="http://api.example.com/hook", events=[]),
            WebhookTarget(url="http://192.168.1.50:9000/hook", events=[]),
            WebhookTarget(url="http://localhost:9999/hook", events=[]),
        ]
        dispatcher = EventDispatcher(targets=targets)  # allow_external=False default
        matched = dispatcher._matching_targets("flow.classified")
        urls = [t.url for t in matched]
        assert "http://api.example.com/hook" not in urls
        assert "http://192.168.1.50:9000/hook" in urls
        assert "http://localhost:9999/hook" in urls

    def test_external_url_local_suffix_extends_set(self):
        """An operator-supplied suffix in local_url_suffixes makes
        matching hostnames count as local. Without the suffix, the
        same URL is filtered."""
        targets = [WebhookTarget(url="http://box.lab.test/hook", events=[])]
        # Default deny.
        d = EventDispatcher(targets=targets)
        assert d._matching_targets("flow.classified") == []
        # With suffix configured, same URL passes through as local.
        d = EventDispatcher(targets=targets, local_url_suffixes=[".lab.test"])
        matched = d._matching_targets("flow.classified")
        assert [t.url for t in matched] == ["http://box.lab.test/hook"]

    def test_external_url_allowed_when_flag_set(self):
        targets = [WebhookTarget(url="http://api.example.com/hook", events=[])]
        dispatcher = EventDispatcher(targets=targets, allow_external=True)
        matched = dispatcher._matching_targets("flow.classified")
        assert len(matched) == 1

    async def test_fire_success(self):
        target = WebhookTarget(url="http://hook.test/callback", events=["test.event"], secret_key="test-secret")
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            results = await dispatcher.fire("test.event", {"key": "value"})

        assert len(results) == 1
        assert results[0]["success"] is True
        assert results[0]["status"] == 200

        # Verify the POST was called with correct headers.
        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert headers["Content-Type"] == "application/json"
        assert headers["X-Event-Type"] == "test.event"
        assert "X-Signature-256" in headers
        assert headers["X-Signature-256"].startswith("sha256=")

    async def test_fire_with_payload_verification(self):
        """Verify the signature matches the actual payload sent."""
        target = WebhookTarget(url="http://hook.test/cb", events=["flow.classified"], secret_key="verify-me")
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        captured_payload = None
        captured_signature = None

        mock_response = MagicMock()
        mock_response.status_code = 200

        async def capture_post(url, content=None, headers=None, **kwargs):
            nonlocal captured_payload, captured_signature
            captured_payload = content
            captured_signature = headers.get("X-Signature-256", "").replace("sha256=", "")
            return mock_response

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post = capture_post
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            await dispatcher.fire("flow.classified", {"flow_id": "abc", "category": "urgent"})

        assert captured_payload is not None
        assert captured_signature is not None
        # Verify the signature matches.
        assert verify_signature(captured_payload, "verify-me", captured_signature)

        # Verify the payload structure.
        payload = json.loads(captured_payload)
        assert payload["event"] == "flow.classified"
        assert payload["data"]["flow_id"] == "abc"
        assert "timestamp" in payload

    async def test_fire_delivery_failure(self):
        """Delivery failure should not raise — returns error info."""
        target = WebhookTarget(url="http://unreachable.test/hook", events=["test"])
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("Connection refused")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            results = await dispatcher.fire("test", {"data": "value"})

        assert len(results) == 1
        assert results[0]["success"] is False
        assert "Connection refused" in results[0]["error"]

    async def test_fire_no_matching_targets(self):
        target = WebhookTarget(url="http://hook.test", events=["flow.finished"])
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        results = await dispatcher.fire("flow.classified", {})
        assert results == []

    async def test_fire_no_signature_without_secret(self):
        """No signature header when secret_key is empty."""
        target = WebhookTarget(url="http://hook.test/cb", events=["test"], secret_key="")
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            await dispatcher.fire("test", {})

        call_kwargs = mock_client.post.call_args
        headers = call_kwargs.kwargs.get("headers") or call_kwargs[1].get("headers", {})
        assert "X-Signature-256" not in headers

    async def test_fire_multiple_targets(self):
        targets = [
            WebhookTarget(url="http://a/hook", events=["test"]),
            WebhookTarget(url="http://b/hook", events=["test"]),
        ]
        dispatcher = EventDispatcher(targets=targets, allow_external=True)

        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_client

            results = await dispatcher.fire("test", {"data": "x"})

        assert len(results) == 2
        assert all(r["success"] for r in results)

    def test_resolve_secret_from_provider(self):
        mock_secrets = MagicMock()
        mock_secrets.get.return_value = "resolved-secret"

        target = WebhookTarget(url="http://hook", secret_key="WEBHOOK_SECRET")
        dispatcher = EventDispatcher(targets=[target], secrets_provider=mock_secrets)

        secret = dispatcher._resolve_secret(target)
        assert secret == "resolved-secret"
        mock_secrets.get.assert_called_once_with("WEBHOOK_SECRET")

    def test_resolve_secret_fallback(self):
        """Without a secrets provider, secret_key is used directly."""
        target = WebhookTarget(url="http://hook", secret_key="direct-secret")
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        secret = dispatcher._resolve_secret(target)
        assert secret == "direct-secret"

    def test_resolve_secret_empty(self):
        target = WebhookTarget(url="http://hook", secret_key="")
        dispatcher = EventDispatcher(targets=[target], allow_external=True)

        secret = dispatcher._resolve_secret(target)
        assert secret == ""


# ---------------------------------------------------------------------------
# is_in_quiet_hours / fire_triage_completed
# ---------------------------------------------------------------------------

from datetime import datetime, timezone
from email_triage.config import PushConfig, TriageConfig
from email_triage.web.events import (
    fire_triage_completed,
    get_openclaw_quiet_settings,
    is_in_quiet_hours,
)


class TestQuietHours:
    def test_inside_simple_window(self):
        # Window 09:00-17:00. 12:00 is inside.
        now = datetime(2026, 4, 18, 12, 0, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "09:00", "17:00") is True

    def test_outside_simple_window(self):
        now = datetime(2026, 4, 18, 8, 0, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "09:00", "17:00") is False
        now = datetime(2026, 4, 18, 17, 0, tzinfo=timezone.utc)
        # End is exclusive.
        assert is_in_quiet_hours(now, "09:00", "17:00") is False

    def test_cross_midnight_late_night(self):
        # 22:00 - 08:00. 23:30 is inside.
        now = datetime(2026, 4, 18, 23, 30, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "22:00", "08:00") is True

    def test_cross_midnight_early_morning(self):
        # 22:00 - 08:00. 03:00 is inside.
        now = datetime(2026, 4, 18, 3, 0, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "22:00", "08:00") is True

    def test_cross_midnight_outside(self):
        # 22:00 - 08:00. 12:00 is outside.
        now = datetime(2026, 4, 18, 12, 0, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "22:00", "08:00") is False

    def test_malformed_falls_open(self):
        now = datetime(2026, 4, 18, 12, 0, tzinfo=timezone.utc)
        assert is_in_quiet_hours(now, "garbage", "17:00") is False


def _hipaa_acct(hipaa=False):
    return {"id": 1, "name": "Test", "hipaa": hipaa, "created_under_system_hipaa": False}


def _push_cfg(enabled=True):
    return TriageConfig(push=PushConfig(openclaw_webhook_enabled=enabled))


class TestFireTriageCompleted:
    async def test_fires_on_happy_path(self, db, admin_user):
        # Need an account row so settings table FKs are satisfied.
        from email_triage.web.db import set_setting
        acct = _hipaa_acct()
        dispatcher = EventDispatcher(targets=[
            WebhookTarget(url="http://hook", events=["triage.completed"], secret_key=""),
        ])
        dispatcher.fire = AsyncMock(return_value=[{"success": True}])
        run = {
            "run_id": "r1", "query": "is:unread",
            "total_messages": 2, "results": [{}, {}], "errors": [],
            "elapsed_secs": 0.5,
        }
        ok = await fire_triage_completed(dispatcher, db, _push_cfg(), acct, run, trigger="manual")
        assert ok is True
        dispatcher.fire.assert_awaited_once()
        event_name, payload = dispatcher.fire.await_args.args
        assert event_name == "triage.completed"
        assert payload["account_id"] == 1
        assert payload["total_messages"] == 2
        # Lean payload — no sender/subject/body fields.
        assert "results" not in payload
        assert "sender" not in payload

    async def test_skips_hipaa_account(self, db):
        dispatcher = EventDispatcher()
        dispatcher.fire = AsyncMock()
        ok = await fire_triage_completed(
            dispatcher, db, _push_cfg(), _hipaa_acct(hipaa=True), {"run_id": "x"},
        )
        assert ok is False
        dispatcher.fire.assert_not_awaited()

    async def test_skips_when_kill_switch_off(self, db):
        dispatcher = EventDispatcher()
        dispatcher.fire = AsyncMock()
        ok = await fire_triage_completed(
            dispatcher, db, _push_cfg(enabled=False), _hipaa_acct(), {"run_id": "x"},
        )
        assert ok is False
        dispatcher.fire.assert_not_awaited()

    async def test_skips_when_paused(self, db):
        from email_triage.web.db import set_setting
        set_setting(db, "openclaw_quiet:1", {"enabled": True, "paused": True})
        dispatcher = EventDispatcher()
        dispatcher.fire = AsyncMock()
        ok = await fire_triage_completed(
            dispatcher, db, _push_cfg(), _hipaa_acct(), {"run_id": "x"},
        )
        assert ok is False

    async def test_skips_in_quiet_hours(self, db, monkeypatch):
        from email_triage.web.db import set_setting
        from email_triage.web import events as events_mod
        set_setting(db, "openclaw_quiet:1", {
            "enabled": True, "paused": False,
            "start_utc": "00:00", "end_utc": "23:59",
        })
        dispatcher = EventDispatcher()
        dispatcher.fire = AsyncMock()
        ok = await fire_triage_completed(
            dispatcher, db, _push_cfg(), _hipaa_acct(), {"run_id": "x"},
        )
        # Window covers nearly the whole day → almost certainly inside.
        assert ok is False

    async def test_no_dispatcher_is_no_op(self, db):
        ok = await fire_triage_completed(None, db, _push_cfg(), _hipaa_acct(), {})
        assert ok is False
