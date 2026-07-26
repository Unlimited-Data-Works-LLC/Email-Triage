"""End-to-end fire integration coverage for the per-target reshaper.

Companion to ``tests/test_webhook_render_for_target.py`` (unit-level, hits
``render_for_target`` directly) and ``tests/test_webhook_ssot_pins.py``
(structural, AST-pins the seam). This module exercises the ENTIRE fire
path — ``EventDispatcher.fire(...) -> render_for_target -> HMAC sign ->
httpx POST`` — against ``httpx.MockTransport`` so the exact wire bytes
+ headers + signature that the receiver would observe are asserted.

Why a dedicated integration file: the unit tests prove ``render_for_target``
produces the right shape given an envelope; the SSOT pin proves ``_deliver``
routes through it; NEITHER proves the whole fan-out sequence emits those
exact bytes over the wire. Regressions where the bytes are correctly
rendered but a wrapping seam (``sign_payload`` argument order,
``client.post(content=...)`` vs ``json=``, header merge order) mutates them
would slip past the other two layers. This module closes that gap for the
5 built-in target-types + the ``custom`` envelope-verbatim compat case.

Aligned with  spec_per_target_body_templating_2026-07-14 Drive D.
"""

from __future__ import annotations

import json

import httpx
import pytest

from email_triage.config import WebhookTarget
from email_triage.web.events import EventDispatcher, sign_payload, verify_signature


# --- helpers ---------------------------------------------------------------


class _MockLazyClient:
    """Drop-in for ``LazyHttpClient`` that yields a preassembled
    MockTransport-backed ``httpx.AsyncClient``. Attached onto
    ``dispatcher._http`` after construction so ``fire()`` reaches
    ``_deliver`` through the exact same seam a production run does.
    """

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def get(self) -> httpx.AsyncClient:
        return self._client

    async def aclose(self) -> None:
        await self._client.aclose()


def _make_dispatcher(targets: list[WebhookTarget], handler) -> EventDispatcher:
    """Build a dispatcher wired to a MockTransport that runs ``handler``
    on every request. ``allow_external=True`` bypasses the deny-by-default
    egress gate since the invalid TLD used by the test URLs would
    otherwise be filtered as external.
    """
    d = EventDispatcher(targets=targets, allow_external=True)
    d._http = _MockLazyClient(  # noqa: SLF001 — test-only seam override
        httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    return d


ENVELOPE_DATA = {
    "flow_id": "flow-abc",
    "sender": "alice@example.com",
    "subject": "quarterly numbers",
    "category": "billing",
    "timestamp": "2026-07-14T20:00:00+00:00",
    "summary": "[billing] from alice@example.com: quarterly numbers",
    "pd_routing_key": "PD-KEY-XYZ",
}


# --- Slack ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_slack_posts_slack_text_shape():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, json={"ok": True})

    target = WebhookTarget(
        url="https://hooks.slack.example/services/T/B/S",
        events=["notification"],
        secret_key="slack-signing-secret",
        target_type="slack",
    )
    d = _make_dispatcher([target], handler)
    results = await d.fire("notification", dict(ENVELOPE_DATA))

    assert results == [{"url": target.url, "status": 200, "success": True}]
    assert len(captured) == 1
    body = json.loads(captured[0].content)
    assert body == {"text": "[billing] quarterly numbers from alice@example.com"}
    # HMAC signs the RENDERED bytes, not any envelope wrapping.
    sig = captured[0].headers["x-signature-256"].removeprefix("sha256=")
    assert verify_signature(captured[0].content, "slack-signing-secret", sig)


# --- Discord ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_discord_posts_content_shape():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(204)  # Discord returns 204 on success

    target = WebhookTarget(
        url="https://discord.example/api/webhooks/id/token",
        events=["notification"],
        target_type="discord",
    )
    d = _make_dispatcher([target], handler)
    results = await d.fire("notification", dict(ENVELOPE_DATA))

    assert results == [{"url": target.url, "status": 204, "success": True}]
    body = json.loads(captured[0].content)
    assert body == {"content": "[billing] quarterly numbers from alice@example.com"}


# --- Teams ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_teams_posts_messagecard_shape():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    target = WebhookTarget(
        url="https://tenant.example/webhookb2/id/IncomingWebhook/hash",
        events=["notification"],
        target_type="teams",
    )
    d = _make_dispatcher([target], handler)
    await d.fire("notification", dict(ENVELOPE_DATA))

    body = json.loads(captured[0].content)
    assert body["@type"] == "MessageCard"
    assert body["@context"] == "http://schema.org/extensions"
    assert body["text"] == "[billing] quarterly numbers"


# --- PagerDuty --------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_pagerduty_posts_events_v2_shape():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(202, json={"status": "success"})

    target = WebhookTarget(
        url="https://events.pagerduty.example/v2/enqueue",
        events=["notification"],
        target_type="pagerduty",
    )
    d = _make_dispatcher([target], handler)
    await d.fire("notification", dict(ENVELOPE_DATA))

    body = json.loads(captured[0].content)
    assert body["routing_key"] == "PD-KEY-XYZ"
    assert body["event_action"] == "trigger"
    assert body["payload"] == {
        "summary": "[billing] quarterly numbers",
        "source": "email-triage",
        "severity": "info",
    }


@pytest.mark.asyncio
async def test_fire_pagerduty_missing_routing_key_drops_delivery():
    """Fail-closed required_fields — PagerDuty without ``pd_routing_key``
    must NOT hit the wire (else the receiver 400s + the operator sees a
    silent-failure event class instead of an actionable drop log)."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    target = WebhookTarget(
        url="https://events.pagerduty.example/v2/enqueue",
        events=["notification"],
        target_type="pagerduty",
    )
    d = _make_dispatcher([target], handler)
    data = dict(ENVELOPE_DATA)
    data["pd_routing_key"] = ""
    results = await d.fire("notification", data)

    assert captured == []  # never touched the wire
    assert len(results) == 1
    assert results[0]["success"] is False
    assert results[0]["dropped"] == "required_field_missing"


# --- Opsgenie ---------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_opsgenie_posts_alert_shape_and_geniekey_header():
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(202, json={"result": "Request will be processed"})

    target = WebhookTarget(
        url="https://api.opsgenie.example/v2/alerts",
        events=["notification"],
        secret_key="opsgenie-genie-key-abc123",
        target_type="opsgenie",
    )
    d = _make_dispatcher([target], handler)
    await d.fire("notification", dict(ENVELOPE_DATA))

    body = json.loads(captured[0].content)
    assert body == {
        "message": "[billing] quarterly numbers",
        "alias": "flow-abc",
    }
    # Registry declares Authorization: GenieKey {{secret}} — substituted
    # from resolved_secret in the HEADER-context render path only.
    assert captured[0].headers["authorization"] == "GenieKey opsgenie-genie-key-abc123"


# --- Custom (backward-compat envelope) --------------------------------------


@pytest.mark.asyncio
async def test_fire_custom_no_template_posts_envelope_verbatim():
    """The pre-#413 wire — a canonical-JSON envelope. Preserves the HMAC
    contract every operator relay was written against."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    target = WebhookTarget(
        url="https://relay.example/hook",
        events=["notification"],
        secret_key="relay-signing-secret",
        target_type="custom",
    )
    d = _make_dispatcher([target], handler)
    await d.fire("notification", dict(ENVELOPE_DATA))

    body = json.loads(captured[0].content)
    assert set(body.keys()) == {"event", "timestamp", "data"}
    assert body["event"] == "notification"
    assert body["data"] == ENVELOPE_DATA
    # Signature verifies against the exact wire bytes.
    sig = captured[0].headers["x-signature-256"].removeprefix("sha256=")
    assert verify_signature(captured[0].content, "relay-signing-secret", sig)


# --- HIPAA lock -------------------------------------------------------------


@pytest.mark.asyncio
async def test_fire_hipaa_lock_replaces_body_regardless_of_target_type():
    """A HIPAA fire ships the minimal ``{event, category, timestamp,
    flow_id}`` shape over the wire — REGARDLESS of the operator-picked
    target_type + body_template. Defense-in-depth atop _FORBIDDEN_KEYS."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    target = WebhookTarget(
        url="https://hooks.slack.example/services/T/B/S",
        events=["notification"],
        secret_key="slack-signing-secret",
        target_type="slack",
        body_template='{"text":"OPERATOR PHI LEAK ATTEMPT {{data.subject}}"}',
    )
    d = _make_dispatcher([target], handler)
    await d.fire(
        "notification", dict(ENVELOPE_DATA), is_hipaa=True,
    )

    body = json.loads(captured[0].content)
    # Minimal shape: event/category/timestamp/flow_id only. No subject,
    # no sender, no summary — even though the operator template asked
    # for {{data.subject}}, HIPAA lock IGNORES the template.
    assert set(body.keys()) == {"event", "category", "timestamp", "flow_id"}
    assert "subject" not in captured[0].content.decode("utf-8")
    assert "alice@example.com" not in captured[0].content.decode("utf-8")


# --- HMAC signs rendered bytes, not envelope --------------------------------


@pytest.mark.asyncio
async def test_hmac_signs_rendered_bytes_not_envelope_for_slack():
    """The signature the receiver verifies MUST be over the exact bytes
    it observes (Slack ``{"text":...}``), NOT over our internal envelope.
    Otherwise every non-``custom`` target-type breaks signature check on
    the receiver side. Explicit assertion so a future refactor of
    ``_deliver`` (e.g. moving sign_payload above the reshape) is caught."""
    captured: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    target = WebhookTarget(
        url="https://hooks.slack.example/services/T/B/S",
        events=["notification"],
        secret_key="slack-signing-secret",
        target_type="slack",
    )
    d = _make_dispatcher([target], handler)
    await d.fire("notification", dict(ENVELOPE_DATA))

    wire_bytes = captured[0].content
    sig = captured[0].headers["x-signature-256"].removeprefix("sha256=")
    # Positive: signature validates over the wire bytes.
    assert verify_signature(wire_bytes, "slack-signing-secret", sig)
    # Negative: signature does NOT validate over the envelope shape.
    envelope_bytes = json.dumps(
        {"event": "notification", "data": ENVELOPE_DATA}, sort_keys=True,
    ).encode("utf-8")
    assert not verify_signature(envelope_bytes, "slack-signing-secret", sig)
