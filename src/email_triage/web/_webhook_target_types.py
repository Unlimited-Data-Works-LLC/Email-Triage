"""Registry of built-in outbound-webhook target types (SSOT).

Consumed by:

* ``web/_webhook_template.py::render_for_target`` — default template
  lookup when the target has no operator override.
* ``web/_webhook_template.py::render_headers_for_target`` — per-type
  required headers (Opsgenie ``GenieKey``, …).
* ``config.py::_parse_webhooks`` — validates the operator-supplied
  ``target_type`` against this registry at load time.
* (Drive C) ``web/routers/integrations.py`` — populates the admin
  wizard dropdown + auto-fills URL / template placeholders.

Each entry is a self-contained dict; the module-level ``TARGET_TYPES``
mapping is the ONE public surface. Adding a new receiver = adding one
entry (+ one unit test in ``tests/test_webhook_render_for_target.py``).

Envelope shape available to every template (via ``{{data.field}}`` and
``{{event}}`` / ``{{timestamp}}``)::

    {
        "event": "triage.completed",
        "timestamp": "<UTC ISO8601>",
        "data": {
            "flow_id": "...",
            "sender": "...",       # HIPAA mode: absent
            "subject": "...",      # HIPAA mode: absent
            "category": "...",
            "timestamp": "...",
            "summary": "...",
            "pd_routing_key": "...",  # per-target extension for PagerDuty
        },
    }
"""

from __future__ import annotations

from typing import Any


TARGET_TYPES: dict[str, dict[str, Any]] = {
    "custom": {
        "label": "Custom (envelope + HMAC signature)",
        "url_shape_hint": "https://your-relay.example.com/webhook",
        "required_headers": {},
        "default_template": None,  # None → emit our envelope verbatim
        # ``required_fields`` = envelope fields under ``data.`` that MUST
        # be present + non-empty; a missing field refuses the send (Prime
        # Directive #8, fail-closed). Custom is envelope-passthrough so
        # has no per-field requirement.
        "required_fields": [],
        "docs_url": None,
    },
    "slack": {
        "label": "Slack incoming webhook",
        "url_shape_hint": "https://hooks.slack.com/services/T…/B…/…",
        "required_headers": {},
        "default_template": (
            '{"text": "[{{data.category}}] {{data.subject}} from '
            '{{data.sender}}"}'
        ),
        "required_fields": [],
        "docs_url": "https://api.slack.com/messaging/webhooks",
    },
    "pagerduty": {
        "label": "PagerDuty Events API v2",
        "url_shape_hint": "https://events.pagerduty.com/v2/enqueue",
        "required_headers": {},
        "default_template": (
            '{"routing_key": "{{data.pd_routing_key}}",'
            '"event_action": "trigger",'
            '"payload": {"summary": "[{{data.category}}] {{data.subject}}",'
            '"source": "email-triage","severity": "info"}}'
        ),
        # PagerDuty rejects an empty ``routing_key`` (400 invalid_event) —
        # refuse the send rather than fire-and-forget an unroutable event.
        "required_fields": ["pd_routing_key"],
        "docs_url": (
            "https://developer.pagerduty.com/docs/events-api-v2/overview/"
        ),
    },
    "opsgenie": {
        "label": "Opsgenie Alert API",
        "url_shape_hint": "https://api.opsgenie.com/v2/alerts",
        "required_headers": {
            # Opsgenie's own auth — target's ``secret_key`` is the
            # GenieKey (NOT an HMAC signing key for Opsgenie's case).
            "Authorization": "GenieKey {{secret}}",
        },
        "default_template": (
            '{"message": "[{{data.category}}] {{data.subject}}",'
            '"alias": "{{data.flow_id}}"}'
        ),
        "required_fields": [],
        "docs_url": "https://docs.opsgenie.com/docs/alert-api",
    },
    "discord": {
        "label": "Discord webhook",
        "url_shape_hint": "https://discord.com/api/webhooks/<id>/<token>",
        "required_headers": {},
        "default_template": (
            '{"content": "[{{data.category}}] {{data.subject}} from '
            '{{data.sender}}"}'
        ),
        "required_fields": [],
        "docs_url": (
            "https://discord.com/developers/docs/resources/webhook"
        ),
    },
    "teams": {
        "label": "Microsoft Teams incoming webhook",
        "url_shape_hint": (
            "https://<tenant>.webhook.office.com/webhookb2/<id>/…"
        ),
        "required_headers": {},
        "default_template": (
            '{"@type": "MessageCard","@context": '
            '"http://schema.org/extensions",'
            '"text": "[{{data.category}}] {{data.subject}}"}'
        ),
        "required_fields": [],
        "docs_url": (
            "https://learn.microsoft.com/en-us/microsoftteams/platform/"
            "webhooks-and-connectors/how-to/add-incoming-webhook"
        ),
    },
}


VALID_TARGET_TYPES: frozenset[str] = frozenset(TARGET_TYPES.keys())
