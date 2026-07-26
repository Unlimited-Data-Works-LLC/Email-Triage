"""Unit + HIPAA-lock coverage for the per-target webhook reshaper.

Covers `src/email_triage/web/_webhook_template.py` +
`src/email_triage/web/_webhook_target_types.py`.

Guarantees pinned here:

* Each built-in target-type renders a body that is (a) valid JSON and
  (b) contains the substituted envelope values in a top-level key the
  receiver expects — Slack ``text``, Discord ``content``, Teams
  ``text``, PagerDuty ``payload.summary`` + ``routing_key``, Opsgenie
  ``message`` + ``alias``.
* HIPAA-flagged targets IGNORE the operator template and emit ONLY
  ``{category, timestamp, flow_id}`` — regardless of target-type.
* Placeholder substitution is JSON-string-escaped so a subject
  containing ``"`` cannot break the rendered payload.
* The ``custom`` target-type with NO operator template returns the
  envelope byte-identical to ``canonical_json(envelope)`` — the
  existing HMAC-verification contract for custom-relay integrations
  keeps working.
* Opsgenie header rendering substitutes ``{{secret}}`` from the
  resolved target secret.
* Unknown target_type at load time is rejected by
  ``config._parse_webhooks`` with a ``ConfigError``.
"""

from __future__ import annotations

import json
import types

import pytest

from email_triage._signing import canonical_json
from email_triage.web._webhook_target_types import (
    TARGET_TYPES,
    VALID_TARGET_TYPES,
)
from email_triage.web._webhook_template import (
    render_for_target,
    render_headers_for_target,
)


def _target(target_type: str = "custom", body_template: str | None = None):
    """Duck-typed target — matches the WebhookTarget attribute surface
    the reshaper reads."""
    return types.SimpleNamespace(
        url="http://example.invalid/hook",
        events=["notification"],
        secret_key="",
        target_type=target_type,
        body_template=body_template,
    )


ENVELOPE = {
    "event": "notification",
    "timestamp": "2026-07-14T20:00:00+00:00",
    "data": {
        "flow_id": "flow-abc",
        "sender": "alice@example.com",
        "subject": "quarterly numbers",
        "category": "billing",
        "timestamp": "2026-07-14T20:00:00+00:00",
        "summary": "[billing] from alice@example.com: quarterly numbers",
        "pd_routing_key": "PD-KEY-XYZ",
    },
}


# --- registry sanity -------------------------------------------------------

def test_registry_has_five_public_targets_plus_custom():
    # Spec: 5 built-in target defaults + the pre-existing custom.
    assert VALID_TARGET_TYPES == frozenset(
        {"custom", "slack", "pagerduty", "opsgenie", "discord", "teams"}
    )
    for key in VALID_TARGET_TYPES - {"custom"}:
        entry = TARGET_TYPES[key]
        assert entry["default_template"], (
            f"target-type {key!r} must ship a default_template"
        )
        # Every default template must be JSON-parseable AFTER the
        # placeholders substitute — sanity-render with a stub envelope.
        rendered = render_for_target(ENVELOPE, _target(key))
        json.loads(rendered)  # raises on malformed


# --- per-target-type shape assertions --------------------------------------

def test_slack_shape():
    body = json.loads(render_for_target(ENVELOPE, _target("slack")))
    assert "text" in body
    assert "billing" in body["text"]
    assert "alice@example.com" in body["text"]
    assert "quarterly numbers" in body["text"]


def test_discord_shape():
    body = json.loads(render_for_target(ENVELOPE, _target("discord")))
    assert "content" in body
    assert "billing" in body["content"]


def test_teams_shape():
    body = json.loads(render_for_target(ENVELOPE, _target("teams")))
    assert body["@type"] == "MessageCard"
    assert "billing" in body["text"]


def test_pagerduty_shape():
    body = json.loads(render_for_target(ENVELOPE, _target("pagerduty")))
    assert body["routing_key"] == "PD-KEY-XYZ"
    assert body["event_action"] == "trigger"
    assert "billing" in body["payload"]["summary"]
    assert body["payload"]["source"] == "email-triage"


def test_opsgenie_shape():
    body = json.loads(render_for_target(ENVELOPE, _target("opsgenie")))
    assert "billing" in body["message"]
    assert body["alias"] == "flow-abc"


def test_opsgenie_header_renders_secret():
    headers = render_headers_for_target(
        _target("opsgenie"), resolved_secret="my-genie-key"
    )
    assert headers["Authorization"] == "GenieKey my-genie-key"


def test_slack_no_required_headers():
    assert render_headers_for_target(_target("slack")) == {}


# --- custom passthrough ----------------------------------------------------

def test_custom_no_template_is_envelope_byte_identical():
    rendered = render_for_target(ENVELOPE, _target("custom"))
    assert rendered == canonical_json(ENVELOPE)


def test_custom_with_operator_template_overrides():
    tmpl = '{"my_field": "{{data.category}}"}'
    body = json.loads(
        render_for_target(ENVELOPE, _target("custom", body_template=tmpl))
    )
    assert body == {"my_field": "billing"}


# --- HIPAA lock (defense-in-depth) -----------------------------------------

def test_hipaa_lock_ignores_operator_template():
    """HIPAA flag → minimal shape, operator template IGNORED."""
    leaky_template = (
        '{"leaked_subject": "{{data.subject}}",'
        '"leaked_sender": "{{data.sender}}"}'
    )
    rendered = render_for_target(
        ENVELOPE,
        _target("slack", body_template=leaky_template),
        is_hipaa=True,
    )
    body = json.loads(rendered)
    # Only the 4 permitted fields (SME-panel 2026-07-15 HIPAA F4 —
    # ``event`` added; it is a fixed enum with zero PHI risk and lets
    # receivers discriminate).
    assert set(body.keys()) == {"event", "category", "timestamp", "flow_id"}
    assert body["category"] == "billing"
    assert body["flow_id"] == "flow-abc"
    assert body["event"] == "notification"


@pytest.mark.parametrize("t", sorted(VALID_TARGET_TYPES))
def test_hipaa_lock_holds_for_every_target_type(t):
    """The HIPAA lock is target-type agnostic — every registry entry
    yields the same minimal shape when is_hipaa=True."""
    rendered = render_for_target(ENVELOPE, _target(t), is_hipaa=True)
    body = json.loads(rendered)
    assert set(body.keys()) == {"event", "category", "timestamp", "flow_id"}


def test_hipaa_lock_emits_audit_log(caplog):
    """SME-panel 2026-07-15 HIPAA F1 — §164.312(b) Audit Controls:
    HIPAA-lock enforcement MUST log an observable line so "did the lock
    fire?" is answerable post-incident."""
    import logging
    caplog.set_level(logging.INFO, logger="email_triage.web._webhook_template")
    render_for_target(
        ENVELOPE, _target("slack", body_template='{"x":"y"}'), is_hipaa=True,
    )
    lock_lines = [
        r for r in caplog.records
        if getattr(r, "event_class", None) == "hipaa_webhook_lock_enforced"
    ]
    assert lock_lines, "HIPAA-lock enforcement must emit an audit log line"
    (r,) = lock_lines
    assert r.flow_id == "flow-abc"
    assert r.target_type == "slack"
    # URL host only — never a path (Slack webhook URLs bake the token
    # into the path; the netloc alone is safe to log).
    assert "example.invalid" in r.url_host
    assert "hook" not in r.url_host  # /hook path fragment excluded
    assert r.template_present is True


def test_hipaa_lock_shape_does_not_read_data_timestamp():
    """SME-panel 2026-07-15 HIPAA F3 — a future caller could populate
    ``data.timestamp`` from a PHI-time (encounter/appointment). Lock
    must read only ``envelope.timestamp`` (dispatcher-authoritative)."""
    envelope_with_phi_time = {
        "event": "notification",
        "timestamp": "2026-07-14T20:00:00+00:00",  # dispatcher's
        "data": {
            "flow_id": "f1",
            "category": "clinical",
            "timestamp": "2026-01-15T09:00:00+00:00",  # PHI-time (never emit)
        },
    }
    body = json.loads(
        render_for_target(envelope_with_phi_time, _target("custom"), is_hipaa=True)
    )
    assert body["timestamp"] == "2026-07-14T20:00:00+00:00"
    assert "2026-01-15" not in json.dumps(body)


# --- JSON escaping (subject with double-quote) -----------------------------

def test_substitution_json_escapes_double_quote_in_subject():
    """A subject containing ``"`` MUST NOT break the rendered JSON."""
    envelope = {
        "event": "notification",
        "timestamp": "2026-07-14T20:00:00+00:00",
        "data": {
            "flow_id": "f1",
            "sender": "s@e.com",
            "subject": 'she said "hi" then left',
            "category": "misc",
            "timestamp": "2026-07-14T20:00:00+00:00",
        },
    }
    rendered = render_for_target(envelope, _target("slack"))
    # Must be parseable JSON — the escaping is what makes this so.
    body = json.loads(rendered)
    assert 'she said "hi" then left' in body["text"]


def test_missing_placeholder_becomes_empty_string():
    envelope = {"event": "x", "timestamp": "t", "data": {"category": "c"}}
    body = json.loads(render_for_target(envelope, _target("slack")))
    # sender/subject missing → substituted as empty strings.
    assert body["text"] == "[c]  from "


# --- parse-time validation -------------------------------------------------

def test_unknown_target_type_rejected_at_load():
    from email_triage.config import ConfigError, _parse_webhooks
    with pytest.raises(ConfigError, match="Unknown webhook target_type"):
        _parse_webhooks([{"url": "http://x", "target_type": "totally-fake"}])


def test_body_template_wrong_type_rejected_at_load():
    from email_triage.config import ConfigError, _parse_webhooks
    with pytest.raises(ConfigError, match="body_template must be a string"):
        _parse_webhooks([{"url": "http://x", "body_template": 42}])


def test_defaults_backward_compatible():
    """A YAML dict with only the pre-existing fields still parses and
    yields a ``custom`` target with no body template."""
    from email_triage.config import _parse_webhooks
    [t] = _parse_webhooks([{"url": "http://x", "events": ["notification"]}])
    assert t.url == "http://x"
    assert t.events == ["notification"]
    assert t.target_type == "custom"
    assert t.body_template is None


# --- SME-panel 2026-07-15 DA1 HIGH — secret exfil defense ------------------

def test_secret_not_bound_into_body_render_context():
    """DA finding: an operator body_template ``{{secret}}`` on a
    ``custom`` target would exfiltrate the HMAC signing key. Body
    render context is envelope-only — ``{{secret}}`` in a body
    template renders as an empty string."""
    body = json.loads(render_for_target(
        ENVELOPE,
        _target("custom", body_template='{"x":"{{secret}}"}'),
        resolved_secret="LEAKED-HMAC-KEY-DO-NOT-SHIP",
    ))
    assert body["x"] == ""
    # And obviously — the plaintext key doesn't appear anywhere in the bytes.
    rendered = render_for_target(
        ENVELOPE,
        _target("custom", body_template='{"x":"{{secret}}"}'),
        resolved_secret="LEAKED-HMAC-KEY-DO-NOT-SHIP",
    )
    assert b"LEAKED-HMAC-KEY" not in rendered


def test_parse_refuses_secret_placeholder_in_body_template():
    """Belt-and-suspenders: even if the render-side scoping regresses,
    parse-time refuses ``{{secret}}`` in operator body_template."""
    from email_triage.config import ConfigError, _parse_webhooks
    with pytest.raises(ConfigError, match=r"NOT reference \{\{secret\}\}"):
        _parse_webhooks([{
            "url": "http://x",
            "body_template": '{"x":"{{secret}}"}',
        }])


def test_headers_still_receive_secret():
    """The scoping is BODY-only — headers legitimately need the secret
    (Opsgenie ``Authorization: GenieKey {{secret}}``)."""
    headers = render_headers_for_target(
        _target("opsgenie"), resolved_secret="my-genie-key"
    )
    assert headers["Authorization"] == "GenieKey my-genie-key"


# --- SME-panel 2026-07-15 DA4 — fail-closed required_fields ---------------

def test_pagerduty_missing_routing_key_raises():
    """PagerDuty rejects an empty ``routing_key`` — refuse the send
    rather than silently ship an unroutable event (Prime Directive #8
    fail-closed)."""
    from email_triage.web._webhook_template import RequiredFieldMissing
    envelope_no_pdkey = {
        "event": "notification",
        "timestamp": "2026-07-14T20:00:00+00:00",
        "data": {
            "flow_id": "f",
            "sender": "s@e.com",
            "subject": "sub",
            "category": "cat",
            # NO pd_routing_key
        },
    }
    with pytest.raises(RequiredFieldMissing, match="pd_routing_key"):
        render_for_target(envelope_no_pdkey, _target("pagerduty"))


def test_pagerduty_with_routing_key_renders():
    body = json.loads(render_for_target(ENVELOPE, _target("pagerduty")))
    assert body["routing_key"] == "PD-KEY-XYZ"


# --- SME-panel 2026-07-15 DA5 — ensure_ascii pinned literal ---------------

def test_json_escape_forces_ensure_ascii():
    """``_json_escape`` MUST call ``json.dumps(..., ensure_ascii=True)``
    — a future perf micro-optim to ``ensure_ascii=False`` would break
    JS parsers that treat U+2028 / U+2029 as literal line terminators.
    This pin locks the call-site literal."""
    import ast
    import inspect
    from email_triage.web import _webhook_template
    src = inspect.getsource(_webhook_template._json_escape)
    tree = ast.parse(src)
    dumps_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "dumps"
    ]
    assert dumps_calls, "_json_escape must call json.dumps"
    for call in dumps_calls:
        kwargs = {k.arg: k.value for k in call.keywords}
        assert "ensure_ascii" in kwargs, (
            "_json_escape's json.dumps() call MUST pin ensure_ascii "
            "explicitly (DA-finding 2026-07-15)"
        )
        val = kwargs["ensure_ascii"]
        assert isinstance(val, ast.Constant) and val.value is True, (
            "_json_escape's json.dumps() MUST pass ensure_ascii=True "
            "as a Constant — never False, never a variable"
        )


def test_json_escape_handles_unicode_line_terminators():
    """Concrete behavior test paired with the AST pin above."""
    envelope = {
        "event": "notification",
        "timestamp": "2026-07-14T20:00:00+00:00",
        "data": {
            "flow_id": "f",
            "sender": "s@e.com",
            "subject": "line1 line2 line3",
            "category": "misc",
        },
    }
    rendered = render_for_target(envelope, _target("slack"))
    # The rendered bytes MUST NOT contain the raw U+2028 / U+2029
    # code points (which would break JS parsers historically).
    assert b"\xe2\x80\xa8" not in rendered  # U+2028 UTF-8
    assert b"\xe2\x80\xa9" not in rendered  # U+2029 UTF-8
    # And it must still parse as valid JSON with the escaped content.
    body = json.loads(rendered)
    assert "line1" in body["text"] and "line3" in body["text"]


# --- SME-panel 2026-07-15 D1/DA2 — TARGET_TYPES ↔ VALID_TARGET_TYPES pin --

def test_valid_target_types_matches_registry_keys():
    """DA finding: registry drift would allow a shipped shape to
    silently disappear. Lock the set-identity."""
    assert VALID_TARGET_TYPES == frozenset(TARGET_TYPES.keys())


def test_every_registry_entry_declares_required_fields_key():
    """Structural: every entry declares ``required_fields`` explicitly
    (even if empty). New target-type additions can't skip the
    fail-closed contract by omission."""
    for name, entry in TARGET_TYPES.items():
        assert "required_fields" in entry, (
            f"target-type {name!r} must declare required_fields explicitly"
        )
        assert isinstance(entry["required_fields"], list), (
            f"{name!r} required_fields must be a list"
        )


# --- Drive C admin UI wizard write path ---------------------------------

# --- DA-F3b — per-account targeting (cross-account fanning fix) ---------

def test_dispatcher_wildcard_target_matches_all_accounts():
    """A ``WebhookTarget`` with ``account_id=None`` (default) fires on
    every account — preserves the pre-fix single-account behavior."""
    from email_triage.config import WebhookTarget
    from email_triage.web.events import EventDispatcher
    t = WebhookTarget(url="http://127.0.0.1:9/hook", events=["notification"])
    d = EventDispatcher(targets=[t])
    assert d._matching_targets("notification", account_id="anything") == [t]
    assert d._matching_targets("notification", account_id=None) == [t]


def test_dispatcher_account_scoped_target_filters_out_wrong_account():
    """A ``WebhookTarget`` scoped to ``account_id="A"`` MUST NOT fire
    on account ``B``'s events — closes the cross-account fanning class."""
    from email_triage.config import WebhookTarget
    from email_triage.web.events import EventDispatcher
    t_a = WebhookTarget(
        url="http://127.0.0.1:9/a", events=["notification"], account_id="A",
    )
    t_b = WebhookTarget(
        url="http://127.0.0.1:9/b", events=["notification"], account_id="B",
    )
    t_wild = WebhookTarget(url="http://127.0.0.1:9/w", events=["notification"])
    d = EventDispatcher(targets=[t_a, t_b, t_wild])
    matched = d._matching_targets("notification", account_id="A")
    assert t_a in matched
    assert t_b not in matched, "target scoped to B must not match A's fire"
    assert t_wild in matched, "wildcard target must match every account"


def test_dispatcher_no_context_broadcast_drops_scoped_targets():
    """SME-panel 2026-07-15 DA-F2 close — a no-context broadcast
    (``account_id=None`` — kill-switch, health ping, diagnostic emit)
    reaches ONLY wildcard targets. Scoped targets stay silent for
    fires that don't name their account (existence-leak minimization).
    Wildcard targets still receive every broadcast."""
    from email_triage.config import WebhookTarget
    from email_triage.web.events import EventDispatcher
    t_scoped = WebhookTarget(
        url="http://127.0.0.1:9/a", events=["notification"], account_id="A",
    )
    t_wild = WebhookTarget(
        url="http://127.0.0.1:9/w", events=["notification"],
    )
    d = EventDispatcher(targets=[t_scoped, t_wild])
    matched = d._matching_targets("notification", account_id=None)
    assert t_scoped not in matched, (
        "DA-F2 REGRESSION: a broadcast (context account_id=None) MUST "
        "NOT surface to a scoped target (existence-leak)."
    )
    assert t_wild in matched, "wildcard target must receive every broadcast"


def test_account_id_wrong_type_rejected_at_load():
    """SME-panel DA-F3b — ``account_id`` must be str or omitted."""
    from email_triage.config import ConfigError, _parse_webhooks
    with pytest.raises(ConfigError, match="account_id must be a string"):
        _parse_webhooks([{"url": "http://x", "account_id": 42}])


def test_account_id_backward_compatible_default():
    """A YAML without ``account_id`` still parses; account_id is None."""
    from email_triage.config import _parse_webhooks
    [t] = _parse_webhooks([{"url": "http://x"}])
    assert t.account_id is None


def test_account_id_yaml_roundtrip():
    """A YAML with ``account_id`` set round-trips."""
    from email_triage.config import _parse_webhooks
    [t] = _parse_webhooks([{"url": "http://x", "account_id": "acct-42"}])
    assert t.account_id == "acct-42"


def test_wizard_options_helper_returns_all_registry_types():
    """The wizard-side helper `_build_outbound_target_type_options`
    surfaces every registry key via the admin dropdown."""
    from email_triage.web.routers.integrations import (
        _build_outbound_target_type_options,
    )
    opts = _build_outbound_target_type_options()
    keys = [o["key"] for o in opts]
    # Custom first (per _OUTBOUND_TARGET_TYPE_ORDER).
    assert keys[0] == "custom"
    # Registry parity — every VALID_TARGET_TYPES key surfaces.
    assert set(keys) == VALID_TARGET_TYPES
    # Every option carries the wizard fields the template needs.
    for o in opts:
        for field in (
            "key", "label", "url_shape_hint", "default_template",
            "docs_url", "required_fields",
        ):
            assert field in o, f"wizard option missing {field}"
