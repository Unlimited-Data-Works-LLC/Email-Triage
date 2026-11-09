"""Tests for the outbound-webhook body-template live preview endpoint.

Task  — ``POST /admin/integrations/webhook-preview``. Consumed by
the wizard on ``admin/config_tabs/integrations.html`` via HTMX (target-
type change, sample-event change, body-template keyup-changed).

Coverage per Task  decision memo (server-side render via HTMX, not
a client-side Mustache/Handlebars lib): the preview reuses the
``render_for_target`` SSOT so preview bytes MUST equal production emit
bytes for the same inputs — a divergence would defeat the whole reason
we picked server-side render over a JS lib.
"""

from __future__ import annotations

import html

from email_triage.web.auth import SESSION_COOKIE_NAME


def _unescape(body: str) -> str:
    """Jinja HTML-escapes the JSON body inside the ``<pre>`` — XSS
    protection against a hostile operator template. Tests assert
    against the semantic content, not the escape encoding, so unwind
    the escape once here."""
    return html.unescape(body)


class TestWebhookPreviewAuth:
    def test_anonymous_denied(self, client):
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={"target_type": "custom"},
            follow_redirects=False,
        )
        assert resp.status_code in (303, 302, 401, 403)

    def test_regular_user_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={"target_type": "custom"},
        )
        assert resp.status_code == 403

    def test_admin_renders_fragment(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "slack",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = resp.text
        # Fragment shape — two <pre> blocks (normal + HIPAA) and the
        # `render_for_target` SSOT citation.
        assert "Normal (non-HIPAA) wire body" in body
        assert "HIPAA-locked wire body" in body
        assert "render_for_target" in body


class TestWebhookPreviewRender:
    """Content correctness — preview bytes must equal production emit
    bytes for the same inputs (Task  WYSIWYG guarantee)."""

    def test_slack_default_template_uses_registry_default(
        self, client, admin_cookies,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "slack",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # Slack default renders "[<category>] <subject> from <sender>"
        # in a `{"text": ...}` shape (see _webhook_target_types.py).
        assert "sample-category" in body
        assert "Sample subject line" in body
        assert "sample-sender@example.com" in body
        assert '"text"' in body

    def test_custom_target_renders_envelope(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # Custom + no template → canonical envelope (`event`, `timestamp`,
        # `data.*`).
        assert '"event"' in body
        assert '"timestamp"' in body
        assert "triage.completed" in body

    def test_operator_override_renders_verbatim(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": (
                    '{"custom":"{{data.subject}}","cat":"{{data.category}}"}'
                ),
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        assert '"custom":"Sample subject line"' in body
        assert '"cat":"sample-category"' in body

    def test_secret_binding_refused(self, client, admin_cookies):
        """DA-F1 mirror — preview refuses ``{{secret}}`` matching parse-
        time refusal + wizard-save refusal (three places, one contract)."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": '{"x":"{{secret}}"}',
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        assert "Template rejected" in body
        assert "{{secret}}" in body

    def test_secret_binding_refused_whitespace_variant(
        self, client, admin_cookies,
    ):
        """Match the whitespace-tolerant regex the parse + save paths use."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": '{"x":"{{ secret }}"}',
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        assert "Template rejected" in resp.text

    def test_hipaa_locked_shape(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": (
                    '{"leak_subject":"{{data.subject}}",'
                    '"leak_sender":"{{data.sender}}"}'
                ),
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # HIPAA-locked pre block should NOT contain the operator's
        # leaky template output (subject / sender).
        hipaa_marker = "HIPAA-locked wire body"
        assert hipaa_marker in body
        hipaa_section = body[body.index(hipaa_marker):]
        # Subject + sender are the PHI-shaped fields — must be absent
        # from the HIPAA-locked shape.
        assert "Sample subject line" not in hipaa_section
        assert "sample-sender@example.com" not in hipaa_section
        # Whitelisted keys still present.
        assert "flow-DEMO-abc123" in hipaa_section
        assert "sample-category" in hipaa_section

    def test_invalid_target_type_falls_back_to_custom(
        self, client, admin_cookies,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "bogus-not-a-real-type",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        # Fell back to custom → envelope shape.
        assert "<code>custom</code>" in resp.text

    def test_missing_sample_event_defaults(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={"target_type": "custom"},
        )
        assert resp.status_code == 200
        assert "triage.completed" in resp.text

    def test_pagerduty_default_template_renders(self, client, admin_cookies):
        """DA PD-N-coverage fold (SME-panel 2026-07-15) — PagerDuty
        carries the richest ``required_fields`` (``pd_routing_key``)
        and is the most likely to surprise a wizard operator at first
        prod fire. Preview MUST render its default template correctly
        against the sample envelope (which carries pd_routing_key)."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "pagerduty",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # PagerDuty default: `{"routing_key":"...","event_action":"trigger",
        # "payload":{"summary":"[<category>] <subject>","source":"email-triage",
        # "severity":"info"}}`.
        assert "SAMPLE-PD-ROUTING-KEY" in body
        assert '"routing_key"' in body
        assert '"event_action": "trigger"' in body
        assert '"severity": "info"' in body

    def test_pagerduty_missing_required_field_flags_error(
        self, client, admin_cookies,
    ):
        """DA PD-N-coverage sibling — when the envelope is missing a
        ``required_fields`` entry, preview surfaces the
        ``RequiredFieldMissing`` message instead of a silent render
        (matches production fail-closed behavior)."""
        # Feed a synthesized bad envelope by overriding the sample-event
        # source — this test drives the same code path a
        # deleted-required-field would exercise at prod fire time.
        from email_triage.web.routers import integrations as _integ
        # Temporarily strip pd_routing_key from the canned envelope.
        saved = _integ._PREVIEW_SAMPLE_ENVELOPES["triage.completed"]["data"][
            "pd_routing_key"
        ]
        _integ._PREVIEW_SAMPLE_ENVELOPES["triage.completed"]["data"][
            "pd_routing_key"
        ] = ""
        try:
            client.cookies.set(
                SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
            )
            client.raise_server_exceptions = True
            resp = client.post(
                "/admin/integrations/webhook-preview",
                data={
                    "target_type": "pagerduty",
                    "body_template": "",
                    "sample_event": "triage.completed",
                },
            )
        finally:
            _integ._PREVIEW_SAMPLE_ENVELOPES["triage.completed"]["data"][
                "pd_routing_key"
            ] = saved
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # Preview surfaces the RequiredFieldMissing message inline.
        assert "Delivery would be refused" in body
        assert "pd_routing_key" in body

    def test_operator_template_omitting_required_field_flags_hint(
        self, client, admin_cookies,
    ):
        """DA PD-N-operator-mistake fold + the backlog row 415 (shipped
        same-drive per feedback_dont_over_defer): operator template
        that OMITS a typed target's required field renders fine
        against the canned envelope, but a prod fire against a
        real envelope missing the same field would refuse. Hint
        surfaces the omission at wizard-write time."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        # PagerDuty requires `pd_routing_key`. This template omits it.
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "pagerduty",
                "body_template": (
                    '{"payload":{"summary":"[{{data.category}}] '
                    '{{data.subject}}"}}'
                ),
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        assert "Operator template omits required fields" in body
        assert "data.pd_routing_key" in body

    def test_operator_template_referencing_required_field_no_hint(
        self, client, admin_cookies,
    ):
        """Template that references pd_routing_key → no hint fired."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "pagerduty",
                "body_template": (
                    '{"routing_key":"{{data.pd_routing_key}}",'
                    '"event_action":"trigger",'
                    '"payload":{"summary":"[{{data.category}}] {{data.subject}}"}}'
                ),
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        assert "Operator template omits required fields" not in _unescape(resp.text)

    def test_default_template_no_required_field_hint(
        self, client, admin_cookies,
    ):
        """Empty operator template → target-type's default → hint
        MUST NOT fire (the default references every required field
        by design; a hint would be a false positive)."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "pagerduty",
                "body_template": "",
                "sample_event": "triage.completed",
            },
        )
        assert resp.status_code == 200
        assert "Operator template omits required fields" not in _unescape(resp.text)

    def test_bogus_sample_event_coerces_display(
        self, client, admin_cookies,
    ):
        """DA PD-N-honesty fold — the fragment displays the RESOLVED
        sample_event key, not the raw form value. Otherwise preview
        would advertise "sample: <bogus>" while rendering
        triage.completed bytes (record ≠ HEAD-reality)."""
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "sample_event": "not.a.real.event",
            },
        )
        assert resp.status_code == 200
        body = _unescape(resp.text)
        # Displayed sample_event is the RESOLVED fallback, not the
        # bogus input.
        assert "not.a.real.event" not in body
        assert "triage.completed" in body

    def test_flow_classified_sample_available(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": "custom",
                "body_template": "",
                "sample_event": "flow.classified",
            },
        )
        assert resp.status_code == 200
        assert "flow.classified" in resp.text


import re


def _extract_pre_blocks(body: str) -> list[str]:
    """Extract every ``<pre>...</pre>`` block from a preview fragment,
    HTML-unescaped. Returns block *contents* in document order —
    normal-body block first, HIPAA-locked block second."""
    return [
        html.unescape(m.group(1))
        for m in re.finditer(r"<pre[^>]*>(.+?)</pre>", body, re.DOTALL)
    ]


class TestWebhookPreviewWizardPageRender:
    """DA PD-N-view fold (SME-panel 2026-07-15) — the wizard page
    itself must render cleanly under Jinja StrictUndefined so a
    missing template var in the HTMX-wired block surfaces as a test
    failure, not a silent 500 in the operator's browser
    (recurrence-class flag: `feedback_test_the_view_not_just_machinery`).

    Test the VIEW, not just the fragment.
    """

    def test_integrations_page_renders_under_strict_undefined(
        self, client, admin_cookies, strict_undefined_templates,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        resp = client.get("/config?tab=integrations", follow_redirects=True)
        assert resp.status_code == 200, (
            f"integrations tab render 500'd under StrictUndefined — "
            f"probably a HTMX wiring block references a template var "
            f"the handler doesn't provide"
        )
        body = resp.text
        # Preview surface is wired.
        assert 'id="outbound-body-preview"' in body
        assert 'hx-post="/admin/integrations/webhook-preview"' in body
        assert 'id="outbound-preview-sample-event"' in body


class TestWebhookPreviewSSotEquivalence:
    """The load-bearing invariant of Task : preview bytes == production
    emit bytes for the same inputs. If this drifts the whole reason we
    picked server-side render over a JS lib collapses.

    DB-F1 fold (SME panel 2026-07-15): the equivalence test MUST POST
    the preview endpoint and compare the extracted `<pre>` bytes byte-
    for-byte against a direct SSOT call. Substring-only assertions
    let a future in-route wrapper drift silently (e.g. someone adds
    ``"pretty":True`` reshape "for readability", or the fragment
    template loses a field). Extract the block, unescape, compare
    equal.
    """

    @staticmethod
    def _post_preview(client, admin_cookies, *, target_type, template, sample):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.raise_server_exceptions = True
        return client.post(
            "/admin/integrations/webhook-preview",
            data={
                "target_type": target_type,
                "body_template": template,
                "sample_event": sample,
            },
        )

    def _direct_ssot_bytes(self, *, target_type, template, sample, is_hipaa):
        """SSOT reference: what production emit ships for the same inputs.

        DA PD-1 fold (SME-panel 2026-07-15): the HIPAA-branch reference
        MUST be ``render_for_target(is_hipaa=True)`` — the actual
        production emit path — NOT the sibling ``_hipaa_locked_bytes``.
        A future addition to render_for_target's HIPAA branch (canary,
        scrub, trace) must reach preview transparently; asserting on
        the sibling would silently pass the drift.
        """
        from email_triage.web._webhook_template import render_for_target
        from email_triage.web.routers.integrations import (
            _PREVIEW_SAMPLE_ENVELOPES, _PreviewTarget,
        )
        envelope = _PREVIEW_SAMPLE_ENVELOPES[sample]
        target = _PreviewTarget(
            target_type=target_type, body_template=(template or None),
        )
        return render_for_target(
            envelope, target, is_hipaa=is_hipaa, resolved_secret="",
            # Silences the INFO log the preview endpoint also silences —
            # test invariant is bytes-equal, not log-equal.
            _suppress_audit_log=True,
        )

    # DB-N2 fold: parameterize over every typed target-type × both sample
    # events × {operator-override, default-template} so a future
    # target-type can't regress preview-vs-emit unnoticed.
    _NORMAL_MATRIX = [
        (t, tmpl, s)
        for t in ("custom", "slack", "pagerduty", "opsgenie", "discord", "teams")
        for tmpl in (
            "",
            '{"override":"{{data.subject}}","evt":"{{event}}"}',
        )
        for s in ("triage.completed", "flow.classified")
    ]

    def test_preview_body_bytes_equal_ssot_over_full_matrix(
        self, client, admin_cookies,
    ):
        """Every (target_type × template × sample) combination must have
        preview-rendered normal body bytes-equal to the SSOT direct call."""
        for target_type, template, sample in self._NORMAL_MATRIX:
            resp = self._post_preview(
                client, admin_cookies,
                target_type=target_type, template=template, sample=sample,
            )
            assert resp.status_code == 200, (
                f"preview POST failed for {target_type}/{sample}/{template!r}"
            )
            blocks = _extract_pre_blocks(resp.text)
            assert len(blocks) >= 2, (
                f"expected 2 <pre> blocks for {target_type}/{sample}, "
                f"got {len(blocks)}"
            )
            preview_body_str = blocks[0]  # normal-body block first
            direct_bytes = self._direct_ssot_bytes(
                target_type=target_type, template=template,
                sample=sample, is_hipaa=False,
            )
            assert preview_body_str.encode("utf-8") == direct_bytes, (
                f"preview drift on {target_type}/{sample}/{template!r} — "
                f"preview {preview_body_str!r} != SSOT {direct_bytes!r}"
            )

    def test_preview_hipaa_bytes_equal_ssot_over_samples(
        self, client, admin_cookies,
    ):
        """HIPAA-locked <pre> block must be bytes-equal to the direct
        _hipaa_locked_bytes call for every sample envelope, regardless
        of what the operator's template is (the lock forces the shape)."""
        for sample in ("triage.completed", "flow.classified"):
            # Operator template deliberately tries to leak PHI — HIPAA
            # lock MUST override it.
            resp = self._post_preview(
                client, admin_cookies,
                target_type="custom",
                template=(
                    '{"leak_subject":"{{data.subject}}",'
                    '"leak_sender":"{{data.sender}}"}'
                ),
                sample=sample,
            )
            assert resp.status_code == 200
            blocks = _extract_pre_blocks(resp.text)
            assert len(blocks) >= 2
            hipaa_body_str = blocks[1]  # HIPAA-locked block second
            direct_bytes = self._direct_ssot_bytes(
                target_type="custom", template="",
                sample=sample, is_hipaa=True,
            )
            assert hipaa_body_str.encode("utf-8") == direct_bytes, (
                f"HIPAA-lock preview drift on sample {sample} — "
                f"preview {hipaa_body_str!r} != SSOT {direct_bytes!r}"
            )
