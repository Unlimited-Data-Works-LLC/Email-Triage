"""A4 (divergence census 2026-06-09) — webhook external-URL egress gate SSOT.

The "is this webhook destination internal?" predicate is now ONE module-level
function, ``email_triage.web.events.is_local_webhook_url``, used by BOTH the
``EventDispatcher`` dispatch gate AND the watch-fired webhook path
(``watch_runner.fire_one_watch``). Before A4 the watch path bypassed the
``webhooks_allow_external`` policy that EventDispatcher enforced — so a per-watch
external webhook URL would be POSTed to even with the policy off.

(Census egress-class dispositions, verify-don't-accept:
  - ``_is_local_host`` for LLM backends — REFUTED: already a single shared def
    in ``classify/base.py``, imported by every backend.
  - CLI sent-mail embed path — DOWNGRADED (NOT refuted; DA caught my over-hasty
    first call): ``SentMailIndex``'s ``NonLocalBackendError`` guards the
    backend_type LABEL, and HIPAA accounts are hard-blocked upstream — but the
    inline ``_OllamaEmbedShim`` POSTed to ``config.classifier.base_url`` with no
    URL-locality check, so a misconfigured base_url could egress NON-HIPAA
    sent-mail content. Fixed (A4b): an explicit ``_is_local_host(base_url)``
    gate in ``cli.py`` before the shim.
  - watch-fired webhook external-URL gate — the real divergence, fixed here.)
"""

from __future__ import annotations

import logging

from email_triage.config import TriageConfig, WebhookTarget
from email_triage.web.events import (
    announce_external_egress_posture,
    is_local_webhook_url,
)


class TestIsLocalWebhookUrlSSOT:
    def test_localhost_and_loopback_are_local(self):
        assert is_local_webhook_url("http://localhost:8080/hook")
        assert is_local_webhook_url("http://127.0.0.1/hook")
        assert is_local_webhook_url("http://[::1]:9000/hook")

    def test_rfc1918_private_ranges_are_local(self):
        assert is_local_webhook_url("http://10.0.0.5/hook")
        assert is_local_webhook_url("http://192.168.1.10/hook")
        assert is_local_webhook_url("http://172.16.0.1/hook")
        assert is_local_webhook_url("http://172.31.255.254/hook")
        # 172.32+ is NOT private.
        assert not is_local_webhook_url("http://172.32.0.1/hook")

    def test_mdns_and_operator_suffixes_are_local(self):
        assert is_local_webhook_url("http://the deploy host.local/hook")
        assert is_local_webhook_url(
            "http://host.example.com/hook", (".example.com",),
        )

    def test_public_urls_are_external(self):
        assert not is_local_webhook_url("https://evil.example.com/hook")
        assert not is_local_webhook_url("https://hooks.slack.com/x")
        assert not is_local_webhook_url("")
        # The external→gated behaviour is what both webhook paths now key on:
        # an external URL with webhooks_allow_external=False is dropped.
        # (EventDispatcher's gate + watch_runner.fire_one_watch's gate both
        # call this predicate; the existing 74 dispatcher/watch tests exercise
        # the integration — this pins the shared predicate itself.)


class TestExternalEgressPostureAnnouncement:
    """#8-FULL MUST-FIX (devils-advocate, 2026-06-10): wiring the
    ``webhooks_allow_external`` loader read activates a previously-INERT
    hand-edited YAML flag on the first post-upgrade boot. That deny→allow
    egress flip must NOT be silent (§164.502(e) disclosure surface). This
    pins ``announce_external_egress_posture`` — the loud boot-time WARNING."""

    def test_allow_external_true_logs_loud_warning(self, caplog):
        cfg = TriageConfig()
        cfg.webhooks_allow_external = True
        cfg.webhooks = [WebhookTarget(url="https://hooks.example.com/x")]
        with caplog.at_level(logging.WARNING, logger="email_triage.web.events"):
            warned = announce_external_egress_posture(cfg)
        assert warned is True
        msgs = [r.getMessage() for r in caplog.records
                if r.levelno >= logging.WARNING]
        assert any("ENABLED" in m and "webhooks_allow_external" in m
                   for m in msgs), msgs

    def test_allow_external_false_is_silent(self, caplog):
        """The safe deny default must stay silent — no warning noise on the
        overwhelmingly-common install where external egress is off."""
        cfg = TriageConfig()  # webhooks_allow_external defaults False
        with caplog.at_level(logging.WARNING, logger="email_triage.web.events"):
            warned = announce_external_egress_posture(cfg)
        assert warned is False
        assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []
