"""SSRF regression pin for the  model-probe endpoint (S-A1, 2am audit 2026-06-07).

GET /config/ai-backends/probe-models issues a server-side outbound GET to an
operator-submitted endpoint URL. The SSRF control is a single `if not
probe.is_local:` early-return before the fetch. The control is correct — but
the 2am release-audit found it had ZERO test coverage, so a future refactor
that inverts/deletes the guard would keep the whole suite green. These tests
pin both the reject branch (non-local endpoints) and the happy path (local
endpoint reaches list_models), asserting no outbound fetch is issued when the
guard rejects.
"""

from __future__ import annotations

import socket
from unittest.mock import AsyncMock, patch

from email_triage.web.auth import SESSION_COOKIE_NAME


def _admin(client, admin_cookies):
    client.cookies.set(
        SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME],
    )


def _probe(client, endpoint):
    return client.get(
        "/config/ai-backends/probe-models",
        params={"backend_type": "ollama", "endpoint": endpoint},
    )


def _fake_getaddrinfo(*ips):
    """Hermetic getaddrinfo stand-in — no real DNS in the test."""
    def _f(host, port, *a, **k):
        return [
            (socket.AF_INET6 if ":" in ip else socket.AF_INET,
             socket.SOCK_STREAM, 0, "", (ip, port or 0))
            for ip in ips
        ]
    return _f


class TestProbeModelsSSRF:
    def test_rejects_cloud_metadata_ip(self, client, admin_cookies):
        """169.254.169.254 (cloud metadata) must be rejected WITHOUT any
        outbound fetch."""
        _admin(client, admin_cookies)
        with patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "http://169.254.169.254/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "local" in body["error"].lower()
        m.assert_not_called()  # SSRF guard fired BEFORE the fetch

    def test_rejects_public_host(self, client, admin_cookies):
        _admin(client, admin_cookies)
        #  — the gate now RESOLVES the host; mock it to a public IP so the
        # test is hermetic (no real DNS) and exercises the resolve path.
        with patch(
            "email_triage._netloc.socket.getaddrinfo",
            _fake_getaddrinfo("93.184.216.34"),
        ), patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "https://example.com/")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "local" in body["error"].lower()
        m.assert_not_called()

    def test_rejects_hostname_resolving_to_metadata(self, client, admin_cookies):
        """ (the rebinding core) — a hostname that a string/suffix gate would
        trust but that RESOLVES to the cloud-metadata IP is rejected without any
        outbound fetch."""
        _admin(client, admin_cookies)
        with patch(
            "email_triage._netloc.socket.getaddrinfo",
            _fake_getaddrinfo("169.254.169.254"),
        ), patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "http://metadata.local/")
        assert resp.json()["ok"] is False
        m.assert_not_called()

    def test_rejects_hostname_with_mixed_records(self, client, admin_cookies):
        """A round-robin / rebinding name returning one private + one public
        address is rejected (fail-closed on ANY non-local record)."""
        _admin(client, admin_cookies)
        with patch(
            "email_triage._netloc.socket.getaddrinfo",
            _fake_getaddrinfo("192.168.1.5", "203.0.113.9"),
        ), patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "http://rebind.evil/")
        assert resp.json()["ok"] is False
        m.assert_not_called()

    def test_local_hostname_resolving_private_passes_and_pins(
        self, client, admin_cookies,
    ):
        """The operator's real local Ollama (a homelab name resolving to a
        private IP) still passes the resolve gate and reaches list_models —
         hardens without over-rejecting."""
        _admin(client, admin_cookies)
        with patch(
            "email_triage._netloc.socket.getaddrinfo",
            _fake_getaddrinfo("192.168.1.5"),
        ), patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "http://ollama.home.lan:11434")
        assert resp.json()["ok"] is True
        m.assert_awaited()

    def test_local_endpoint_passes_guard_and_reaches_list_models(
        self, client, admin_cookies,
    ):
        """A local endpoint must pass the guard and actually reach the
        (mocked) list_models — proving the guard isn't over-rejecting."""
        _admin(client, admin_cookies)
        with patch(
            "email_triage.classify.ollama.OllamaClassifier.list_models",
            new=AsyncMock(return_value=[]),
        ) as m:
            resp = _probe(client, "http://localhost:11434")
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is True
        m.assert_awaited()  # guard passed → fetch attempted

    def test_non_ollama_backend_short_circuits(self, client, admin_cookies):
        _admin(client, admin_cookies)
        resp = client.get(
            "/config/ai-backends/probe-models",
            params={"backend_type": "openai", "endpoint": "http://localhost:11434"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is False
