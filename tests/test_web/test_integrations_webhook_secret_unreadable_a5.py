"""A5 / SME finding DA-2 — outbound-webhook-secret "unreadable" UI state.

When the install-level outbound webhook signing secret EXISTS but won't
decrypt (corrupt row / master-key mismatch), the /admin/integrations page
must NOT lie green. Before the fix it rendered the normal "A secret is
stored; leave blank to keep." copy — telling the operator to KEEP a broken
secret while HMAC-signed deliveries were being silently dropped.

These are RENDERED-HTML assertions (per feedback_test_the_view_not_just_machinery):
a context-only test would pass while the operator still saw the wrong copy.
"""

from __future__ import annotations

import pytest

from email_triage.config import WebhookTarget
from email_triage.secrets import SecretsDecryptError
from email_triage.web.auth import SESSION_COOKIE_NAME

_SECRET_KEY = "OPENCLAW_WEBHOOK_SECRET"


class _UnreadableSecrets:
    """Secrets provider whose outbound-webhook key exists but won't
    decrypt — raises SecretsDecryptError exactly like DbSecrets does on a
    master-key mismatch. Everything else is absent."""

    def get(self, key: str):
        if key == _SECRET_KEY:
            raise SecretsDecryptError(key)
        return None

    def set(self, key: str, value: str) -> None:  # pragma: no cover
        pass

    def list_keys(self):  # pragma: no cover
        return [_SECRET_KEY]


def _render_integrations(client, app, admin_cookies, secrets):
    app.state.config.webhooks = [
        WebhookTarget(
            url="http://192.168.1.10:9999/hook",
            events=["triage.completed"],
            secret_key=_SECRET_KEY,
        )
    ]
    app.state.secrets = secrets
    client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
    client.raise_server_exceptions = True
    resp = client.get("/admin/integrations")
    assert resp.status_code == 200
    return resp.text


def test_unreadable_secret_shows_distinct_warning(
    client, db, app, admin_user, admin_cookies,
):
    body = _render_integrations(client, app, admin_cookies, _UnreadableSecrets())

    # The distinct unreadable warning IS rendered...
    assert "cannot be decrypted" in body
    assert "deliveries are being dropped" in body

    # ...and the misleading "leave blank to keep" copy is NOT shown for the
    # outbound webhook secret (it would tell the operator to keep a broken
    # secret). Isolate the region around the outbound shared-secret field.
    idx = body.find("Used to compute the HMAC-SHA256 signature")
    assert idx != -1
    region = body[idx: idx + 600]
    assert "leave blank to keep" not in region


def test_readable_secret_shows_normal_keep_copy(
    client, db, app, admin_user, admin_cookies,
):
    """Control: a normally-readable stored secret still shows the
    standard 'leave blank to keep' copy and NOT the unreadable warning."""
    secrets = app.state.secrets  # the _InMemorySecrets from the db fixture
    secrets.set(_SECRET_KEY, "a-perfectly-fine-secret")
    body = _render_integrations(client, app, admin_cookies, secrets)

    idx = body.find("Used to compute the HMAC-SHA256 signature")
    assert idx != -1
    region = body[idx: idx + 600]
    assert "leave blank to keep" in region
    assert "cannot be decrypted" not in body
