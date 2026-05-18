"""Tests for /admin/backup web surface (#65)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from email_triage.web.auth import SESSION_COOKIE_NAME


_PASSPHRASE = "operator-strong-passphrase-32-chars"


def _set_secrets(app, master_key: str = "fernet-key-base64-32-bytes-pad"):
    """Wire a fake bootstrap provider so the backup route can read
    the master key without actually touching keyring / podman secrets.

    The route calls _make_bootstrap_provider() which constructs a
    fresh provider from config.secrets.backend. We monkeypatch that
    factory to return a stub.
    """
    class _Stub:
        def get(self, k):
            return master_key if k == "ET_MASTER_KEY" else None

        def set(self, k, v):
            pass

        def list_keys(self):
            return ["ET_MASTER_KEY"]

        def require(self, k):
            v = self.get(k)
            if v is None:
                raise KeyError(k)
            return v

    return _Stub()


# ---------------------------------------------------------------------------
# Page render + auth gating
# ---------------------------------------------------------------------------

class TestBackupPage:
    def test_anonymous_redirects(self, client):
        resp = client.get("/admin/backup", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers.get("location", "")

    def test_regular_user_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/backup")
        assert resp.status_code == 403

    def test_admin_renders(self, client, admin_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/backup")
        assert resp.status_code == 200
        body = resp.text
        # Both forms present.
        assert 'action="/admin/backup/export-full"' in body
        assert 'action="/admin/backup/export-key"' in body
        # Three checkboxes for the full bundle.
        assert 'name="include_master_key"' in body
        assert 'name="include_tls_certs"' in body
        assert 'name="include_logs"' in body


# ---------------------------------------------------------------------------
# Full-bundle POST
# ---------------------------------------------------------------------------

class TestExportFull:
    def _post(self, client, **form):
        defaults = {
            "passphrase": _PASSPHRASE,
            "passphrase_confirm": _PASSPHRASE,
            "include_master_key": "",
            "include_tls_certs": "1",
            "include_logs": "",
        }
        defaults.update(form)
        return client.post(
            "/admin/backup/export-full",
            data=defaults,
            follow_redirects=False,
        )

    def test_anonymous_blocked(self, client):
        resp = self._post(client)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers.get("location", "")

    def test_regular_user_blocked(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = self._post(client)
        assert resp.status_code == 403

    def test_passphrase_mismatch_redirects_with_error(
        self, client, admin_cookies, app, db,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = self._post(
            client, passphrase=_PASSPHRASE, passphrase_confirm="different-32-chars",
        )
        assert resp.status_code == 303
        loc = resp.headers["location"]
        assert "/admin/backup" in loc
        assert "err=" in loc

    def test_weak_passphrase_redirects_with_error(
        self, client, admin_cookies, app,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(
                client, passphrase="short", passphrase_confirm="short",
            )
        assert resp.status_code == 303
        assert "err=" in resp.headers["location"]

    def test_admin_export_returns_attachment(
        self, client, admin_cookies, app, db, tmp_path,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        # Ensure the config has a valid YAML the route can read.
        # The default ``client`` fixture sets app.state.config to a
        # default TriageConfig; _resolve_config_path falls back to a
        # tmp YAML when none of the search paths exist, so this works.
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client)
        assert resp.status_code == 200, resp.text[:500]
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert ".etbk" in cd
        assert resp.headers.get("content-type", "").startswith(
            "application/octet-stream",
        )
        assert len(resp.content) > 0
        # First 8 bytes are the magic prefix.
        from email_triage.backup import MAGIC_FULL
        assert resp.content.startswith(MAGIC_FULL)

    def test_export_decryptable_round_trip(
        self, client, admin_cookies, app, db, tmp_path,
    ):
        """End-to-end: POST to the route, take the bytes, run them
        through the public unbundle. The full pipeline (route ->
        backup module -> tarball -> Fernet -> unbundle) round-trips."""
        from email_triage.backup import unbundle
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client)
        assert resp.status_code == 200
        result = unbundle(resp.content, passphrase=_PASSPHRASE)
        assert result.bundle_type == "full"
        assert "triage.db" in result.files
        assert "email-triage.yaml" in result.files

    def test_export_with_master_key_includes_file(
        self, client, admin_cookies, app, db,
    ):
        from email_triage.backup import unbundle
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client, include_master_key="1")
        assert resp.status_code == 200
        result = unbundle(resp.content, passphrase=_PASSPHRASE)
        assert "data/master_key.bin" in result.files
        assert result.manifest["include"]["master_key"] is True

    def test_audit_event_written_on_success(
        self, client, admin_cookies, app, db, admin_user,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client)
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT event_type, outcome, email FROM auth_events "
            "WHERE event_type = 'backup_export_full' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
        assert rows[0]["email"] == admin_user["email"]


# ---------------------------------------------------------------------------
# Key-only POST
# ---------------------------------------------------------------------------

class TestExportKeyOnly:
    def _post(self, client, **form):
        defaults = {
            "passphrase": _PASSPHRASE,
            "passphrase_confirm": _PASSPHRASE,
        }
        defaults.update(form)
        return client.post(
            "/admin/backup/export-key",
            data=defaults,
            follow_redirects=False,
        )

    def test_anonymous_blocked(self, client):
        resp = self._post(client)
        assert resp.status_code in (302, 303)

    def test_regular_user_blocked(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = self._post(client)
        assert resp.status_code == 403

    def test_admin_export_returns_attachment(
        self, client, admin_cookies, app,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client)
        assert resp.status_code == 200, resp.text[:500]
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert ".etbkkey" in cd
        from email_triage.backup import MAGIC_KEY_ONLY
        assert resp.content.startswith(MAGIC_KEY_ONLY)

    def test_round_trip_with_unbundle(self, client, admin_cookies, app):
        from email_triage.backup import unbundle
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(
                app, master_key="known-master-key-bytes-32x"
            ),
        ):
            resp = self._post(client)
        assert resp.status_code == 200
        result = unbundle(resp.content, passphrase=_PASSPHRASE)
        assert result.bundle_type == "key-only"
        assert result.files["master_key.bin"].data == b"known-master-key-bytes-32x"

    def test_audit_event_written_on_success(
        self, client, admin_cookies, app, db, admin_user,
    ):
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        with patch(
            "email_triage.web.routers.backup._make_bootstrap_provider",
            return_value=_set_secrets(app),
        ):
            resp = self._post(client)
        assert resp.status_code == 200
        rows = db.execute(
            "SELECT event_type, outcome FROM auth_events "
            "WHERE event_type = 'backup_export_key' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
