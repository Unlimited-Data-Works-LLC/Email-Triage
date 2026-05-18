"""Tests for /admin/tls/csr web surface (#74)."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

from email_triage import tls_csr
from email_triage.web.auth import SESSION_COOKIE_NAME


def _sign_with_test_ca(csr_pem: bytes, valid_days: int = 365) -> bytes:
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(
            csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName,
            ).value,
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _set_cert_dir(app, tmp_path: Path) -> Path:
    """Point the live config at a tmp cert_dir so our test doesn't
    write to the project's actual data/certs/. Returns the cert_dir
    path."""
    cd = tmp_path / "certs"
    cd.mkdir(parents=True, exist_ok=True)
    app.state.config.tls.cert_dir = str(cd)
    return cd


# ---------------------------------------------------------------------------
# Page render + auth gating
# ---------------------------------------------------------------------------

class TestPageRender:
    def test_anonymous_redirects(self, client):
        resp = client.get("/admin/tls/csr", follow_redirects=False)
        assert resp.status_code in (302, 303)
        assert "/login" in resp.headers.get("location", "")

    def test_regular_user_forbidden(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/tls/csr")
        assert resp.status_code == 403

    def test_admin_idle_state(self, client, admin_cookies, app, tmp_path):
        _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/tls/csr")
        assert resp.status_code == 200
        body = resp.text
        # Idle state should render the Make-CSR form + Self-sign form.
        assert 'action="/admin/tls/csr/make"' in body
        assert 'action="/admin/tls/csr/self-sign"' in body
        # No pending controls.
        assert 'action="/admin/tls/csr/import"' not in body

    def test_admin_pending_state_renders_import(
        self, client, admin_cookies, app, tmp_path,
    ):
        cd = _set_cert_dir(app, tmp_path)
        tls_csr.make_csr(cd, hostname="x.example.com")
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/tls/csr")
        assert resp.status_code == 200
        body = resp.text
        assert "CSR pending" in body
        assert 'action="/admin/tls/csr/import"' in body
        assert 'action="/admin/tls/csr/cancel"' in body

    def test_admin_active_state_shows_metadata(
        self, client, admin_cookies, app, tmp_path,
    ):
        cd = _set_cert_dir(app, tmp_path)
        tls_csr.self_sign_now(cd, hostname="active.example.com")
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.get("/admin/tls/csr")
        assert resp.status_code == 200
        body = resp.text
        assert "Active certificate" in body
        assert "active.example.com" in body


# ---------------------------------------------------------------------------
# POST /admin/tls/csr/make
# ---------------------------------------------------------------------------

class TestMake:
    def test_anonymous_blocked(self, client):
        resp = client.post(
            "/admin/tls/csr/make",
            data={"hostname": "x"},
            follow_redirects=False,
        )
        assert resp.status_code in (302, 303)

    def test_regular_user_blocked(self, client, user_cookies):
        client.cookies.set(SESSION_COOKIE_NAME, user_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/make",
            data={"hostname": "x"},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_admin_make_csr_returns_attachment(
        self, client, admin_cookies, app, tmp_path,
    ):
        _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/make",
            data={
                "hostname": "triage.example.com",
                "extra_sans": "alt.example.com,10.0.0.5",
                "organization": "TestOrg",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 200, resp.text[:500]
        assert "attachment" in resp.headers.get("content-disposition", "")
        assert ".csr" in resp.headers.get("content-disposition", "")
        assert resp.content.startswith(b"-----BEGIN CERTIFICATE REQUEST-----")

    def test_make_with_pending_redirects_with_error(
        self, client, admin_cookies, app, tmp_path,
    ):
        cd = _set_cert_dir(app, tmp_path)
        tls_csr.make_csr(cd, hostname="first.example.com")
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/make",
            data={"hostname": "second.example.com"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "err=" in resp.headers["location"]

    def test_audit_event_written(
        self, client, admin_cookies, app, db, admin_user, tmp_path,
    ):
        _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.post(
            "/admin/tls/csr/make",
            data={"hostname": "audit.example.com"},
            follow_redirects=False,
        )
        rows = db.execute(
            "SELECT event_type, outcome, email FROM auth_events "
            "WHERE event_type = 'tls_csr_make' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"


# ---------------------------------------------------------------------------
# POST /admin/tls/csr/import
# ---------------------------------------------------------------------------

class TestImport:
    def test_round_trip_paste(self, client, admin_cookies, app, tmp_path):
        cd = _set_cert_dir(app, tmp_path)
        _, _, csr_pem = tls_csr.make_csr(cd, hostname="rt.example.com")
        signed = _sign_with_test_ca(csr_pem)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/import",
            data={"cert_pem": signed.decode("utf-8")},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "saved=1" in resp.headers["location"]
        # Files in place.
        assert (cd / tls_csr.CERT_FILENAME).is_file()
        assert (cd / tls_csr.KEY_FILENAME).is_file()
        # Pending cleaned up.
        assert not (cd / tls_csr.PENDING_KEY_FILENAME).is_file()

    def test_invalid_pem_redirects_with_error(
        self, client, admin_cookies, app, tmp_path,
    ):
        cd = _set_cert_dir(app, tmp_path)
        tls_csr.make_csr(cd, hostname="x.example.com")
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/import",
            data={"cert_pem": "not a real PEM"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "err=" in resp.headers["location"]
        # No swap happened.
        assert not (cd / tls_csr.CERT_FILENAME).is_file()

    def test_no_pending_redirects_with_error(
        self, client, admin_cookies, app, tmp_path,
    ):
        _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/import",
            data={"cert_pem": "----- BEGIN CERTIFICATE -----"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert "err=" in resp.headers["location"]


# ---------------------------------------------------------------------------
# POST /admin/tls/csr/cancel
# ---------------------------------------------------------------------------

class TestCancel:
    def test_clears_pending(self, client, admin_cookies, app, tmp_path):
        cd = _set_cert_dir(app, tmp_path)
        tls_csr.make_csr(cd, hostname="x.example.com")
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/cancel", follow_redirects=False,
        )
        assert resp.status_code == 303
        assert not (cd / tls_csr.PENDING_KEY_FILENAME).is_file()
        assert not (cd / tls_csr.PENDING_CSR_FILENAME).is_file()


# ---------------------------------------------------------------------------
# POST /admin/tls/csr/self-sign
# ---------------------------------------------------------------------------

class TestSelfSign:
    def test_writes_active_files(
        self, client, admin_cookies, app, tmp_path,
    ):
        cd = _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        resp = client.post(
            "/admin/tls/csr/self-sign",
            data={
                "hostname": "ss.example.com",
                "valid_days": "30",
            },
            follow_redirects=False,
        )
        assert resp.status_code == 303
        assert (cd / tls_csr.CERT_FILENAME).is_file()
        assert (cd / tls_csr.KEY_FILENAME).is_file()
        # Cert valid days actually applied.
        md = tls_csr.cert_metadata((cd / tls_csr.CERT_FILENAME).read_bytes())
        # 30 - test latency = 29 or 30.
        assert 28 <= md["days_until_expiry"] <= 30

    def test_audit_event_written(
        self, client, admin_cookies, app, db, tmp_path,
    ):
        _set_cert_dir(app, tmp_path)
        client.cookies.set(SESSION_COOKIE_NAME, admin_cookies[SESSION_COOKIE_NAME])
        client.post(
            "/admin/tls/csr/self-sign",
            data={"hostname": "ss.example.com", "valid_days": "365"},
            follow_redirects=False,
        )
        rows = db.execute(
            "SELECT event_type, outcome FROM auth_events "
            "WHERE event_type = 'tls_csr_self_sign' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "success"
