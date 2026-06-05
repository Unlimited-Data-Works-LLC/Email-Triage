"""Tests for session-cookie payload extension.

Adds ``auth_source`` + ``auth_key_id`` to the payload while preserving
back-compat with cookies minted before the upgrade.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from starlette.responses import Response

from email_triage.web.auth import (
    SESSION_COOKIE_NAME,
    create_session_token,
    set_session_cookie,
    verify_session_token,
)


SECRET = "test-session-secret-1234567890"


def test_legacy_payload_decodes_as_otp():
    """A token minted with the old 2-arg signature must decode with
    ``auth_source='otp'`` + ``auth_key_id=None`` (back-compat for any
    sessions that survive the upgrade in operator browsers)."""
    # Old-style signature has no auth_source / auth_key_id.
    token = create_session_token(SECRET, "a@b.com", "admin")
    payload = verify_session_token(SECRET, token)
    assert payload is not None
    assert payload["email"] == "a@b.com"
    assert payload["role"] == "admin"
    assert payload["auth_source"] == "otp"
    assert payload["auth_key_id"] is None


def test_new_payload_round_trips():
    """auth_source + auth_key_id round-trip through serialize/verify."""
    token = create_session_token(
        SECRET, "x@y.com", "user",
        auth_source="webauthn", auth_key_id=42,
    )
    payload = verify_session_token(SECRET, token)
    assert payload is not None
    assert payload["auth_source"] == "webauthn"
    assert payload["auth_key_id"] == 42


def test_dev_keypair_payload_round_trips():
    token = create_session_token(
        SECRET, "ops@x.com", "admin",
        auth_source="dev_keypair", auth_key_id=7,
    )
    payload = verify_session_token(SECRET, token)
    assert payload["auth_source"] == "dev_keypair"
    assert payload["auth_key_id"] == 7


def test_tampered_token_rejected():
    """Bit-flipped tokens must fail verification."""
    token = create_session_token(SECRET, "a@b.com", "admin")
    bad = token + "x"
    assert verify_session_token(SECRET, bad) is None


def test_wrong_secret_rejected():
    """Different secret can't verify the token (signature mismatch)."""
    token = create_session_token(SECRET, "a@b.com", "admin")
    assert verify_session_token("different-secret", token) is None


# ---------------------------------------------------------------------------
# set_session_cookie —  Secure-flag gating
# ---------------------------------------------------------------------------

def _session_set_cookie_header(config) -> str:
    """Run set_session_cookie against a fresh Response, return its
    single Set-Cookie header."""
    resp = Response()
    set_session_cookie(resp, "tok123", config)
    cookies = [
        v.decode() for k, v in resp.raw_headers if k == b"set-cookie"
    ]
    assert len(cookies) == 1
    return cookies[0]


def test_session_cookie_secure_when_tls_enabled():
    """ — on a TLS install the session cookie MUST carry Secure,
    so the session token can't ride a plaintext request."""
    header = _session_set_cookie_header(
        SimpleNamespace(tls=SimpleNamespace(enabled=True), auth=None)
    )
    assert SESSION_COOKIE_NAME in header
    assert "; Secure" in header
    assert "HttpOnly" in header
    assert "samesite=lax" in header.lower()


def test_session_cookie_not_secure_without_tls():
    """Plain-HTTP dev/LAN install: no Secure flag — else the browser
    would never send the cookie and login would silently break."""
    header = _session_set_cookie_header(
        SimpleNamespace(tls=SimpleNamespace(enabled=False), auth=None)
    )
    assert "; Secure" not in header


def test_session_cookie_tls_block_missing_degrades_safely():
    """A config with no tls block degrades to not-Secure, not a crash."""
    header = _session_set_cookie_header(SimpleNamespace(auth=None))
    assert "; Secure" not in header
