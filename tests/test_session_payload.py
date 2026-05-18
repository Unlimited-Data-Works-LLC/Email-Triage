"""Tests for session-cookie payload extension (#67).

Adds ``auth_source`` + ``auth_key_id`` to the payload while preserving
back-compat with cookies minted before the upgrade.
"""

from __future__ import annotations

import pytest

from email_triage.web.auth import (
    create_session_token,
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
