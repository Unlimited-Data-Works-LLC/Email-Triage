"""Tests for the dev-keypair module + DB helpers (#67)."""

from __future__ import annotations

import base64
import sqlite3
import struct
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from email_triage.web.dev_keypair import (
    DevKeyParseError,
    fingerprint,
    generate_login_challenge,
    parse_ssh_ed25519_pubkey,
    verify_signature,
)
from email_triage.web.db import init_db
from email_triage.web.db_auth_helpers import (
    add_dev_key,
    find_dev_key_by_fingerprint,
    is_dev_key_active,
    list_dev_keys,
    mark_dev_key_used,
    revoke_dev_key,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _build_pubkey_text(priv: ed25519.Ed25519PrivateKey, comment: str = "test") -> str:
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    blob = (
        struct.pack(">I", 11) + b"ssh-ed25519"
        + struct.pack(">I", 32) + pub_raw
    )
    return f"ssh-ed25519 {base64.b64encode(blob).decode()} {comment}"


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    return init_db(str(tmp_path / "test.db"))


@pytest.fixture
def keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    return priv, _build_pubkey_text(priv)


# ---------------------------------------------------------------------------
# parse_ssh_ed25519_pubkey
# ---------------------------------------------------------------------------

class TestParse:
    def test_valid_round_trip(self, keypair):
        priv, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        assert parsed.keytype == "ssh-ed25519"
        assert len(parsed.raw_pubkey) == 32
        assert parsed.comment == "test"

    def test_empty_input_rejected(self):
        with pytest.raises(DevKeyParseError, match="Empty"):
            parse_ssh_ed25519_pubkey("")

    def test_only_keytype_rejected(self):
        with pytest.raises(DevKeyParseError, match="at least"):
            parse_ssh_ed25519_pubkey("ssh-ed25519")

    def test_rsa_key_rejected(self):
        # ssh-rsa key would have keytype != ssh-ed25519.
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        text = priv.public_key().public_bytes(
            serialization.Encoding.OpenSSH,
            serialization.PublicFormat.OpenSSH,
        ).decode()
        with pytest.raises(DevKeyParseError, match="ssh-ed25519"):
            parse_ssh_ed25519_pubkey(text)

    def test_malformed_base64_rejected(self):
        with pytest.raises(DevKeyParseError, match="base64"):
            parse_ssh_ed25519_pubkey("ssh-ed25519 !!!notbase64!!!")

    def test_truncated_blob_rejected(self):
        # Build a wire blob that lies about its inner length.
        bad_blob = struct.pack(">I", 100) + b"ssh-ed25519"  # claims 100 bytes
        text = "ssh-ed25519 " + base64.b64encode(bad_blob).decode()
        with pytest.raises(DevKeyParseError, match="Truncated"):
            parse_ssh_ed25519_pubkey(text)


class TestFingerprint:
    def test_format(self, keypair):
        _, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        fp = fingerprint(parsed)
        assert fp.startswith("SHA256:")
        # Stripped padding: no trailing '='.
        assert not fp.endswith("=")

    def test_stable_across_calls(self, keypair):
        _, text = keypair
        p1 = parse_ssh_ed25519_pubkey(text)
        p2 = parse_ssh_ed25519_pubkey(text)
        assert fingerprint(p1) == fingerprint(p2)

    def test_different_keys_different_fp(self):
        priv_a = ed25519.Ed25519PrivateKey.generate()
        priv_b = ed25519.Ed25519PrivateKey.generate()
        fp_a = fingerprint(parse_ssh_ed25519_pubkey(_build_pubkey_text(priv_a)))
        fp_b = fingerprint(parse_ssh_ed25519_pubkey(_build_pubkey_text(priv_b)))
        assert fp_a != fp_b


class TestVerifySignature:
    def test_valid_signature_passes(self, keypair):
        priv, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        msg = b"login challenge bytes"
        sig = priv.sign(msg)
        assert verify_signature(parsed, msg, sig) is True

    def test_wrong_key_fails(self, keypair):
        priv, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        # Sign with a DIFFERENT key.
        other = ed25519.Ed25519PrivateKey.generate()
        sig = other.sign(b"msg")
        assert verify_signature(parsed, b"msg", sig) is False

    def test_wrong_message_fails(self, keypair):
        priv, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        sig = priv.sign(b"original")
        assert verify_signature(parsed, b"tampered", sig) is False

    def test_garbage_signature_returns_false_not_raise(self, keypair):
        _, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        # Defensive — verify_signature must never propagate exceptions.
        assert verify_signature(parsed, b"msg", b"too short") is False


def test_generate_login_challenge_size_and_uniqueness():
    a = generate_login_challenge()
    b = generate_login_challenge()
    assert len(a) == 32
    assert a != b


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------

class TestDevKeyDbHelpers:
    def test_add_and_lookup_round_trip(self, db, keypair):
        _, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        fp = fingerprint(parsed)
        kid = add_dev_key(
            db, name="laptop", public_key=text, fingerprint=fp,
            email_allowlist=["a@b.com"], created_by_user_id=None,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        row = find_dev_key_by_fingerprint(db, fp)
        assert row is not None
        assert row["id"] == kid
        assert row["email_allowlist"] == ["a@b.com"]

    def test_duplicate_fingerprint_rejected(self, db, keypair):
        _, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        fp = fingerprint(parsed)
        add_dev_key(
            db, name="A", public_key=text, fingerprint=fp,
            email_allowlist=["a@b.com"], created_by_user_id=None,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        with pytest.raises(sqlite3.IntegrityError):
            add_dev_key(
                db, name="B", public_key=text, fingerprint=fp,
                email_allowlist=["a@b.com"], created_by_user_id=None,
                expires_at="2099-01-01T00:00:00+00:00",
            )

    def test_revoke_sets_timestamp(self, db, keypair):
        _, text = keypair
        parsed = parse_ssh_ed25519_pubkey(text)
        fp = fingerprint(parsed)
        kid = add_dev_key(
            db, name="x", public_key=text, fingerprint=fp,
            email_allowlist=["a@b.com"], created_by_user_id=None,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        assert revoke_dev_key(db, kid, revoked_by_user_id=None) is True
        # Idempotent — second call returns False.
        assert revoke_dev_key(db, kid, revoked_by_user_id=None) is False
        row = find_dev_key_by_fingerprint(db, fp)
        assert row["revoked_at"] is not None

    def test_mark_used_stamps_metadata(self, db, keypair):
        _, text = keypair
        fp = fingerprint(parse_ssh_ed25519_pubkey(text))
        kid = add_dev_key(
            db, name="x", public_key=text, fingerprint=fp,
            email_allowlist=["a@b.com"], created_by_user_id=None,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        mark_dev_key_used(db, kid, email="a@b.com", ip="10.0.0.1")
        row = find_dev_key_by_fingerprint(db, fp)
        assert row["last_used_email"] == "a@b.com"
        assert row["last_used_ip"] == "10.0.0.1"
        assert row["last_used_at"] is not None

    def test_is_active_checks_expiry_and_revoke(self):
        future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        now = datetime.now(timezone.utc).isoformat()
        assert is_dev_key_active(
            {"revoked_at": None, "expires_at": future}, now,
        ) is True
        assert is_dev_key_active(
            {"revoked_at": None, "expires_at": past}, now,
        ) is False
        assert is_dev_key_active(
            {"revoked_at": now, "expires_at": future}, now,
        ) is False

    def test_list_returns_all_including_revoked(self, db, keypair):
        _, text = keypair
        fp = fingerprint(parse_ssh_ed25519_pubkey(text))
        kid = add_dev_key(
            db, name="x", public_key=text, fingerprint=fp,
            email_allowlist=["a@b.com"], created_by_user_id=None,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        revoke_dev_key(db, kid, revoked_by_user_id=None)
        keys = list_dev_keys(db)
        assert len(keys) == 1
        assert keys[0]["revoked_at"] is not None
