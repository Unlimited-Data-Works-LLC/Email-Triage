"""Punch 444: a lower-counter replay against the REAL webauthn library, no patched verify call.

``tests/test_webauthn.py`` patches ``verify_authentication_response`` out, and the 2026-08-27
browser bar (docs/registers/webauthn-3.0.0-evidence-bar-cfaed3f223ae.md) could not mint a
properly signed assertion with a lowered counter: Chrome's virtual authenticator signs what it
is given, and editing the counter afterwards breaks the signature, so a refusal would not be
attributable to the counter check. A software authenticator in the test signs the lowered
counter itself, so the signature is VALID and the only thing wrong with the assertion is the
counter.

Everything below runs ``begin_authentication`` / ``finish_authentication`` and the library's
real ``verify_registration_response`` / ``verify_authentication_response``; the authenticator is
an in-test EC P-256 key (generated per test, no stored secret). The tests hold:

  * POSITIVE CONTROL on the same handler: a higher counter is accepted and stored.
  * a lower and an equal counter, correctly signed, are refused with ``WebAuthnSignCountError``
    and the stored count does not move;
  * the refusal is DISTINGUISHABLE: a flipped signature byte, a missing id, bad JSON and an
    unknown credential id raise ``WebAuthnAuthError`` and not the sign-count subclass;
  * after a refusal a legitimate higher counter still authenticates (not a lockout);
  * LIMIT, characterised not endorsed: stored 0 and presented 0 is accepted by the library
    (synced passkeys report 0), so replay protection there is the single-use challenge.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn import verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, encode_cbor

import email_triage.web.webauthn_auth as wa
from email_triage.web.db import init_db
from email_triage.web.db_auth_helpers import add_hardware_key, list_hardware_keys

# CBOR goes through webauthn's own public encoder (cycle P Q8, standing DA ruling): cbor2 is
# only a transitive dependency of webauthn, so this file never imports it and no skip can hide
# the test.

RP_ID = "example.com"
ORIGIN = "https://example.com"
EMAIL = "user@example.com"


class SoftwareAuthenticator:
    """A minimal ES256 platform authenticator: registers with 'none' attestation and signs
    assertions over authenticatorData || SHA-256(clientDataJSON), as the spec requires."""

    def __init__(self) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.credential_id = os.urandom(32)

    def _cose_key(self) -> bytes:
        n = self.key.public_key().public_numbers()
        return encode_cbor({
            1: 2, 3: -7, -1: 1,
            -2: n.x.to_bytes(32, "big"), -3: n.y.to_bytes(32, "big"),
        })

    @staticmethod
    def _client_data(kind: str, challenge: bytes) -> bytes:
        return json.dumps({
            "type": kind, "challenge": bytes_to_base64url(challenge),
            "origin": ORIGIN, "crossOrigin": False,
        }).encode()

    def register(self, challenge: bytes, sign_count: int = 0) -> dict:
        cose = self._cose_key()
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest() + bytes([0x45])
            + sign_count.to_bytes(4, "big") + b"\x00" * 16
            + len(self.credential_id).to_bytes(2, "big") + self.credential_id + cose
        )
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(self._client_data("webauthn.create", challenge)),
                "attestationObject": bytes_to_base64url(attestation),
            },
            "clientExtensionResults": {},
        }

    def assertion(self, challenge: bytes, sign_count: int, *, flip_signature: bool = False) -> dict:
        client_data = self._client_data("webauthn.get", challenge)
        auth_data = (
            hashlib.sha256(RP_ID.encode()).digest() + bytes([0x05])  # UP | UV
            + sign_count.to_bytes(4, "big")
        )
        sig = self.key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        if flip_signature:
            sig = sig[:-1] + bytes([sig[-1] ^ 0x01])  # still valid DER, no longer a valid signature
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(sig),
            },
            "clientExtensionResults": {},
        }


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    from _db_tracking import track
    return track(init_db(str(tmp_path / "test.db")))


@pytest.fixture
def user_id(db) -> int:
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        (EMAIL, "User", "user", datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return cur.lastrowid


@pytest.fixture
def enrolled(db, user_id):
    """A credential registered through the library's real verify_registration_response."""
    auth = SoftwareAuthenticator()
    challenge = os.urandom(32)
    reg = verify_registration_response(
        credential=auth.register(challenge),
        expected_challenge=challenge, expected_rp_id=RP_ID, expected_origin=ORIGIN,
    )
    kid = add_hardware_key(
        db, user_id=user_id, credential_id=reg.credential_id,
        public_key=reg.credential_public_key, sign_count=reg.sign_count,
        transports=[], aaguid=None, nickname="software-authenticator",
    )
    return auth, kid


def _stored_count(db, user_id, kid) -> int:
    return int(next(r for r in list_hardware_keys(db, user_id) if r["id"] == kid)["sign_count"])


def _login(db, user_id, auth, sign_count, **kw):
    opts = json.loads(wa.begin_authentication(db, user_id=user_id, email=EMAIL, rp_id=RP_ID))
    response = auth.assertion(base64url_to_bytes(opts["challenge"]), sign_count, **kw)
    return wa.finish_authentication(
        db, user_id=user_id, rp_id=RP_ID, origin=ORIGIN, response_json=response,
    )


def test_positive_control_a_higher_counter_is_accepted_and_stored(db, user_id, enrolled):
    auth, kid = enrolled
    assert _login(db, user_id, auth, 5) == kid
    assert _stored_count(db, user_id, kid) == 5
    assert _login(db, user_id, auth, 6) == kid
    assert _stored_count(db, user_id, kid) == 6


@pytest.mark.parametrize("replayed", [3, 5])  # lower than stored, and equal to it
def test_a_correctly_signed_assertion_with_a_non_advancing_counter_is_refused(
    db, user_id, enrolled, replayed
):
    auth, kid = enrolled
    _login(db, user_id, auth, 5)
    with pytest.raises(wa.WebAuthnSignCountError) as info:
        _login(db, user_id, auth, replayed)
    assert "sign count" in str(info.value).lower()
    assert _stored_count(db, user_id, kid) == 5, "a refused assertion must not move the stored count"


def test_a_refusal_is_not_a_lockout(db, user_id, enrolled):
    auth, kid = enrolled
    _login(db, user_id, auth, 5)
    with pytest.raises(wa.WebAuthnSignCountError):
        _login(db, user_id, auth, 3)
    assert _login(db, user_id, auth, 7) == kid
    assert _stored_count(db, user_id, kid) == 7


def test_the_counter_refusal_is_distinguishable_from_malformed_payloads(db, user_id, enrolled):
    auth, kid = enrolled
    _login(db, user_id, auth, 5)

    # valid higher counter, flipped signature byte: refused, but NOT as a counter refusal
    with pytest.raises(wa.WebAuthnAuthError) as bad_sig:
        _login(db, user_id, auth, 9, flip_signature=True)
    assert not isinstance(bad_sig.value, wa.WebAuthnSignCountError)
    assert "sign count" not in str(bad_sig.value).lower()

    def finish_with(response_json):
        opts = json.loads(wa.begin_authentication(db, user_id=user_id, email=EMAIL, rp_id=RP_ID))
        assert opts["challenge"]
        return wa.finish_authentication(
            db, user_id=user_id, rp_id=RP_ID, origin=ORIGIN, response_json=response_json,
        )

    good = auth.assertion(os.urandom(32), 9)
    no_id = {k: v for k, v in good.items() if k != "id"}
    unknown_id = dict(good, id=bytes_to_base64url(os.urandom(32)))
    for payload in ("{not json", no_id, unknown_id):
        with pytest.raises(wa.WebAuthnAuthError) as bad:
            finish_with(payload)
        assert not isinstance(bad.value, wa.WebAuthnSignCountError), payload
    assert _stored_count(db, user_id, kid) == 5


def test_limit_zero_counters_are_not_checked_by_the_library(db, user_id, enrolled):
    """Characterisation: stored 0 and presented 0 passes twice. A synced passkey reports 0,
    so for those the control is the single-use challenge (punch 449), not the counter."""
    auth, kid = enrolled
    assert _stored_count(db, user_id, kid) == 0
    assert _login(db, user_id, auth, 0) == kid
    assert _login(db, user_id, auth, 0) == kid
