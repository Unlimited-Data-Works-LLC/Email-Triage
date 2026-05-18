"""Tests for the WebAuthn / FIDO2 module + DB helpers (#67).

The full ceremony (browser-side ``navigator.credentials.create/get``)
needs a real authenticator and is covered by manual smoke tests in
the deploy doc. These tests cover what we can isolate:

* ``WebAuthnConfigError`` raised when rp_id / origin missing.
* ``user_has_active_hardware_key`` reflects DB state.
* hardware_keys CRUD round-trips correctly.
* WebAuthn challenge store / consume single-use semantics.
* ``get_or_create_webauthn_user_handle`` is stable across calls.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from email_triage.web.db import init_db
from email_triage.web.db_auth_helpers import (
    add_hardware_key,
    consume_webauthn_challenge,
    find_hardware_key_by_credential_id,
    find_user_by_webauthn_handle,
    get_or_create_webauthn_user_handle,
    list_hardware_keys,
    prune_expired_webauthn_challenges,
    revoke_hardware_key,
    store_webauthn_challenge,
    update_hardware_key_sign_count,
    user_has_active_hardware_key,
)
from email_triage.web.webauthn_auth import (
    WebAuthnConfigError,
    begin_authentication,
    begin_registration,
    finish_authentication,
    finish_registration,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    return init_db(str(tmp_path / "test.db"))


@pytest.fixture
def user_id(db) -> int:
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) "
        "VALUES (?, ?, ?, ?)",
        ("user@example.com", "User", "user",
         datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return cur.lastrowid


# ---------------------------------------------------------------------------
# user_has_active_hardware_key
# ---------------------------------------------------------------------------

class TestUserHasActiveHardwareKey:
    def test_no_keys_returns_false(self, db, user_id):
        assert user_has_active_hardware_key(db, user_id) is False

    def test_active_key_returns_true(self, db, user_id):
        add_hardware_key(
            db, user_id=user_id, credential_id=b"\x01" * 16,
            public_key=b"pubkey", sign_count=0,
            transports=["usb"], aaguid=None, nickname="yk1",
        )
        assert user_has_active_hardware_key(db, user_id) is True

    def test_revoked_key_returns_false(self, db, user_id):
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=b"\x02" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="yk2",
        )
        revoke_hardware_key(db, kid)
        assert user_has_active_hardware_key(db, user_id) is False

    def test_other_users_keys_do_not_count(self, db, user_id):
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("other@example.com", "Other", "user",
             datetime.now(timezone.utc).isoformat()),
        )
        other_id = cur.lastrowid
        db.commit()
        add_hardware_key(
            db, user_id=other_id, credential_id=b"\x03" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="other",
        )
        assert user_has_active_hardware_key(db, user_id) is False
        assert user_has_active_hardware_key(db, other_id) is True


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

class TestHardwareKeyCrud:
    def test_round_trip_lookup(self, db, user_id):
        cred_id = b"\xaa" * 32
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=cred_id,
            public_key=b"COSE-encoded", sign_count=0,
            transports=["usb", "nfc"], aaguid=b"\x00" * 16,
            nickname="YubiKey Blue",
        )
        row = find_hardware_key_by_credential_id(db, cred_id)
        assert row is not None
        assert row["id"] == kid
        assert row["nickname"] == "YubiKey Blue"

    def test_revoked_key_not_returned_by_credential_lookup(self, db, user_id):
        cred_id = b"\xbb" * 16
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=cred_id,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="x",
        )
        revoke_hardware_key(db, kid)
        assert find_hardware_key_by_credential_id(db, cred_id) is None

    def test_list_excludes_revoked_by_default(self, db, user_id):
        kid_active = add_hardware_key(
            db, user_id=user_id, credential_id=b"\x01" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="active",
        )
        kid_revoked = add_hardware_key(
            db, user_id=user_id, credential_id=b"\x02" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="revoked",
        )
        revoke_hardware_key(db, kid_revoked)
        active = list_hardware_keys(db, user_id)
        all_ = list_hardware_keys(db, user_id, include_revoked=True)
        assert len(active) == 1 and active[0]["id"] == kid_active
        assert len(all_) == 2

    def test_sign_count_update(self, db, user_id):
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=b"\xcc" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="x",
        )
        update_hardware_key_sign_count(db, kid, 5)
        rows = list_hardware_keys(db, user_id)
        assert rows[0]["sign_count"] == 5
        assert rows[0]["last_used_at"] is not None


# ---------------------------------------------------------------------------
# webauthn_user_handle
# ---------------------------------------------------------------------------

class TestUserHandle:
    def test_lazy_generation(self, db, user_id):
        h = get_or_create_webauthn_user_handle(db, user_id)
        assert isinstance(h, bytes)
        assert len(h) == 32

    def test_stable_across_calls(self, db, user_id):
        h1 = get_or_create_webauthn_user_handle(db, user_id)
        h2 = get_or_create_webauthn_user_handle(db, user_id)
        assert h1 == h2

    def test_reverse_lookup(self, db, user_id):
        h = get_or_create_webauthn_user_handle(db, user_id)
        u = find_user_by_webauthn_handle(db, h)
        assert u is not None
        assert u["id"] == user_id


# ---------------------------------------------------------------------------
# Challenge store
# ---------------------------------------------------------------------------

class TestChallengeStore:
    def test_store_and_consume_round_trip(self, db, user_id):
        cid = store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
            challenge=b"abc",
        )
        assert cid > 0
        ch = consume_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
        )
        assert ch == b"abc"

    def test_consume_is_single_use(self, db, user_id):
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
            challenge=b"abc",
        )
        consume_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
        )
        # Second consume returns None.
        ch2 = consume_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
        )
        assert ch2 is None

    def test_kind_isolation(self, db, user_id):
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
            challenge=b"reg",
        )
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"auth",
        )
        # Each kind has its own challenge.
        assert consume_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
        ) == b"reg"
        assert consume_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
        ) == b"auth"

    def test_email_keyed_lookup(self, db):
        # Email-keyed challenges (used during the authenticate flow
        # before user resolution).
        store_webauthn_challenge(
            db, user_id=None, email="x@y.com", kind="authenticate",
            challenge=b"e",
        )
        assert consume_webauthn_challenge(
            db, user_id=None, email="x@y.com", kind="authenticate",
        ) == b"e"

    def test_prune_removes_expired(self, db, user_id):
        # Insert a challenge with TTL=0 — already expired.
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
            challenge=b"old", ttl_seconds=0,
        )
        # Sleep is unnecessary — TTL of 0 puts expires_at == now, which
        # the prune query (expires_at <= now) catches.
        n = prune_expired_webauthn_challenges(db)
        assert n >= 1


# ---------------------------------------------------------------------------
# WebAuthnConfigError
# ---------------------------------------------------------------------------

class TestConfigError:
    def test_begin_registration_without_rp_id_raises(self, db, user_id):
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        with pytest.raises(WebAuthnConfigError):
            begin_registration(db, user=user, rp_id="", rp_name="")

    def test_begin_authentication_without_rp_id_raises(self, db, user_id):
        # Need an active hw key first or it raises the no-credential
        # error before the config check. So add one.
        add_hardware_key(
            db, user_id=user_id, credential_id=b"\x99" * 16,
            public_key=b"p", sign_count=0,
            transports=[], aaguid=None, nickname="x",
        )
        with pytest.raises(WebAuthnConfigError):
            begin_authentication(
                db, user_id=user_id, email="u@e.com", rp_id="",
            )


# ---------------------------------------------------------------------------
# finish_registration / finish_authentication — integration shape
#
# These tests mock out the webauthn library's verify_*_response calls
# and exercise the rest of finish_registration / finish_authentication
# end-to-end against a real DB. Their job is to lock in the integration
# shape between *our* code and the library's output dataclasses
# (VerifiedRegistration / VerifiedAuthentication).
#
# Why this matters: the prior breakage path was a string of single-
# field shape changes in the webauthn library (parse_obj -> model_validate
# -> direct dict; aaguid: bytes -> str) that each blew up in production
# because nothing exercised the verify-then-DB-write path under test.
# When the library bumps again and changes a field, the failure should
# surface here, not in the operator's browser.
#
# To update the mock when the library shape changes: edit the
# _make_verified_registration / _make_verified_authentication factories
# to match the new dataclass attributes; the test will fail here first
# if our code can't handle the new shape.
# ---------------------------------------------------------------------------

class TestFinishRegistrationIntegration:
    """Lock in the verify_registration_response -> add_hardware_key
    bridge. Mocks the library's verify call to avoid needing a real
    crypto authenticator."""

    def _make_verified_registration(
        self, *, aaguid_str: str = "00000000-0000-0000-0000-000000000000",
    ):
        """Construct a stand-in for VerifiedRegistration. We use
        SimpleNamespace so the test stays robust against the library
        adding new fields -- our code only reads a known subset."""
        from types import SimpleNamespace
        return SimpleNamespace(
            credential_id=b"\xaa" * 32,
            credential_public_key=b"COSE-encoded-pk",
            sign_count=0,
            aaguid=aaguid_str,  # library 2.7.x returns str, not bytes
        )

    def _setup_pending_register(self, db, user_id):
        """Stash a register-kind challenge so finish_registration can
        find one to consume. Real value doesn't matter -- we mock the
        verify call that would check it."""
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="register",
            challenge=b"fake-challenge",
        )

    def test_aaguid_as_str_uuid_is_accepted_and_stored_as_bytes(
        self, db, user_id, monkeypatch,
    ):
        """Reproduces the 2026-04-29 production crash: lib hands us
        aaguid as a UUID-formatted string; old code tried bytes(str)
        and raised TypeError. New code converts via uuid.UUID().bytes
        so the DB column shape stays consistent."""
        self._setup_pending_register(db, user_id)
        verified = self._make_verified_registration(
            aaguid_str="abcdef00-1234-5678-9abc-def012345678",
        )
        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_registration_response",
            lambda **kwargs: verified,
        )
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        new_id = finish_registration(
            db, user=user, rp_id="example.com",
            origin="https://example.com",
            response_json={"id": "x", "rawId": "x", "type": "public-key",
                           "response": {"transports": ["usb"]}},
            nickname="YubiKey",
        )
        assert new_id > 0
        rows = list_hardware_keys(db, user_id)
        assert len(rows) == 1
        assert rows[0]["nickname"] == "YubiKey"
        # aaguid stored as 16 raw bytes (UUID(...).bytes form).
        assert rows[0]["aaguid"] == bytes.fromhex(
            "abcdef0012345678" "9abcdef012345678",
        )

    def test_aaguid_as_bytes_still_accepted(
        self, db, user_id, monkeypatch,
    ):
        """Defensive: if the library bumps back to bytes, our converter
        passes them through unchanged."""
        self._setup_pending_register(db, user_id)
        from types import SimpleNamespace
        verified = SimpleNamespace(
            credential_id=b"\xbb" * 32,
            credential_public_key=b"pk",
            sign_count=0,
            aaguid=b"\x12" * 16,  # bytes form
        )
        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_registration_response",
            lambda **kwargs: verified,
        )
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        new_id = finish_registration(
            db, user=user, rp_id="example.com",
            origin="https://example.com",
            response_json={"id": "x", "rawId": "x", "type": "public-key",
                           "response": {"transports": []}},
            nickname="key2",
        )
        rows = list_hardware_keys(db, user_id)
        assert rows[0]["aaguid"] == b"\x12" * 16

    def test_aaguid_none_writes_null(self, db, user_id, monkeypatch):
        self._setup_pending_register(db, user_id)
        verified = self._make_verified_registration(aaguid_str="")
        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_registration_response",
            lambda **kwargs: verified,
        )
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        finish_registration(
            db, user=user, rp_id="example.com",
            origin="https://example.com",
            response_json={"id": "x", "rawId": "x", "type": "public-key",
                           "response": {"transports": []}},
            nickname="k",
        )
        rows = list_hardware_keys(db, user_id)
        assert rows[0]["aaguid"] is None

    def test_origin_can_be_a_list(self, db, user_id, monkeypatch):
        """Route layer passes a list of allowed origins (configured +
        request Origin header). webauthn lib accepts Union[str, list]."""
        self._setup_pending_register(db, user_id)
        captured = {}

        def fake_verify(**kwargs):
            captured.update(kwargs)
            return self._make_verified_registration()

        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_registration_response",
            fake_verify,
        )
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        finish_registration(
            db, user=user, rp_id="example.com",
            origin=["https://example.com", "https://example.com:8081"],
            response_json={"id": "x", "rawId": "x", "type": "public-key",
                           "response": {"transports": []}},
            nickname="k",
        )
        assert captured["expected_origin"] == [
            "https://example.com", "https://example.com:8081",
        ]

    def test_no_pending_challenge_raises(self, db, user_id, monkeypatch):
        # No store_webauthn_challenge call -> consume returns None.
        # verify shouldn't be called at all in this path; sentinel
        # ensures it isn't.
        def fail_if_called(**_):
            raise AssertionError("verify_registration_response called")

        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_registration_response",
            fail_if_called,
        )
        from email_triage.web.webauthn_auth import WebAuthnAuthError
        user = {"id": user_id, "email": "u@e.com", "name": "U", "role": "user"}
        with pytest.raises(WebAuthnAuthError):
            finish_registration(
                db, user=user, rp_id="example.com",
                origin="https://example.com",
                response_json={"id": "x", "rawId": "x", "type": "public-key",
                               "response": {"transports": []}},
                nickname="k",
            )


class TestFinishAuthenticationIntegration:
    """Lock in the verify_authentication_response -> sign_count update
    bridge."""

    def _make_verified_authentication(self, *, new_count: int = 1):
        from types import SimpleNamespace
        return SimpleNamespace(new_sign_count=new_count)

    def test_sign_count_update_round_trip(self, db, user_id, monkeypatch):
        """Verify path: existing hardware key, mock library verify,
        finish_authentication updates sign_count and returns key id."""
        cred_id = b"\xcc" * 32
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=cred_id,
            public_key=b"pk", sign_count=0,
            transports=[], aaguid=None, nickname="yk",
        )
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"ch",
        )
        verified = self._make_verified_authentication(new_count=42)
        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_authentication_response",
            lambda **kwargs: verified,
        )
        # Browser-shaped response dict. credential id is the
        # base64url of cred_id.
        from webauthn.helpers import bytes_to_base64url
        response_data = {
            "id": bytes_to_base64url(cred_id),
            "rawId": bytes_to_base64url(cred_id),
            "type": "public-key",
            "response": {
                "authenticatorData": bytes_to_base64url(b"ad"),
                "clientDataJSON": bytes_to_base64url(b"cd"),
                "signature": bytes_to_base64url(b"sig"),
            },
        }
        result = finish_authentication(
            db, user_id=user_id, rp_id="example.com",
            origin="https://example.com",
            response_json=response_data,
        )
        assert result == kid
        rows = list_hardware_keys(db, user_id)
        assert rows[0]["sign_count"] == 42

    def test_unknown_credential_raises(self, db, user_id, monkeypatch):
        """No matching hardware_keys row -> verify is never called."""
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"ch",
        )

        def fail_if_called(**_):
            raise AssertionError("verify_authentication_response called")

        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_authentication_response",
            fail_if_called,
        )
        from webauthn.helpers import bytes_to_base64url
        from email_triage.web.webauthn_auth import WebAuthnAuthError
        response_data = {
            "id": bytes_to_base64url(b"\xff" * 32),
            "rawId": bytes_to_base64url(b"\xff" * 32),
            "type": "public-key",
            "response": {
                "authenticatorData": "",
                "clientDataJSON": "",
                "signature": "",
            },
        }
        with pytest.raises(WebAuthnAuthError):
            finish_authentication(
                db, user_id=user_id, rp_id="example.com",
                origin="https://example.com",
                response_json=response_data,
            )

    def test_credential_belongs_to_other_user_raises(
        self, db, user_id, monkeypatch,
    ):
        """user_id supplied at finish doesn't match the cred row's
        owner -> reject before verify."""
        cur = db.execute(
            "INSERT INTO users (email, name, role, created_at) "
            "VALUES (?, ?, ?, ?)",
            ("other@e.com", "O", "user",
             datetime.now(timezone.utc).isoformat()),
        )
        other_id = cur.lastrowid
        db.commit()
        cred_id = b"\xdd" * 32
        add_hardware_key(
            db, user_id=other_id, credential_id=cred_id,
            public_key=b"pk", sign_count=0,
            transports=[], aaguid=None, nickname="theirs",
        )
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"ch",
        )

        def fail_if_called(**_):
            raise AssertionError("verify called for wrong-owner cred")

        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_authentication_response",
            fail_if_called,
        )
        from webauthn.helpers import bytes_to_base64url
        from email_triage.web.webauthn_auth import WebAuthnAuthError
        response_data = {
            "id": bytes_to_base64url(cred_id),
            "rawId": bytes_to_base64url(cred_id),
            "type": "public-key",
            "response": {
                "authenticatorData": "",
                "clientDataJSON": "",
                "signature": "",
            },
        }
        with pytest.raises(WebAuthnAuthError):
            finish_authentication(
                db, user_id=user_id, rp_id="example.com",
                origin="https://example.com",
                response_json=response_data,
            )


# ---------------------------------------------------------------------------
# sign_count monotonicity probe (audit 2026-04-30 next-cycle deeper dive #1)
#
# The webauthn library's ``verify_authentication_response`` enforces
# ``new_sign_count > stored_sign_count`` as the primary cloned-authenticator
# detector. On regression it raises ``InvalidAuthenticationResponse``. Our
# ``finish_authentication`` catches that and re-raises ``WebAuthnAuthError``;
# the route handler returns 403 ``verify_failed`` to the browser. These
# tests lock in the contract end-to-end so a future maintainer doesn't
# accidentally bypass the check (e.g. by upgrading sign_count BEFORE the
# library verify, by swallowing the exception, or by writing a fresh
# sign_count to the DB even on rejection).
# ---------------------------------------------------------------------------

class TestSignCountMonotonicity:
    """Cloned-authenticator detection ends in a clean reject + no
    DB sign_count bump. Library does the actual comparison; we lock
    in the wrapper behavior."""

    def _make_response_data(self, cred_id_bytes: bytes) -> dict:
        from webauthn.helpers import bytes_to_base64url
        return {
            "id": bytes_to_base64url(cred_id_bytes),
            "rawId": bytes_to_base64url(cred_id_bytes),
            "type": "public-key",
            "response": {
                "authenticatorData": bytes_to_base64url(b"ad"),
                "clientDataJSON": bytes_to_base64url(b"cd"),
                "signature": bytes_to_base64url(b"sig"),
            },
        }

    def test_sign_count_regression_rejects_and_does_not_bump_db(
        self, db, user_id, monkeypatch,
    ):
        """Stored sign_count = 50. Library reports regression
        (InvalidAuthenticationResponse). finish_authentication must
        raise WebAuthnAuthError AND must not write a fresh count to
        the DB row -- the row stays at 50 so a subsequent legitimate
        login can be evaluated against the same baseline."""
        from webauthn.helpers.exceptions import InvalidAuthenticationResponse
        cred_id = b"\xee" * 32
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=cred_id,
            public_key=b"pk", sign_count=50,
            transports=[], aaguid=None, nickname="yk-clone-test",
        )
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"ch",
        )

        def fake_verify(**kwargs):
            assert kwargs.get("credential_current_sign_count") == 50
            raise InvalidAuthenticationResponse("Sign count regression")

        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_authentication_response",
            fake_verify,
        )

        from email_triage.web.webauthn_auth import WebAuthnAuthError
        with pytest.raises(WebAuthnAuthError):
            finish_authentication(
                db, user_id=user_id, rp_id="example.com",
                origin="https://example.com",
                response_json=self._make_response_data(cred_id),
            )

        rows = list_hardware_keys(db, user_id)
        row = next(r for r in rows if r["id"] == kid)
        assert row["sign_count"] == 50

    def test_sign_count_advance_on_success_writes_to_db(
        self, db, user_id, monkeypatch,
    ):
        """Counterpart of the regression test: legitimate auth with
        a fresh sign_count writes the new value."""
        from types import SimpleNamespace
        cred_id = b"\xdd" * 32
        kid = add_hardware_key(
            db, user_id=user_id, credential_id=cred_id,
            public_key=b"pk", sign_count=10,
            transports=[], aaguid=None, nickname="yk-monotonic",
        )
        store_webauthn_challenge(
            db, user_id=user_id, email=None, kind="authenticate",
            challenge=b"ch",
        )
        verified = SimpleNamespace(new_sign_count=11)
        monkeypatch.setattr(
            "email_triage.web.webauthn_auth.verify_authentication_response",
            lambda **kwargs: verified,
        )
        result = finish_authentication(
            db, user_id=user_id, rp_id="example.com",
            origin="https://example.com",
            response_json=self._make_response_data(cred_id),
        )
        assert result == kid
        rows = list_hardware_keys(db, user_id)
        row = next(r for r in rows if r["id"] == kid)
        assert row["sign_count"] == 11
