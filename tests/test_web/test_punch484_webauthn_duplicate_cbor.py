"""Punch 484: py_webauthn 3.0.0 rejects CBOR with duplicate map keys. Does that
reach our handlers as a clean auth failure, or as a 500?

Runs the REAL library (no monkeypatch of verify_*), like punch 481. Each
duplicate-key case has a CONTROL: the same bytes without the duplicate get past
the CBOR parse (and here, succeed), so a refusal is the duplicate key and not
an earlier check.

What 3.0.0 does (read from the 3.0.0 wheel, ``helpers/parse_cbor.py``:
``cbor2.loads(data, allow_duplicate_keys=False)`` -> ``InvalidCBORData``):
  * client-supplied CBOR (attestationObject, authenticatorData) is parsed
    inside the library's own ``except Exception`` and re-raised as
    ``InvalidRegistrationResponse`` / ``InvalidAuthenticationResponse``;
  * the STORED credential public key is decoded in
    ``verify_authentication_response`` under ``except InvalidSignature`` only,
    so a duplicate key there escapes as a bare ``InvalidCBORData``. Our three
    verify sites caught ``(Invalid*Response, ValueError, KeyError)``, so it
    escaped them too: a 500, and no ``record_login_failure``. The fix catches
    the library's base ``WebAuthnException`` at each site.

Only meaningful on the locked library; skips locally on another version and
FAILS under CI (same fixture as punch 481).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from importlib.metadata import version
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from email_triage._envbool import parse_bool
from email_triage.web import webauthn_auth as wa
from email_triage.web.db_auth_helpers import add_hardware_key

REPO = Path(__file__).resolve().parents[2]
RP_ID = "triage.example.test"
ORIGIN = f"https://{RP_ID}"
CRED_ID = b"punch484-credential-id"


def _locked_webauthn() -> str:
    text = (REPO / "requirements.lock").read_text(encoding="utf-8")
    m = re.search(r"^webauthn==([^\s\\]+)", text, re.MULTILINE)
    assert m, "requirements.lock no longer pins webauthn"
    return m.group(1)


@pytest.fixture(autouse=True)
def _on_the_locked_library():
    locked, installed = _locked_webauthn(), version("webauthn")
    if installed == locked:
        return
    msg = (f"webauthn {installed} installed, {locked} locked: these tests "
           f"measure the locked library only")
    if parse_bool(os.environ.get("CI")):
        pytest.fail(msg + " (CI must install requirements.lock)")
    pytest.skip(msg + " (run scripts/test-local-podman.sh)")


# --- CBOR / WebAuthn byte builders ------------------------------------------

def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _cbor_head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    return bytes([major << 5 | 25]) + n.to_bytes(2, "big")


def _cbor(v) -> bytes:
    """Minimal RFC 8949 encoder for the shapes these fixtures use (no new
    test dependency: cbor2 is only a transitive dep of webauthn)."""
    if isinstance(v, bool):
        return bytes([0xF5]) if v else bytes([0xF4])  # CBOR true / false
    if isinstance(v, int):
        return _cbor_head(0, v) if v >= 0 else _cbor_head(1, -1 - v)
    if isinstance(v, bytes):
        return _cbor_head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode()
        return _cbor_head(3, len(b)) + b
    if isinstance(v, dict):
        return _cbor_map(list(v.items()))
    raise TypeError(type(v))


def _cbor_map(pairs: list[tuple]) -> bytes:
    """A CBOR map from (key, value) pairs, duplicates allowed (a dict cannot
    hold a duplicate key, so no dict-based encoder can emit one)."""
    return _cbor_head(5, len(pairs)) + b"".join(_cbor(k) + _cbor(v) for k, v in pairs)


def _key_pairs(priv) -> list[tuple]:
    nums = priv.public_key().public_numbers()
    return [(1, 2), (3, -7), (-1, 1),
            (-2, nums.x.to_bytes(32, "big")), (-3, nums.y.to_bytes(32, "big"))]


def _cose_key(priv, *, duplicate: bool = False) -> bytes:
    pairs = _key_pairs(priv)
    return _cbor_map(pairs + [(3, -7)] if duplicate else pairs)


def _client_data(kind: str, challenge: bytes) -> bytes:
    return json.dumps({"type": kind, "challenge": _b64(challenge),
                       "origin": ORIGIN, "crossOrigin": False}).encode()


def _registration(challenge: bytes, priv, *, duplicate: bool) -> dict:
    flags = 0x01 | 0x04 | 0x40                       # UP | UV | AT
    auth_data = (hashlib.sha256(RP_ID.encode()).digest() + bytes([flags])
                 + (0).to_bytes(4, "big") + b"\x00" * 16
                 + len(CRED_ID).to_bytes(2, "big") + CRED_ID + _cose_key(priv))
    pairs = [("fmt", "none"), ("attStmt", {}), ("authData", auth_data)]
    if duplicate:
        pairs.append(("fmt", "none"))
    return {"id": _b64(CRED_ID), "rawId": _b64(CRED_ID), "type": "public-key",
            "response": {"clientDataJSON": _b64(_client_data("webauthn.create", challenge)),
                         "attestationObject": _b64(_cbor_map(pairs))}}


def _assertion(challenge: bytes, priv, *, duplicate: bool, user_handle=None) -> dict:
    flags = 0x01 | 0x04 | 0x80                       # UP | UV | ED (extensions)
    ext = [("credProps", True)] + ([("credProps", False)] if duplicate else [])
    auth_data = (hashlib.sha256(RP_ID.encode()).digest() + bytes([flags])
                 + (1).to_bytes(4, "big") + _cbor_map(ext))
    cdj = _client_data("webauthn.get", challenge)
    sig = priv.sign(auth_data + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
    resp = {"clientDataJSON": _b64(cdj), "authenticatorData": _b64(auth_data),
            "signature": _b64(sig)}
    if user_handle is not None:
        resp["userHandle"] = _b64(user_handle)
    return {"id": _b64(CRED_ID), "rawId": _b64(CRED_ID), "type": "public-key",
            "response": resp}


# --- fixtures ----------------------------------------------------------------

@pytest.fixture
def priv():
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture
def user(db):
    from datetime import datetime, timezone
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("p484@example.com", "P484", "user", datetime.now(timezone.utc).isoformat()))
    db.commit()
    return {"id": cur.lastrowid, "email": "p484@example.com", "name": "P484"}


def _register_key(db, user, priv, *, stored_key: bytes | None = None) -> int:
    return add_hardware_key(
        db, user_id=user["id"], credential_id=CRED_ID,
        public_key=stored_key if stored_key is not None else _cose_key(priv),
        sign_count=0, transports=[], aaguid=None, nickname="k")


def _begin_reg(db, user) -> bytes:
    opts = json.loads(wa.begin_registration(db, user=user, rp_id=RP_ID, rp_name="ET"))
    return base64.urlsafe_b64decode(opts["challenge"] + "=" * (-len(opts["challenge"]) % 4))


def _begin_auth(db, user) -> bytes:
    opts = json.loads(wa.begin_authentication(
        db, user_id=user["id"], email=user["email"], rp_id=RP_ID,
        require_user_verification=True))
    return base64.urlsafe_b64decode(opts["challenge"] + "=" * (-len(opts["challenge"]) % 4))


def _begin_passkey(db) -> tuple[bytes, int]:
    opts_json, cid = wa.begin_passkey_authentication(db, rp_id=RP_ID)
    opts = json.loads(opts_json)
    return base64.urlsafe_b64decode(opts["challenge"] + "=" * (-len(opts["challenge"]) % 4)), cid


# --- function level: the three verify sites ---------------------------------

def test_registration_control_without_duplicate_succeeds(db, user, priv):
    ch = _begin_reg(db, user)
    key_id = wa.finish_registration(db, user=user, rp_id=RP_ID, origin=ORIGIN,
                                    response_json=_registration(ch, priv, duplicate=False),
                                    nickname="k")
    assert key_id > 0


def test_registration_duplicate_key_is_a_clean_auth_error(db, user, priv):
    ch = _begin_reg(db, user)
    with pytest.raises(wa.WebAuthnAuthError, match="Registration verify failed"):
        wa.finish_registration(db, user=user, rp_id=RP_ID, origin=ORIGIN,
                               response_json=_registration(ch, priv, duplicate=True),
                               nickname="k")


def test_authentication_control_without_duplicate_succeeds(db, user, priv):
    _register_key(db, user, priv)
    ch = _begin_auth(db, user)
    assert wa.finish_authentication(db, user_id=user["id"], rp_id=RP_ID, origin=ORIGIN,
                                    response_json=_assertion(ch, priv, duplicate=False)) > 0


def test_authentication_duplicate_key_is_a_clean_auth_error(db, user, priv):
    _register_key(db, user, priv)
    ch = _begin_auth(db, user)
    with pytest.raises(wa.WebAuthnAuthError, match="Assertion verify failed"):
        wa.finish_authentication(db, user_id=user["id"], rp_id=RP_ID, origin=ORIGIN,
                                 response_json=_assertion(ch, priv, duplicate=True))


def test_stored_key_with_duplicate_cbor_is_a_clean_auth_error(db, user, priv):
    """The path 3.0.0 does NOT wrap: the stored key is decoded outside the
    library's except clause. Before the fix this raised a bare InvalidCBORData
    through finish_authentication."""
    _register_key(db, user, priv, stored_key=_cose_key(priv, duplicate=True))
    ch = _begin_auth(db, user)
    with pytest.raises(wa.WebAuthnAuthError, match="Assertion verify failed"):
        wa.finish_authentication(db, user_id=user["id"], rp_id=RP_ID, origin=ORIGIN,
                                 response_json=_assertion(ch, priv, duplicate=False))


@pytest.mark.parametrize("duplicate_in", ["assertion", "stored_key"])
def test_passkey_duplicate_key_is_a_clean_auth_error(db, user, priv, duplicate_in):
    from email_triage.web.db_auth_helpers import get_or_create_webauthn_user_handle
    handle = get_or_create_webauthn_user_handle(db, user["id"])
    _register_key(db, user, priv,
                  stored_key=_cose_key(priv, duplicate=duplicate_in == "stored_key"))
    ch, cid = _begin_passkey(db)
    resp = _assertion(ch, priv, duplicate=duplicate_in == "assertion", user_handle=handle)
    with pytest.raises(wa.WebAuthnAuthError, match="Assertion verify failed"):
        wa.finish_passkey_authentication(db, rp_id=RP_ID, origin=ORIGIN,
                                         response_json=resp, challenge_id=cid)


def test_passkey_control_without_duplicate_succeeds(db, user, priv):
    from email_triage.web.db_auth_helpers import get_or_create_webauthn_user_handle
    handle = get_or_create_webauthn_user_handle(db, user["id"])
    _register_key(db, user, priv)
    ch, cid = _begin_passkey(db)
    uid, _key = wa.finish_passkey_authentication(
        db, rp_id=RP_ID, origin=ORIGIN, challenge_id=cid,
        response_json=_assertion(ch, priv, duplicate=False, user_handle=handle))
    assert uid == user["id"]


# --- route level: a refusal, not a 500, and the failure is counted ----------

def _webauthn_config(client):
    client.app.state.config.webauthn.rp_id = RP_ID
    client.app.state.config.webauthn.origin = ORIGIN


def _login_failures(db, email):
    return db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE email = ? AND outcome = 'failure'",
        (email,)).fetchone()[0]


@pytest.mark.parametrize("duplicate_in", ["assertion", "stored_key"])
def test_login_route_refuses_duplicate_cbor_with_403_and_counts_it(
    client, db, user, priv, duplicate_in,
):
    _webauthn_config(client)
    _register_key(db, user, priv,
                  stored_key=_cose_key(priv, duplicate=duplicate_in == "stored_key"))
    ch = _begin_auth(db, user)
    before = _login_failures(db, user["email"])
    r = client.post("/login/webauthn/finish", json={
        "email": user["email"],
        "response": _assertion(ch, priv, duplicate=duplicate_in == "assertion")})
    assert r.status_code == 403, r.text
    assert "Traceback" not in r.text and "InvalidCBORData" not in r.text
    assert _login_failures(db, user["email"]) == before + 1


def test_login_route_control_succeeds(client, db, user, priv):
    _webauthn_config(client)
    _register_key(db, user, priv)
    ch = _begin_auth(db, user)
    r = client.post("/login/webauthn/finish", json={
        "email": user["email"], "response": _assertion(ch, priv, duplicate=False)})
    assert r.status_code == 200, r.text


def test_register_route_refuses_duplicate_cbor_with_400(client, db, admin_user, admin_cookies, priv):
    _webauthn_config(client)
    ch = _begin_reg(db, admin_user)
    r = client.post("/profile/hardware-keys/register/finish", cookies=admin_cookies, json={
        "nickname": "k", "response": _registration(ch, priv, duplicate=True)})
    assert r.status_code == 400, r.text
    assert "Traceback" not in r.text


# --- structural pin ---------------------------------------------------------
#
# INVARIANT (count-agnostic over src): every ``try`` whose body calls a
# py_webauthn ``verify_*_response`` has a handler that catches the library's
# base ``WebAuthnException`` (or ``Exception``), so no library refusal can
# escape a verify site as a 500.
#
# SCOPE CAVEAT: recognises the call by the function names
# verify_registration_response / verify_authentication_response; a call
# through an alias is not followed. A verify call with NO enclosing try is
# flagged too.

_VERIFY = {"verify_registration_response", "verify_authentication_response"}
_BROAD = {"WebAuthnException", "Exception", "BaseException"}


def _handler_names(h) -> set[str]:
    t = h.type
    nodes = t.elts if isinstance(t, ast.Tuple) else [t] if t is not None else []
    out = {getattr(n, "id", None) or getattr(n, "attr", None) for n in nodes}
    return out if t is not None else {"BaseException"}


def _verify_violations(tree, rel):
    out = []
    for call in ast.walk(tree):
        if not (isinstance(call, ast.Call)
                and (getattr(call.func, "id", None) or getattr(call.func, "attr", None)) in _VERIFY):
            continue
        cur, covered = getattr(call, "_ph_parent", None), False
        while cur is not None and not covered:
            if isinstance(cur, ast.Try):
                covered = any(_handler_names(h) & _BROAD for h in cur.handlers)
            cur = getattr(cur, "_ph_parent", None)
        if not covered:
            out.append(f"{rel}:{call.lineno}: verify call not covered by WebAuthnException")
    return out


import ast  # noqa: E402

from _pin_harness import assert_pin_has_teeth, iter_src_files, parse_module, relpath  # noqa: E402


def test_every_verify_site_catches_the_library_base_exception():
    violations, sites = [], 0
    for path in iter_src_files():
        tree = parse_module(path)
        if tree is None:
            continue
        rel = relpath(path)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", None) in _VERIFY:
                sites += 1
        violations += _verify_violations(tree, rel)
    assert sites >= 3
    assert violations == [], "\n".join(violations)


def test_verify_pin_has_teeth():
    assert_pin_has_teeth(
        lambda t: _verify_violations(t, "web/webauthn_auth.py"),
        bad_source=("try:\n    v = verify_authentication_response(credential=c)\n"
                    "except (InvalidAuthenticationResponse, ValueError, KeyError) as e:\n"
                    "    raise WebAuthnAuthError(str(e))\n"),
        good_source=("try:\n    v = verify_authentication_response(credential=c)\n"
                     "except WebAuthnException as e:\n    raise WebAuthnAuthError(str(e))\n"),
    )
