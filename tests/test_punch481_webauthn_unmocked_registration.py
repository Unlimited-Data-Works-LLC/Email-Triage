"""Punch 481 + 483: WebAuthn registration runs against the real library.

Every other WebAuthn test monkeypatches the library, so before this file no
test reached `generate_registration_options` at all, and the 2.7.1 -> 3.0.0
bump (which narrowed the offered algorithms from nine to three) shipped with
nothing executed. These tests call OUR `begin_registration` with the library
un-mocked and assert what it offers, per
`decision_2026-09-21_assert_the_webauthn_algorithm_list_rather_than_pin_it`:
the list is ASSERTED, not pinned at the call site, so a change fails here and
becomes a decision with a name on it.

They are only meaningful on the locked library version. On another version
they skip locally (`scripts/test-local-podman.sh` and CI install the lock)
and FAIL under CI, where a version mismatch means CI is not running the lock.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import pytest

from email_triage._envbool import parse_bool
from email_triage.web.db import init_db
from email_triage.web.db_auth_helpers import consume_webauthn_challenge
from email_triage.web.webauthn_auth import begin_registration

REPO = Path(__file__).resolve().parents[1]

# The offered COSE algorithms at the locked version, in preference order:
# EdDSA (-8), ES256 (-7), RS256 (-257). Read from the v3.0.0 wheel's
# `default_supported_pub_key_algs` on 2026-10-10. 2.7.1 offered nine
# (-7 -8 -36 -37 -38 -39 -257 -258 -259); see punch 483.
EXPECTED_ALGS = [-8, -7, -257]


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


@pytest.fixture
def db(tmp_path: Path) -> sqlite3.Connection:
    from _db_tracking import track
    return track(init_db(str(tmp_path / "test.db")))


@pytest.fixture
def user(db) -> dict:
    cur = db.execute(
        "INSERT INTO users (email, name, role, created_at) VALUES (?, ?, ?, ?)",
        ("user@example.com", "User", "user",
         datetime.now(timezone.utc).isoformat()),
    )
    db.commit()
    return {"id": cur.lastrowid, "email": "user@example.com", "name": "User"}


def _begin(db, user) -> dict:
    return json.loads(begin_registration(
        db, user=user, rp_id="triage.example.test", rp_name="Email Triage",
    ))


def test_registration_offers_the_expected_algorithms(db, user):
    opts = _begin(db, user)
    params = opts["pubKeyCredParams"]
    assert all(p["type"] == "public-key" for p in params)
    offered = [p["alg"] for p in params]
    assert offered == EXPECTED_ALGS, (
        f"the library's offered algorithms changed from {EXPECTED_ALGS} to "
        f"{offered}. Confirm the change is intended (a newly offered "
        f"algorithm may be a post-quantum one), then update EXPECTED_ALGS "
        f"and record it on the punch list.")
    assert len(set(offered)) == len(offered) == 3


def test_the_real_ceremony_stores_a_consumable_challenge(db, user):
    import base64

    opts = _begin(db, user)
    assert opts["rp"]["id"] == "triage.example.test"
    assert opts["authenticatorSelection"]["residentKey"] == "preferred"
    challenge = base64.urlsafe_b64decode(
        opts["challenge"] + "=" * (-len(opts["challenge"]) % 4))
    row = consume_webauthn_challenge(
        db, user_id=user["id"], email=None, kind="register")
    assert row is not None and row.challenge == challenge


#: A SimpleNamespace carrying one of these keywords stands in for a verify
#: result: `credential_public_key` only exists on VerifiedRegistration and
#: `new_sign_count` only on VerifiedAuthentication.
_RESULT_MARKERS = {"credential_public_key": "registration",
                   "new_sign_count": "authentication"}


def _verify_result_stand_ins() -> list[tuple[str, int, str, list[str]]]:
    """Every verify-result stand-in in every test that mocks the verify calls.

    Discovered, not listed: any `tests/**/*.py` naming
    `verify_registration_response` or `verify_authentication_response`, and
    in it any `SimpleNamespace(...)` carrying a result marker (devils-advocate
    V1 F6, db-sme V1 F10: the 449/450 stand-ins set `user_verified`, which
    `webauthn_auth.py` reads).
    """
    import ast

    from tests._pin_harness import iter_files, parse_module

    out = []
    for path in iter_files(REPO / "tests"):
        text = path.read_text(encoding="utf-8")
        if ("verify_registration_response" not in text
                and "verify_authentication_response" not in text):
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and getattr(node.func, "id", getattr(node.func, "attr", "")) == "SimpleNamespace"):
                continue
            names = [kw.arg for kw in node.keywords if kw.arg]
            kinds = {_RESULT_MARKERS[n] for n in names if n in _RESULT_MARKERS}
            if len(kinds) == 1:
                out.append((path.name, node.lineno, kinds.pop(), names))
    return out


def test_the_mock_stand_ins_match_the_real_dataclasses():
    """The finish_* tests mock the library's verify calls with SimpleNamespace
    stand-ins. Every attribute a stand-in sets must exist on the real result
    dataclass, so a renamed or dropped field fails here instead of passing
    behind the mock. Names only: one stand-in deliberately sets a bytes
    `aaguid` (the real field is str) to exercise a defensive branch."""
    from webauthn.authentication.verify_authentication_response import (
        VerifiedAuthentication,
    )
    from webauthn.registration.verify_registration_response import (
        VerifiedRegistration,
    )

    real = {"registration": {f.name for f in dataclasses.fields(VerifiedRegistration)},
            "authentication": {f.name for f in dataclasses.fields(VerifiedAuthentication)}}
    stand_ins = _verify_result_stand_ins()
    assert {k for _, _, k, _ in stand_ins} == {"registration", "authentication"}, (
        "found no stand-ins of one result kind; the discovery no longer matches")
    missing = sorted((f, line, kind, n) for f, line, kind, names in stand_ins
                     for n in names if n not in real[kind])
    assert not missing, f"stand-in attributes the library does not have: {missing}"
