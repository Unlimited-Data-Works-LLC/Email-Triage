"""Punch  -- hardware-key ENROLMENT rides the HMAC audit chain on both edges.

Revocation was already audited (N-121, ``hardware_key_revoked``); enrolment only
logged. Since punch  registration enforces the admin UV policy, so a refused
admin enrolment must leave a tamper-evident row too (§164.312(b);
§164.308(a)(4)). This drives the REAL route end-to-end with the verify step
faked (the library refusal paths are covered by the punch 481/484 suites):

* success edge -> one ``hardware_key_registered`` row, ``outcome='success'``,
  ``key_id`` = the new key;
* refused edge -> one ``hardware_key_registered`` row, ``outcome='denied:verify_failed'``
  and a class-name slug in ``detail`` -- and the login-lockout counter
  (``outcome='failure'`` by email AND by ip, ``login_guard._count_failures_since``)
  does NOT move: a fumbled enrolment must never lock its owner out of login.

The structural half (every grant path, both edges) is
``tests/test_session_epoch_on_revoke_pin.py::test_hardware_key_grant_emits_audit_event_on_both_edges``.
"""

from __future__ import annotations

from email_triage.web import webauthn_auth as wa

RP_ID = "localhost"
ORIGIN = "http://localhost"


def _webauthn_config(client):
    client.app.state.config.webauthn.rp_id = RP_ID
    client.app.state.config.webauthn.origin = ORIGIN


def _rows(db):
    return db.execute(
        "SELECT * FROM auth_events WHERE event_type = 'hardware_key_registered' "
        "ORDER BY id",
    ).fetchall()


def _lockout_failures(db, *, column, value):
    # login_guard._count_failures_since counted EVERY ``outcome='failure'`` row for
    # lockout until 2026-10-25; it now counts login_* event types only. This keeps the
    # broader predicate on purpose: the refusal edge must stay out of any failure count.
    return db.execute(
        f"SELECT COUNT(*) FROM auth_events WHERE {column} = ? AND outcome = 'failure'",
        (value,),
    ).fetchone()[0]


def _all_failures(db):
    return db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE outcome = 'failure'",
    ).fetchone()[0]


def test_register_success_writes_hardware_key_registered_row(
    client, db, admin_user, admin_cookies, monkeypatch,
):
    _webauthn_config(client)
    # REAL finish_registration (challenge consume -> UV check -> the atomic
    # grant funnel); only the library's attestation verify is faked.
    wa.begin_registration(
        db, user=admin_user, rp_id=RP_ID, rp_name="ET",
        require_user_verification=True,
    )

    class _Verified:
        credential_id = b"p525-cred"
        credential_public_key = b"p525-pub"
        sign_count = 0
        aaguid = None
        user_verified = True

    monkeypatch.setattr(wa, "verify_registration_response", lambda **_kw: _Verified())
    before = len(_rows(db))

    r = client.post(
        "/profile/hardware-keys/register/finish", cookies=admin_cookies,
        json={"nickname": "k525", "response": {"id": "x"}},
    )
    assert r.status_code == 200, r.text
    new_id = r.json()["key_id"]

    rows = _rows(db)
    assert len(rows) == before + 1, "enrolment success wrote no audit-chain row"
    row = rows[-1]
    assert row["outcome"] == "success"
    assert row["key_id"] == new_id
    assert row["user_id"] == admin_user["id"]
    assert row["email"] == admin_user["email"]
    assert db.execute(
        "SELECT user_id FROM hardware_keys WHERE id = ?", (new_id,),
    ).fetchone()["user_id"] == admin_user["id"]


def test_grant_rolls_back_when_its_witness_fails(db, admin_user, monkeypatch):
    """N-520 shape: the key and its audit row land or roll back TOGETHER. A
    witness failure (the fail-closed HMAC chain on a key gap) must leave NO
    hardware_keys row -- a credential is never granted unwitnessed."""
    from email_triage.db import audit as audit_mod

    def boom(*_a, **_kw):
        raise RuntimeError("simulated chain-key gap")

    monkeypatch.setattr(audit_mod, "record_auth_event_txn", boom)
    keys_before = db.execute("SELECT COUNT(*) FROM hardware_keys").fetchone()[0]
    try:
        audit_mod.record_hardware_key_registration(
            db, user_id=admin_user["id"], credential_id=b"p525-rb",
            public_key=b"p525-pub", sign_count=0, transports=[], aaguid=None,
            nickname="k", email=admin_user["email"],
        )
    except RuntimeError as exc:
        assert "chain-key gap" in str(exc)
    else:  # pragma: no cover - the assertion below is the real failure
        raise AssertionError("grant funnel swallowed its witness failure")
    assert db.execute(
        "SELECT COUNT(*) FROM hardware_keys").fetchone()[0] == keys_before, (
        "a hardware key was granted although its audit row failed (N-520)")
    assert db.execute(
        "SELECT COUNT(*) FROM hardware_keys WHERE credential_id = ?",
        (b"p525-rb",)).fetchone()[0] == 0


def test_register_refusal_writes_denied_row_and_does_not_feed_lockout(
    client, db, admin_user, admin_cookies, monkeypatch,
):
    _webauthn_config(client)

    def fake_finish(conn, **_kw):
        raise wa.WebAuthnAuthError("User verification required but not performed")

    monkeypatch.setattr(wa, "finish_registration", fake_finish)
    before = len(_rows(db))
    all_failures = _all_failures(db)
    email_failures = _lockout_failures(db, column="email", value=admin_user["email"])

    r = client.post(
        "/profile/hardware-keys/register/finish", cookies=admin_cookies,
        json={"nickname": "k525", "response": {"id": "x"}},
    )
    assert r.status_code == 400, r.text
    assert "Traceback" not in r.text

    rows = _rows(db)
    assert len(rows) == before + 1, "refused enrolment wrote no audit-chain row"
    row = rows[-1]
    assert row["outcome"] == "denied:verify_failed"
    assert row["detail"] == "WebAuthnAuthError"
    assert row["key_id"] is None
    assert row["user_id"] == admin_user["id"]
    # The library's free text stays in the structured log, not the chain.
    assert "verification" not in (row["detail"] or "")

    # A refused enrolment is NOT a login failure -- the lockout counter is unmoved,
    # by email and (whatever ip the row carries) in total.
    assert _lockout_failures(db, column="email", value=admin_user["email"]) == email_failures
    assert _all_failures(db) == all_failures
