"""Route-level coverage for N-121 — credential-revoke routes write an HMAC
audit-chain row (``record_auth_event``), not just a structured log.

The structural pin (``tests/test_session_epoch_on_revoke_pin.py``) proves the
COUPLING (a revoke call-site must emit ``record_auth_event``); this proves the
wiring end-to-end through the admin route: the off-loop closure runs and a
``dev_key_revoked`` row lands on the tamper-evident ``auth_events`` chain
(§164.312(b)+(c)(1) access-termination event).
"""

from __future__ import annotations

from email_triage.db.users import add_dev_key


def _make_dev_key(db, allowlist):
    return add_dev_key(
        db, name="laptop", public_key="ssh-ed25519 AAAA routetest",
        fingerprint="SHA256:routetest-n121", email_allowlist=allowlist,
        created_by_user_id=None, expires_at="2099-01-01T00:00:00+00:00",
    )


def _count(db):
    return db.execute(
        "SELECT COUNT(*) FROM auth_events WHERE event_type = 'dev_key_revoked'",
    ).fetchone()[0]


def test_admin_dev_key_revoke_writes_audit_event(csrf_client, admin_cookies, db):
    kid = _make_dev_key(db, ["a@b.com"])
    before = _count(db)

    r = csrf_client.post(
        f"/admin/dev-keys/{kid}/revoke", data={}, cookies=admin_cookies,
        follow_redirects=False,
    )
    assert r.status_code in (302, 303), (r.status_code, r.text[:200])

    # the dev-key is revoked ...
    row = db.execute(
        "SELECT revoked_at FROM dev_keys WHERE id = ?", (kid,),
    ).fetchone()
    assert row is not None and row["revoked_at"] is not None

    # ... AND an HMAC audit-chain row was written (N-121).
    assert _count(db) == before + 1, (
        "revoke route must emit a dev_key_revoked auth_event on the chain"
    )
