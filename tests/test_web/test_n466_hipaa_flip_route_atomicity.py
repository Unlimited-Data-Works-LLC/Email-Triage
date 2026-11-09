"""N-466 — a failed boundary emit leaves the whole HIPAA posture untouched.

MEASURED through the REAL route (``POST /admin/security/save``), in the shape
of ``~/.internal-config/scripts/et-n466-cache-rollback/da_boundary_probe.py`` arm B: the
rotation window the audit module documents by name — a chain key VERSION is
set, that version's key is ABSENT (the ``master_key_history`` row was deleted,
or the lifespan failed to load every historical version). ``_chain_insert`` is
fail-closed BY DESIGN there (Directive 12: never an unsigned audit row).

The arm-A positive control is not decoration. Without it, arm B proves nothing:
a 500 with no boundary row is equally consistent with "the probe never reached
the write at all", which would make every arm-B assertion vacuous.

Arm B pre-fix (measured 2026-09-12): HTTP 500, ``runtime_settings.hipaa``
committed False, live ``_hipaa_mode`` False, ZERO boundary rows — total loss of
the only durable witness this route has (``/admin/security/save`` is in no
``_PHI_ROUTE_PREFIXES``, so there is no ``hipaa_access_events`` row either).
Post-fix the whole tuple must be unchanged: DB row True, live flag True, cache
True, zero boundary rows — plus ONE ``audit_gap_events`` row naming the funnel,
which is the §164.312(b) trace that the failed emit happened at all.

WHAT THIS DOES NOT PROVE: not run under real threads. The N-464-reopening
cache phantom needs a reader landing inside the open transaction; that is
covered by ``tests/test_n466_settings_cache_rollback_pin.py`` with an injected
in-transaction reader. Threading changes WHEN the read arrives, not WHAT it
sees.
"""
from __future__ import annotations

import pytest

from email_triage import triage_logging
from email_triage.db import audit as _audit
from email_triage.web.db import get_setting, invalidate_setting_cache, set_setting

_KEY = "runtime_settings"
_ON = {"dry_run": False, "log_level": "INFO", "hipaa": True}
_KEY_BYTES = b"\x01" * 32


def _boundary_count(db) -> int:
    return db.execute("SELECT COUNT(*) FROM hipaa_boundary_events").fetchone()[0]


def _gap_rows(db) -> list[tuple]:
    return [
        tuple(r) for r in db.execute(
            "SELECT helper_name FROM audit_gap_events ORDER BY id DESC"
        ).fetchall()
    ]


@pytest.fixture()
def hipaa_on(db):
    """A healthy, HIPAA-ON install with a provisioned chain key.

    Restores the process flag + the chain-key registry afterwards: both are
    module globals, so a leak would contaminate the rest of the session.
    """
    prev_mode = triage_logging._hipaa_mode
    _audit._clear_hmac_keys_for_test()
    _audit._set_hmac_key_for_test(_KEY_BYTES, 1)
    triage_logging._hipaa_mode = True
    invalidate_setting_cache(_KEY)
    set_setting(db, _KEY, dict(_ON))
    try:
        yield db
    finally:
        triage_logging._hipaa_mode = prev_mode
        _audit._clear_hmac_keys_for_test()
        invalidate_setting_cache(_KEY)


def _post_flip_off(client, admin_cookies):
    """The flip: NO ``hipaa`` field in the form => ``hipaa_flag`` False => the
    install goes HIPAA ON -> OFF, the direction that disables the safeguard."""
    return client.post(
        "/admin/security/save",
        data={"tls_csrf_enforce": "1", "auth_session_ttl_secs": "86400"},
        cookies=admin_cookies,
        follow_redirects=False,
    )


def test_arm_a_healthy_chain_flips_and_witnesses_it(client, hipaa_on, admin_cookies):
    """POSITIVE CONTROL. With a healthy chain the flip must SUCCEED end to end
    — otherwise arm B's "nothing changed" is unfalsifiable."""
    db = hipaa_on
    before = _boundary_count(db)

    resp = _post_flip_off(client, admin_cookies)

    assert resp.status_code < 400, (
        f"the healthy-chain flip did not succeed (HTTP {resp.status_code}); "
        "arm B below would then prove nothing"
    )
    invalidate_setting_cache(_KEY)
    assert get_setting(db, _KEY)["hipaa"] is False
    assert triage_logging._hipaa_mode is False
    assert _boundary_count(db) == before + 1, (
        "the successful flip did not write its boundary event — the witness "
        "this finding is about"
    )


def test_arm_b_failed_boundary_emit_changes_nothing(client, hipaa_on, admin_cookies):
    """THE INVARIANT. A fail-closed chain must leave the settings row, the live
    process flag and the settings cache ALL on the pre-save posture."""
    db = hipaa_on
    before = _boundary_count(db)
    # The documented rotation-window state: version rotated to 2, whose key row
    # is missing (_HMAC_KEYS still holds only {1: key}).
    _audit._HMAC_CURRENT_VERSION = 2
    assert _audit._get_current_hmac_version() == 2
    assert _audit._get_hmac_key(2) is None, (
        "probe setup failed: version 2's key is present, so _chain_insert will "
        "SUCCEED and this test is not measuring the fail-closed path"
    )

    resp = _post_flip_off(client, admin_cookies)

    assert resp.status_code >= 500, (
        f"expected the fail-closed chain to surface as a 5xx, got "
        f"{resp.status_code} — a 2xx here means the emit did not fail and the "
        "assertions below are vacuous"
    )
    # 1. The durable row. Pre-fix this was False (committed before the witness).
    invalidate_setting_cache(_KEY)
    row = db.execute(
        "SELECT value_json FROM settings WHERE key = ?", (_KEY,)
    ).fetchone()
    assert row is not None, "the settings row vanished — the rollback took too much"
    assert '"hipaa": true' in row[0].lower().replace("'", '"'), (
        "N-466: the HIPAA-DISABLING settings row committed even though its "
        f"boundary event could not be written. Durable value: {row[0]}"
    )
    # 2. The live process flag — applied only after the commit, so untouched.
    assert triage_logging._hipaa_mode is True, (
        "N-466: the in-process HIPAA flag was flipped off although the "
        "transaction rolled back. The apply must run AFTER db_call returns."
    )
    # 3. The cache — the N-464 reopening surface.
    assert get_setting(db, _KEY)["hipaa"] is True, (
        "N-466/N-464: the settings cache serves the DISCARDED value. "
        "Invalidate on every exit edge (finally:), not only after COMMIT."
    )
    # 4. No half-written witness.
    assert _boundary_count(db) == before, "a boundary row landed despite the failed emit"


def test_arm_b_records_the_failed_emit_as_an_audit_gap_event(
    client, hipaa_on, admin_cookies,
):
    """§164.312(b) — the failure itself is traceable. The atomic funnel is an
    ``@audit_emitter``, so ``db_write``'s backstop writes an
    ``audit_gap_events`` row naming it (the backstop degrades to secretless
    SHA-256 when the HMAC key is the thing that is missing — punch 423 /
    N-467). Pre-fix there was NO row anywhere for this route."""
    db = hipaa_on
    _audit._HMAC_CURRENT_VERSION = 2

    _post_flip_off(client, admin_cookies)

    helpers = [r[0] for r in _gap_rows(db)]
    assert "record_system_hipaa_flip" in helpers, (
        "the failed atomic flip left no audit_gap_events row — the operator "
        f"has no trace that the emit was attempted. Rows: {helpers}"
    )
