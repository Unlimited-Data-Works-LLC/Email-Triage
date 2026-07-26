"""N-315 R30 execution-coverage test — tranche  DA fix-forward.

DA panel on `d6afa1e6` (N-263) called that the underlying defect
(`_hours_until` returning None on Z-form → Gmail watch treated as
no-expiry → silent watch-expiry regression) closed by parse_iso
migration lacks execution coverage per Prime Directive  (test the
rendered view, not just machinery). The ratchet pin proves
`datetime.fromisoformat` doesn't creep back in, NOT that `_hours_until`
actually parses a Z-form now.

This test executes `_hours_until("<future-Z-form>")` and asserts the
returned float is positive (i.e. non-None, and represents future
hours). It also asserts a past Z-form returns a NEGATIVE float and a
malformed string returns None (fail-closed). §164.312(b)
audit-integrity adjacency (Gmail watch mis-parsed expiry is a
push-audit continuity risk).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def test_hours_until_gmail_z_form_returns_positive():
    """A future Gmail Z-form expiry must return a POSITIVE
    hours-until value (not None / not negative)."""
    from email_triage.web.routers.integrations import _hours_until

    future = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat().replace("+00:00", "Z")
    result = _hours_until(future)
    assert result is not None, (
        "N-315 R30: _hours_until on future Z-form MUST return a "
        "non-None float; got None (parse regression — the N-263 fix "
        "did not close the class)"
    )
    assert 20 < result < 26, (
        f"N-315 R30: expected ~24 hours for a 24-hour-future Z-form; "
        f"got {result}"
    )


def test_hours_until_past_z_form_returns_negative():
    """A past Z-form expiry MUST return a negative value (watch
    already expired) — not None + not zero."""
    from email_triage.web.routers.integrations import _hours_until

    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    result = _hours_until(past)
    assert result is not None
    assert result < 0, (
        f"N-315 R30: past Z-form MUST return negative hours-until; "
        f"got {result}"
    )


def test_hours_until_malformed_returns_none():
    """Fail-CLOSED on unparseable input (parse_iso returns None →
    _hours_until returns None → caller treats as no-expiry-known)."""
    from email_triage.web.routers.integrations import _hours_until

    assert _hours_until("not-a-datetime") is None
    assert _hours_until("") is None
