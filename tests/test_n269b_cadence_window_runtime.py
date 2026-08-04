"""N-269b R28 HIPAA-SME follow-up (2026-07-03) — runtime unit tests for
`_is_within_cadence_window` on truthy Z-form `rebuilt_at`.

The N-269b batch-script rewrite shipped an UnboundLocalError on all 3
migrated sites (indent bug — `ts = parse_iso(...)` ended up dead code
inside the `if not rebuilt_at: return False` block). Fix-forward
N-283 corrected the indent. The pre-fix N-269b pin was TEXTUAL only —
"grep for parse_iso" would have passed while `_is_within_cadence_
window` crashed on every truthy rebuilt_at.

This adds the RUNTIME anti-vacuity per the HIPAA-SME follow-up:
construct a rebuilt_at Z-form + call the function + assert no
exception. Would have caught the N-269b defect at pin-run time.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch


def test_hipaa_style_distill_cadence_window_truthy_zform_no_crash():
    """`actions/hipaa_style_distill._is_within_cadence_window` on a
    truthy Z-form `rebuilt_at` must NOT raise (was UnboundLocalError
    at N-269b commit)."""
    from email_triage.actions import hipaa_style_distill as m
    with patch(
        "email_triage.web.db.get_hipaa_style_descriptor",
        return_value={
            "rebuilt_at": "2026-07-03T12:00:00Z",  # Z-form — the exact shape
        },
    ):
        result = m._is_within_cadence_window(None, 1)  # conn unused via mock
    assert isinstance(result, bool)


def test_distill_hipaa_cadence_window_truthy_zform_no_crash():
    """`style_learning/distill_hipaa._is_within_cadence_window` on a
    truthy Z-form `rebuilt_at` must NOT raise."""
    from email_triage.style_learning import distill_hipaa as m
    with patch(
        "email_triage.web.db.get_hipaa_style_descriptor",
        return_value={
            "rebuilt_at": "2026-07-03T12:00:00Z",
        },
    ):
        result = m._is_within_cadence_window(None, 1)
    assert isinstance(result, bool)


def test_cadence_window_false_on_empty_rebuilt_at():
    """Sanity: empty rebuilt_at → False (no crash)."""
    from email_triage.actions import hipaa_style_distill as m
    with patch(
        "email_triage.web.db.get_hipaa_style_descriptor",
        return_value={"rebuilt_at": ""},
    ):
        assert m._is_within_cadence_window(None, 1) is False


def test_cadence_window_false_on_bad_iso():
    """Bad ISO string → False (parse_iso returns None → early return)."""
    from email_triage.actions import hipaa_style_distill as m
    with patch(
        "email_triage.web.db.get_hipaa_style_descriptor",
        return_value={"rebuilt_at": "not-an-iso-string"},
    ):
        assert m._is_within_cadence_window(None, 1) is False
