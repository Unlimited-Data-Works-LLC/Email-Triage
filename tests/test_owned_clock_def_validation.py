"""validate_owned_clock_def — the fail-CLOSED safety funnel for operator-OWNED
IRB/INTERNAL clock-deadline templates (operator 2026-06-15).

An owned deadline feeds the immutable v47 HMAC clock chain, so a malformed
payload must RAISE (never coerce-and-proceed) — a wrong duration/unit/timezone
could chain a false `breached`. This pins every rejection + the normalization.
"""

from __future__ import annotations

import json

import pytest

from email_triage.db.regulatory_clock import (
    ClockDefValidationError,
    validate_owned_clock_def,
)


def _ok(**over):
    base = {
        "title": "Our IRB unanticipated-problem report",
        "regime": "IRB",
        "severity_class": "irb_up",
        "clock_kind": "escalating",
        "duration_value": 0,
        "duration_unit": "working_day",
        "clock_start_kind": "on_awareness",
        "calendar_tz": "America/New_York",
        "escalation_lead_pcts": [0, 50, 80],
    }
    base.update(over)
    return base


def test_happy_path_normalizes():
    out = validate_owned_clock_def(_ok())
    assert out["regime"] == "IRB"
    assert out["duration_overridable"] == 1          # owned rows always overridable
    assert out["ack_required"] == 1                  # default on
    assert json.loads(out["escalation_lead_pcts"]) == [0, 50, 80]
    # Only data columns — never owner/code/enabled (the writer supplies those).
    assert "config_owner_account_id" not in out
    assert "code" not in out


def test_regime_lock_rejects_fda_and_eu():
    for regime in ("FDA", "EU_CTR", "BOGUS", ""):
        with pytest.raises(ClockDefValidationError):
            validate_owned_clock_def(_ok(regime=regime))


def test_internal_regime_allowed():
    out = validate_owned_clock_def(_ok(regime="INTERNAL", severity_class="internal"))
    assert out["regime"] == "INTERNAL"


def test_title_required():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(title="   "))


def test_negative_or_nonint_duration_rejected():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(duration_value=-1))
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(duration_value="five"))


def test_zero_duration_is_the_unconfigured_sentinel_ok():
    # 0 = unconfigured; allowed (nothing arms) even without a calendar.
    out = validate_owned_clock_def(_ok(duration_value=0, duration_unit="working_day"))
    assert out["duration_value"] == 0


def test_working_day_arming_requires_calendar():
    # duration>0 working_day WITHOUT a configured calendar => refused (a wrong
    # holiday set would chain a false breach).
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(
            _ok(duration_value=10, duration_unit="working_day"),
            working_day_calendar_configured=False,
        )
    # With a configured calendar it passes.
    out = validate_owned_clock_def(
        _ok(duration_value=10, duration_unit="working_day"),
        working_day_calendar_configured=True,
    )
    assert out["duration_value"] == 10
    # calendar_day arming never needs the working-day calendar.
    out2 = validate_owned_clock_def(
        _ok(duration_value=10, duration_unit="calendar_day"),
        working_day_calendar_configured=False,
    )
    assert out2["duration_unit"] == "calendar_day"


def test_arming_irb_must_escalate():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(
            _ok(regime="IRB", duration_value=5, duration_unit="calendar_day",
                clock_kind="informational"))


def test_lead_pcts_bounds_and_shape():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(escalation_lead_pcts=[150]))
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(escalation_lead_pcts=[-5]))
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(escalation_lead_pcts="not json"))
    # A JSON string array is accepted + normalized.
    out = validate_owned_clock_def(_ok(escalation_lead_pcts="[10, 90]"))
    assert json.loads(out["escalation_lead_pcts"]) == [10, 90]


def test_unknown_timezone_rejected():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(calendar_tz="Mars/Phobos"))


def test_bad_enums_rejected():
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(duration_unit="fortnight"))
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(clock_start_kind="whenever"))
    with pytest.raises(ClockDefValidationError):
        validate_owned_clock_def(_ok(severity_class="fatal_lt"))  # not an owned class
