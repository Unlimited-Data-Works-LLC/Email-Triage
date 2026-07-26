"""N-338 R31 unit tests — TriageLogger positional-args HIPAA gate.

Supersedes N-300 R30 (2026-07-03), whose allow-list
``len(s) <= 64 and "@" not in s and ":" not in s`` allow-listed the
exact §164.514(b) identifier shapes it claimed to close: phone / SSN /
DOB / MRN / patient-name / ZIP / ICD-10 codes / short clinical subject
strings all interpolated into ``record.msg`` un-redacted in HIPAA mode.

N-338 tightens the gate to fail-CLOSED on strings: an arg passes IFF it
is ``None`` / ``int`` / ``float`` / ``bool`` / :class:`Safe`. Every
other string redacts to ``<redacted>``. Callers who need a literal in
the interpolated msg wrap it in ``Safe("literal")`` — an explicit,
grep-able commitment that the value carries no PHI.

Fail-open branch (``msg % args`` errored) uses the same gated args
before repr(), so it inherits the fail-CLOSED behaviour.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def logger_hipaa_on(monkeypatch):
    import email_triage.triage_logging as t
    monkeypatch.setattr(t, "_hipaa_mode", True)
    return t.TriageLogger("test")


@pytest.fixture
def logger_hipaa_off(monkeypatch):
    import email_triage.triage_logging as t
    monkeypatch.setattr(t, "_hipaa_mode", False)
    return t.TriageLogger("test")


# ---------------------------------------------------------------------------
# Scalars pass unchanged.
# ---------------------------------------------------------------------------

def test_hipaa_scalar_positional_passes(logger_hipaa_on):
    assert logger_hipaa_on._format_msg("n=%s", (42,)) == "n=42"
    assert logger_hipaa_on._format_msg("f=%.2f", (3.14,)) == "f=3.14"
    assert logger_hipaa_on._format_msg("b=%s", (True,)) == "b=True"
    assert logger_hipaa_on._format_msg("n=%s", (None,)) == "n=None"


# ---------------------------------------------------------------------------
# Bare strings fail-CLOSED — the N-338 tightening. The N-300 predicate
# allow-listed everything below; the new gate redacts unconditionally
# unless the caller wrapped the value in Safe(...).
# ---------------------------------------------------------------------------

def test_hipaa_bare_short_opaque_string_redacts(logger_hipaa_on):
    """N-338: even a short, seemingly-opaque string redacts without Safe()."""
    assert logger_hipaa_on._format_msg("id=%s", ("abc123",)) == "id=<redacted>"


@pytest.mark.parametrize(
    "shape, value",
    [
        ("phone_dashed", "555-123-4567"),
        ("phone_e164_short", "+15551234567"),
        ("ssn", "123-45-6789"),
        ("dob_slash", "01/15/1980"),
        ("dob_iso", "1980-01-15"),
        ("mrn_prefix", "MRN12345"),
        ("mrn_bare_alnum", "PT00042"),
        ("patient_name_short", "Jane Doe"),
        ("patient_name_unicode", "María José García"),
        ("zip5", "90210"),
        ("zip9", "90210-1234"),
        ("icd10_diabetes", "E11.9"),
        ("icd10_malignant", "C34.90"),
        ("clinical_subject", "PT LAB RESULTS"),
        # hipaa-sme N-338 review 2026-07-04 — expand identifier coverage
        ("insurance_policy", "BCBS-XJH-8827441"),
        ("vin", "1HGCM82633A004352"),
        ("ipv4", "192.168.1.42"),
        ("biometric_hash", "a" * 64),
    ],
)
def test_hipaa_identifier_shapes_all_redact(logger_hipaa_on, shape, value):
    """N-338: every §164.514(b) identifier shape that N-300 leaked now redacts.

    The 8 shapes hipaa-sme flagged in the Phase 2 damage report all pass
    the N-300 predicate (``len<=64 and '@' not in a and ':' not in a``).
    The new gate closes them all — one parametrized test-per-shape so a
    future regression names the exact identifier that regressed.
    """
    result = logger_hipaa_on._format_msg("v=%s", (value,))
    assert result == "v=<redacted>", (
        f"identifier shape {shape!r} value={value!r} leaked past HIPAA gate"
    )


def test_hipaa_email_shaped_redacts(logger_hipaa_on):
    assert logger_hipaa_on._format_msg("email=%s", ("phi@example.com",)) == "email=<redacted>"


def test_hipaa_long_string_redacts(logger_hipaa_on):
    assert logger_hipaa_on._format_msg("body=%s", ("x" * 100,)) == "body=<redacted>"


def test_hipaa_dict_redacts(logger_hipaa_on):
    assert logger_hipaa_on._format_msg("extra=%s", ({"phi": "..."},)) == "extra=<redacted>"


def test_hipaa_list_redacts(logger_hipaa_on):
    assert logger_hipaa_on._format_msg("items=%s", (["a", "b", "c"],)) == "items=<redacted>"


def test_hipaa_bytes_redacts(logger_hipaa_on):
    """Bytes are not scalars — could hold binary PHI (attachment head)."""
    assert logger_hipaa_on._format_msg("blob=%s", (b"raw",)) == "blob=<redacted>"


# ---------------------------------------------------------------------------
# Safe(...) marker — the explicit opt-in.
# ---------------------------------------------------------------------------

def test_hipaa_safe_wrapped_string_passes(logger_hipaa_on):
    from email_triage.triage_logging import Safe
    assert logger_hipaa_on._format_msg("stage=%s", (Safe("classify"),)) == "stage=classify"


def test_hipaa_safe_wrapped_short_id_passes(logger_hipaa_on):
    from email_triage.triage_logging import Safe
    assert logger_hipaa_on._format_msg("id=%s", (Safe("abc123"),)) == "id=abc123"


def test_safe_rejects_non_string():
    """Safe wraps str only — a stray Safe(int) or Safe(email_obj) fails loud."""
    from email_triage.triage_logging import Safe
    with pytest.raises(TypeError, match="Safe wraps str only"):
        Safe(42)
    with pytest.raises(TypeError, match="Safe wraps str only"):
        Safe(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Safe wraps str only"):
        Safe(["a"])  # type: ignore[arg-type]


def test_safe_rejects_email_shaped_string():
    """hipaa-sme N-338 fix 2: Safe(patient_email) fails LOUD, not silent."""
    from email_triage.triage_logging import Safe
    with pytest.raises(TypeError, match="email-shaped"):
        Safe("patient@example.com")


def test_safe_rejects_long_string():
    """hipaa-sme N-338 fix 2: Safe("<128-char body>") is the PHI-body shape."""
    from email_triage.triage_logging import Safe
    with pytest.raises(TypeError, match="long strings"):
        Safe("x" * 200)


# ---------------------------------------------------------------------------
# HIPAA-off preserves stdlib semantics fully.
# ---------------------------------------------------------------------------

def test_hipaa_off_passes_through(logger_hipaa_off):
    assert logger_hipaa_off._format_msg("email=%s", ("phi@ex.com",)) == "email=phi@ex.com"
    assert logger_hipaa_off._format_msg("body=%s", ("x" * 100,)) == "body=" + "x" * 100
    assert logger_hipaa_off._format_msg("id=%s", ("abc123",)) == "id=abc123"


def test_hipaa_off_safe_still_unwraps(logger_hipaa_off):
    """Safe(...) is inert outside HIPAA mode — no interpolation surprise."""
    from email_triage.triage_logging import Safe
    # Non-HIPAA path returns args unchanged, so a Safe wrapper survives.
    # msg % (Safe(...),) would call str(Safe(...)) = "Safe('x')" — that
    # is the natural stdlib fallback; the caller opted into Safe() and
    # only uses it in HIPAA mode. Verify the gate leaves it untouched.
    gated = logger_hipaa_off._gate_positional_args((Safe("x"),))
    assert isinstance(gated[0], Safe) and gated[0].value == "x"


# ---------------------------------------------------------------------------
# Direct helper — new gated tuple structure.
# ---------------------------------------------------------------------------

def test_hipaa_gate_helper_direct(logger_hipaa_on):
    """Full mix: scalar + email + dict + bare short str + long str +
    Safe-wrapped literal + bytes.
    """
    from email_triage.triage_logging import Safe
    gated = logger_hipaa_on._gate_positional_args(
        (42, "phi@ex.com", {"k": "v"}, "abc", "x" * 100, Safe("category"), b"blob"),
    )
    assert gated == (42, "<redacted>", "<redacted>", "<redacted>", "<redacted>", "category", "<redacted>")


# ---------------------------------------------------------------------------
# Fail-open branch (msg % args errored) inherits the gate.
# ---------------------------------------------------------------------------

def test_hipaa_format_error_fallback_still_redacts(logger_hipaa_on):
    """A bad format string forces the ``repr()``-fallback branch; the
    args seen by ``repr()`` must be the GATED tuple, so a bare PHI
    string still appears as ``<redacted>`` there.
    """
    # 2 %s, 1 arg → TypeError → fallback path
    result = logger_hipaa_on._format_msg("a=%s b=%s", ("phi@ex.com",))
    assert "phi@ex.com" not in result
    assert "'<redacted>'" in result
