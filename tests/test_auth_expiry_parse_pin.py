"""auth-path expiry parsing — count-agnostic structural pin (census N-65).

The live defect: ``web/auth.py`` parsed persisted ``expires_at`` timestamps on
TWO security-critical paths (``verify_otp``, ``verify_api_key``) with a RAW
``datetime.fromisoformat(...)``. A corrupt / non-ISO stored value raised
``ValueError`` UNHANDLED → a 500 on the OTP login + on every bearer-token
check (a DoS / fail-open-shaped reliability hole on the auth surface). The
``email_triage._isotime.parse_iso`` SSOT already existed (returns ``None`` on
bad/empty input) but these two sites bypassed it.

The fix routes both through ``parse_iso`` and treats ``None`` as
expired/invalid (FAIL CLOSED — refuse the credential).

This pin keeps the auth surface on the SSOT: it bans a RAW
``datetime.fromisoformat`` call ANYWHERE in ``web/auth.py`` (a property over
every site, never ``len(...) == N``, per
``pattern_count_agnostic_structural_drift_catch``) — so a NEW expiry parse
added to the auth module inherits the requirement to go through ``parse_iso``.
"""

from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, parse_module  # N-350 R31

AUTH = SRC_ROOT / "web" / "auth.py"


def _fromisoformat_calls(tree: ast.AST) -> list[int]:
    """Lines of every ``*.fromisoformat(...)`` or bare ``fromisoformat(...)``
    call."""
    hits: list[int] = []
    for n in ast.walk(tree):
        if not isinstance(n, ast.Call):
            continue
        f = n.func
        name = (
            f.attr if isinstance(f, ast.Attribute)
            else f.id if isinstance(f, ast.Name)
            else None
        )
        if name == "fromisoformat":
            hits.append(n.lineno)
    return hits


def test_auth_module_has_no_raw_fromisoformat():
    tree = parse_module(AUTH); assert tree is not None  # N-350 R31 harness SSOT
    offenders = _fromisoformat_calls(tree)
    assert not offenders, (
        "web/auth.py calls datetime.fromisoformat directly at lines "
        f"{offenders} — a corrupt persisted expires_at would raise ValueError "
        "and 500 the auth path (census N-65). Route it through "
        "email_triage._isotime.parse_iso and treat None as expired/invalid "
        "(fail closed)."
    )


def test_auth_module_imports_parse_iso():
    """The SSOT must actually be wired in (a bare absence of fromisoformat
    could also mean the expiry check was deleted — assert the SSOT is used)."""
    src = AUTH.read_text(encoding="utf-8")
    assert "parse_iso" in src, (
        "web/auth.py no longer references parse_iso — the expiry parses must "
        "go through the _isotime.parse_iso SSOT."
    )


# --------------------------------------------------------------------------
# Teeth — the detector must catch a planted raw call + pass a parse_iso call.
# --------------------------------------------------------------------------
def test_pin_has_teeth_raw_call_caught():
    code = "from datetime import datetime\nx = datetime.fromisoformat(s)\n"
    assert _fromisoformat_calls(ast.parse(code))


def test_pin_has_teeth_parse_iso_not_flagged():
    code = "from email_triage._isotime import parse_iso\nx = parse_iso(s)\n"
    assert not _fromisoformat_calls(ast.parse(code))
