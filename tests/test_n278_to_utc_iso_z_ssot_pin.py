"""N-278 R29 structural pin — UTC-ISO-Z wire-format SSOT (2026-07-03).

R29 census MED #5 (calendar UTC-ISO-Z wire fmt): 12 hand-rolled
repetitions across `providers/gmail_calendar.py` +
`providers/office365_calendar.py` of the shape:

    dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

(10 sites) OR

    dt.astimezone(timezone.utc).isoformat().replace("+00:00", "")

(2 O365 sites). No shared helper — any Graph API precision change
would need touching all 12.

N-278 lands two SSOTs in `_isotime.py` (`to_utc_iso_z`,
`to_utc_iso_no_suffix`) + migrates all 12 sites. STRICT-0 pin.

WHAT IT PINS (STRICT-0):

Any `<expr>.astimezone(timezone.utc).isoformat().replace("+00:00",
<const>)` outside `_isotime.py` fires. Route through the SSOT.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILE = "_isotime.py"


def _is_zfmt_replace_call(node: ast.AST) -> bool:
    """`<X>.astimezone(timezone.utc).isoformat().replace("+00:00", <const>)`
    — detect the exact hand-rolled shape N-278 replaces."""
    if not isinstance(node, ast.Call):
        return False
    outer = node.func
    if not (isinstance(outer, ast.Attribute) and outer.attr == "replace"):
        return False
    # args: (from_str, to_str) — from_str MUST be "+00:00"
    if len(node.args) != 2:
        return False
    a0 = node.args[0]
    if not (isinstance(a0, ast.Constant) and a0.value == "+00:00"):
        return False
    # receiver: <Y>.isoformat()
    iso_call = outer.value
    if not (isinstance(iso_call, ast.Call) and isinstance(iso_call.func, ast.Attribute)
            and iso_call.func.attr == "isoformat"):
        return False
    # receiver of isoformat: <Z>.astimezone(timezone.utc)
    astz_call = iso_call.func.value
    if not (isinstance(astz_call, ast.Call) and isinstance(astz_call.func, ast.Attribute)
            and astz_call.func.attr == "astimezone"):
        return False
    return True


def test_no_hand_rolled_utc_iso_z_replace():
    """STRICT-0: any hand-rolled `astimezone(utc).isoformat().replace
    ("+00:00", ...)` outside `_isotime.py` fires. Route through
    `_isotime.to_utc_iso_z(dt)` or `_isotime.to_utc_iso_no_suffix(dt)`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if _is_zfmt_replace_call(node):
                offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-278 R29 UTC-ISO-Z wire-format SSOT bypass: hand-rolled "
        "`astimezone(timezone.utc).isoformat().replace(\"+00:00\", ...)` "
        "outside `_isotime.py`. Route through "
        "`_isotime.to_utc_iso_z(dt)` (Z suffix — Google Cal + O365 "
        "Graph timeMin/timeMax/dateTime) or `to_utc_iso_no_suffix(dt)` "
        "(empty suffix — O365 dateTime with companion timeZone field).\n\n"
        + "\n".join(offenders)
    )


def test_to_utc_iso_z_ssot_shape():
    """Anti-vacuity: SSOTs import + produce the expected wire shapes."""
    from email_triage._isotime import to_utc_iso_z, to_utc_iso_no_suffix
    from datetime import datetime, timezone
    dt = datetime(2026, 7, 3, 12, 34, 56, tzinfo=timezone.utc)
    z = to_utc_iso_z(dt)
    assert z.endswith("Z") and "T" in z and "+00:00" not in z, z
    no_sfx = to_utc_iso_no_suffix(dt)
    assert not no_sfx.endswith("Z") and "+00:00" not in no_sfx, no_sfx
