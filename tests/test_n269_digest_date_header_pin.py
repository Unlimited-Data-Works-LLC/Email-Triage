"""N-269 R28 structural pin — digest date-header SSOT (2026-07-03).

Census R28 discovered MED-LIVE (#4 digest date header UTC vs local tz
drift): `web/digest.py:457` used `now_utc.strftime("%A, %B %d, %Y")` —
UTC-derived — while its 2 sibling sites (`actions/digest.py:600`,
`actions/recipient_digest.py:469`) used LOCAL tz. Consequence: west-
coast afternoons/evenings rendered "Monday" while sibling sites
rendered "Sunday" for the SAME digest emission. Live user-visible
date-off-by-one bug.

N-269 fix: `_isotime.now_local_date_header()` SSOT + all 3 sites
migrated. Sibling `parse_iso_date` SSOT added for the R28 #1
`datetime.fromisoformat` sweep follow-up.

WHAT IT PINS (STRICT-0):

Any `strftime("%A, %B %d, %Y")` outside `_isotime.py` fires. Route
through `now_local_date_header()` (SSOT owns the local-tz + format
string; a caller doesn't need to remember either).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_SSOT_FILE = "_isotime.py"


def test_no_raw_strftime_date_header_outside_ssot():
    """STRICT-0: any `strftime("%A, %B %d, %Y")` outside `_isotime.py`
    fires. Route through `_isotime.now_local_date_header()`."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            f = node.func
            if not (isinstance(f, ast.Attribute) and f.attr == "strftime"):
                continue
            if not node.args:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                if arg.value == "%A, %B %d, %Y":
                    offenders.append(f"{rel}:{node.lineno}")
    assert not offenders, (
        "N-269 R28 digest date-header SSOT bypass: raw "
        "`strftime(\"%A, %B %d, %Y\")` outside `_isotime.py`. Route "
        "through `_isotime.now_local_date_header()` — the SSOT owns "
        "the local-tz timezone fold + the format string. Bypassing "
        "silently drifts either dimension.\n\n"
        + "\n".join(offenders)
    )


def test_now_local_date_header_ssot_reachable():
    """Anti-vacuity: the SSOT + sibling `parse_iso_date` import."""
    from email_triage._isotime import now_local_date_header, parse_iso_date
    assert callable(now_local_date_header)
    assert callable(parse_iso_date)
    # SSOT returns the expected format shape (weekday, month + day, year).
    result = now_local_date_header()
    import re
    assert re.match(r"^[A-Z][a-z]+, [A-Z][a-z]+ \d{2}, \d{4}$", result), (
        f"unexpected format: {result!r}"
    )
