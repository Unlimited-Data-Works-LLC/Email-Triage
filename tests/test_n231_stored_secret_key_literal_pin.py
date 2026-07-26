"""N-231 R22 structural pin — stored-secret KEY-NAME literal SSOT (2026-07-02).

Census R22 discovered class (MED, sub-class of secret-read):
`SMTP_PASSWORD` / `session_secret` / `acme_account_key` key-name string
literals had drifted across 20+ sites (readers + writers + app.state
attribute getattrs — 3 shapes, one literal). A rename or a case-mismatch
decoupled writers from readers silently.

N-231 fix:
  - New SSOT module `email_triage/_secret_keys.py` with 3 constants:
    `SMTP_PASSWORD_KEY`, `SESSION_SECRET_KEY`, `ACME_ACCOUNT_KEY_KEY`.
  - Migrated 16 files: bulk replace of `"SMTP_PASSWORD"` /
    `"session_secret"` / `"acme_account_key"` string literals to the
    corresponding constant. Import line inserted after the last single-
    line `from email_triage.<x> import <y>` in each file.

WHAT IT PINS (count-agnostic, STRICT-0):

Every string literal `"SMTP_PASSWORD"` / `"session_secret"` /
`"acme_account_key"` tree-wide (outside the SSOT module) fires the pin.
Route through `email_triage._secret_keys.<CONST>`.

SCOPE CAVEAT: matches only the exact 3 documented literals. Case-variants
(`"smtp_password"` / `"SMTP_password"`) are NOT flagged — but those are
the DEFECT this pin exists to prevent (a rename that misses N-1 sites).
The three exact literals below are pinned STRICT-0.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_STORED_SECRET_KEYS = {"SMTP_PASSWORD", "session_secret", "acme_account_key"}
_SSOT_FILES = {"_secret_keys.py"}


def test_no_raw_stored_secret_key_literal_outside_ssot():
    """STRICT-0: no string literal in _STORED_SECRET_KEYS tree-wide
    outside the SSOT module."""
    offenders: list[str] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and node.value in _STORED_SECRET_KEYS):
                offenders.append(f"{rel}:{node.lineno}  {node.value!r}")
    assert not offenders, (
        "N-231 R22 stored-secret key-name STRICT-0: raw string literal "
        "for a stored-secret key found outside `email_triage/_secret_keys.py`. "
        "Route through `SMTP_PASSWORD_KEY` / `SESSION_SECRET_KEY` / "
        "`ACME_ACCOUNT_KEY_KEY` so a rename doesn't silently decouple a "
        "writer from a reader.\n\n"
        + "\n".join(offenders)
    )


def test_ssot_constants_reachable():
    """Anti-vacuity: the 3 constants must import + have the documented
    values. A rename here without matching migrations breaks callers."""
    from email_triage._secret_keys import (
        ACME_ACCOUNT_KEY_KEY,
        SESSION_SECRET_KEY,
        SMTP_PASSWORD_KEY,
    )
    assert SMTP_PASSWORD_KEY == "SMTP_PASSWORD"
    assert SESSION_SECRET_KEY == "session_secret"
    assert ACME_ACCOUNT_KEY_KEY == "acme_account_key"
