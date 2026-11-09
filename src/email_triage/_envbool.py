"""String/env/form → bool parsing SSOT (A9, divergence census 2026-06-09).

Parsing a flag value ("1" / "true" / "on" / a checkbox) to a bool was
hand-rolled across the codebase with DIVERGENT recognized sets
({"1","true","yes"} vs {"1","true","yes","on"} vs a case-sensitive
``== "1" or == "on" or == "true"`` chain) — and, worst, a few security
flags were read as a BARE truthy::

    if os.environ.get("EMAIL_TRIAGE_AUDIT_STRICT"):   # WRONG

Every non-empty string is truthy in Python, so ``AUDIT_STRICT=0`` /
``=false`` / ``=off`` *enabled* the flag — an opposite-direction flip on a
§164.312(b) audit control. This module is the single recognized-set
authority; ``tests/test_envbool_ssot_pin_a9.py`` pins it.
"""

from __future__ import annotations

import os
from typing import Any

#: Tokens that mean True / False (compared case-folded + stripped). Kept
#: to the conservative full-word + 1/0 set every existing site already
#: used — NOT single chars — so the recognized surface is unchanged and a
#: typo (e.g. ``flase``) is never silently treated as an explicit False
#: (it falls through to the caller's default / the tristate ``None`` defer,
#: which the DB-encryption gate relies on so a typo can't disable
#: encryption). ``""`` counts as False for :func:`parse_bool` only; the
#: tristate defers on it.
_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off", ""})


def parse_bool(value: Any, *, default: bool = False) -> bool:
    """Parse a flag value to bool. ``1/true/yes/on`` → True,
    ``0/false/no/off``/empty → False (case-insensitive, whitespace
    tolerant); ``None`` or an unrecognized token → ``default``.

    THE fix for the bare-truthy bug: ``parse_bool("0")`` is ``False`` (not
    ``True`` as ``bool("0")`` would be)."""
    if value is None:
        return default
    v = str(value).strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    return default


def parse_bool_tristate(value: Any) -> "bool | None":
    """Like :func:`parse_bool` but returns ``None`` for an unrecognized /
    absent token instead of a default — the "defer to the configured
    value" shape the DB-encryption gate needs so a typo can't silently
    flip a security default (``EMAIL_TRIAGE_AUDIT_STRICT= true/false`` is
    honored; ``=garbage`` falls through to the YAML field)."""
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE - {""}:  # empty string defers, not "explicitly false"
        return False
    return None


def env_bool(key: str, *, default: bool = False) -> bool:
    """Read an environment variable as a bool via :func:`parse_bool`."""
    return parse_bool(os.environ.get(key), default=default)
