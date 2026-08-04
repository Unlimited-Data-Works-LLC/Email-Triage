"""SSOT-registry ↔ pin-file coverage pin (divergence census run14 ; PD#7).

The §3 SSOT registry in ``internal documentation`` records, for
every converged operation-class, the pin file that guards it. That linkage was
itself UNPINNED: if a referenced pin file is renamed or deleted, the registry
silently LIES — the class still reads "✅ pinned" while nothing actually guards
it, and CI stays green. This is the "a pin exists ≠ safe / census the censusers"
failure (Prime Directive #7) one level up: the REGISTRY's claims must themselves
be checked.

This pin asserts the forward bijection: every ``tests/test_*.py`` the registry
NAMES must EXIST on disk. (The reverse direction — every structural pin appears
in the registry — is intentionally NOT asserted here: not every pin maps to a §3
SSOT row; many are N-xx finding pins. Forward-existence is the high-value,
false-positive-free half.)
"""

from __future__ import annotations

import re
from pathlib import Path

from _pin_harness import REPO_ROOT as _REPO  # census run15 #3 — robust repo root
_PLAYBOOK = _REPO / "docs" / "ssot-and-divergence-playbook.md"
# A pin-file reference in the registry: `tests/test_<name>.py` (backtick-wrapped
# or inline). Captures the basename so we can check existence under tests/.
_PIN_REF_RE = re.compile(r"\btests/(test_[a-z0-9_]+\.py)\b")


def _referenced_pin_files() -> list[str]:
    text = _PLAYBOOK.read_text(encoding="utf-8")
    return sorted(set(_PIN_REF_RE.findall(text)))


def test_every_registry_pin_file_exists():
    """Every pin file the §3 SSOT registry references must exist — a stale
    reference means the registry claims a guard that isn't there."""
    referenced = _referenced_pin_files()
    # Sanity: the registry must reference SOME pins, else the regex (or the
    # registry) drifted and this guard is vacuous.
    assert referenced, (
        "no `tests/test_*.py` pin references found in "
        "internal documentation — the regex or the registry drifted"
    )
    missing = [f for f in referenced if not (_REPO / "tests" / f).exists()]
    assert not missing, (
        "The §3 SSOT registry (internal documentation) names pin "
        f"file(s) that DO NOT EXIST under tests/: {missing}. A renamed/deleted "
        "pin makes the registry lie (a class reads '✅ pinned' while nothing "
        "guards it). Fix the registry reference or restore the pin."
    )


def test_pin_has_teeth():
    # A planted missing reference is detected by the same existence logic.
    fake = "test_this_pin_does_not_exist_xyz.py"
    assert not (_REPO / "tests" / fake).exists()
    # The regex matches the registry's reference shape.
    assert _PIN_REF_RE.findall(
        "guarded by `tests/test_credential_hash_ssot_pin.py` (count-agnostic)"
    ) == ["test_credential_hash_ssot_pin.py"]
    # …and does NOT match a non-tests path or a bare filename.
    assert not _PIN_REF_RE.findall("see src/email_triage/web/_credhash.py")
