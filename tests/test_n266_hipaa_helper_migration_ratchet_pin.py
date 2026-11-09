"""N-266 R27 structural pin — is_account_hipaa → account_hipaa_effective growth-cap (2026-07-03).

Census R27 discovered HIGH #2 (two parallel HIPAA-fold helpers, 81
callsites/32 files): `is_account_hipaa` and `account_hipaa_effective`
both live public + carry different intent. Per verify-don't-accept
`is_account_hipaa` DOES fold system HIPAA (line 120 returns True if
`_hipaa_mode`), so it's semantically equivalent to
`account_hipaa_effective(account=x)` for the no-message case. The
class is stylistic drift, not a live defect at HEAD.

BUT: to prevent NEW callers from adopting the deprecated helper,
this pin caps `is_account_hipaa` Call count at baseline. Every
migration to `account_hipaa_effective` decrements the baseline.
Eventually the ratchet reaches zero and the helper can be removed
outright (N-178 pattern).

WHAT IT PINS (count-agnostic growth-cap):

Total `is_account_hipaa(...)` calls tree-wide (bare Name OR Attribute
`x.is_account_hipaa(...)`) outside `triage_logging.py` (the SSOT
module that owns both helpers) must be <= baseline.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_IS_ACCOUNT_HIPAA_CALLS = 58  # 2026-07-03 N-266 R27 baseline.
_SSOT_FILE = "triage_logging.py"


def _count_calls(tree: ast.AST, name: str) -> int:
    n = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Name) and f.id == name:
            n += 1
        if isinstance(f, ast.Attribute) and f.attr == name:
            n += 1
    return n


def test_is_account_hipaa_growth_cap():
    """Total `is_account_hipaa(...)` calls outside `triage_logging.py`
    must be <= baseline. NEW hand-rolls fire — migrate to
    `account_hipaa_effective(account=..., message=...)` (the SSOT that
    also handles the per-message HIPAA axis when a message is in
    scope) or add to `_ALLOW` with reason."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] == _SSOT_FILE:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_calls(tree, "is_account_hipaa")
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_IS_ACCOUNT_HIPAA_CALLS, (
        f"N-266 R27 is_account_hipaa growth-cap: total count "
        f"{total} > baseline {_MAX_IS_ACCOUNT_HIPAA_CALLS}. NEW "
        "hand-rolls must migrate to `account_hipaa_effective` — it's "
        "the SSOT for the 3-axis (system / per-account / per-message) "
        "HIPAA fold. `is_account_hipaa` is semantically equivalent for "
        "the no-message case at HEAD but per operator's DA-gated "
        "convergence plan should be deprecated in favor of the "
        "3-axis SSOT.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in sorted(per_file, key=lambda x: -x[1])[:12])
    )


def test_account_hipaa_effective_ssot_reachable():
    """Anti-vacuity: the SSOT imports."""
    from email_triage.triage_logging import account_hipaa_effective
    assert callable(account_hipaa_effective)
