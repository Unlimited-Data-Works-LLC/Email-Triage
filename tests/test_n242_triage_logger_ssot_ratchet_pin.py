"""N-242 R24 structural pin — TriageLogger SSOT growth-cap (2026-07-03).

Census R24 discovered MED (TriageLogger SSOT bypass): 8 sites tree-wide
use raw `logging.getLogger(...)` (including aliased `import logging as
_logging` at `api.py:363` — which hides an admin user-delete audit
outside the HMAC chain AND from any literal-substring grep).

N-242 already fixed 2 HIPAA-load-bearing sites:
  - `web/routers/api.py::api_delete_user` (admin user-delete audit).
  - `db/accounts.py::_delete_account_and_secrets` (§164.310(d)).

Both migrated to `triage_logging.get_logger(...)`.

The remaining 8 tree-wide sites (baseline for this ratchet) are legit
setLevel-only or defensive-init call sites where the raw stdlib logger
is intentional (see per-site comments). Growth-cap prevents NEW
`getLogger` bypass without decrementing this baseline.

WHAT IT PINS (count-agnostic, growth-cap ratchet):

Every `<x>.getLogger(...)` call tree-wide (excluding
`triage_logging.py`) counts. Total must not exceed
`_MAX_GETLOGGER_CALLS`. Migration to `triage_logging.get_logger`
decrements the baseline (N-178/N-219/etc. pattern).
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


_MAX_GETLOGGER_CALLS = 2  # 2026-07-03 N-242b R24 baseline (post 6-site migration; 2 remaining are root-logger setLevel-legit at web/app.py:799 + web/routers/ui/_shared.py:5909).
_SSOT_FILES = {"triage_logging.py"}


def _count_getlogger_in_tree(tree: ast.AST) -> int:
    n = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "getLogger":
                n += 1
    return n


def test_triage_logger_ssot_growth_cap():
    """Total tree-wide `<x>.getLogger(...)` sites (outside SSOT) must be
    <= baseline. New hand-rolls fire."""
    total = 0
    per_file: list[tuple[str, int]] = []
    for path in iter_files(SRC_ROOT):
        rel = relpath(path)
        if rel.split("/")[-1] in _SSOT_FILES:
            continue
        tree = parse_module(path)
        if tree is None:
            continue
        n = _count_getlogger_in_tree(tree)
        if n > 0:
            total += n
            per_file.append((rel, n))
    assert total <= _MAX_GETLOGGER_CALLS, (
        f"N-242 R24 TriageLogger SSOT ratchet: `<x>.getLogger(...)` count "
        f"{total} > baseline {_MAX_GETLOGGER_CALLS}. NEW hand-rolls must "
        "route through `triage_logging.get_logger(...)` so audit-sensitive "
        "log lines ride the HMAC chain. An aliased-import bypass (`import "
        "logging as _logging`) is the same SSOT bypass shape.\n\n"
        + "\n".join(f"{p}: {n}" for p, n in per_file[:12])
    )


def test_ssot_get_logger_exists():
    """Anti-vacuity: `triage_logging.get_logger` must import."""
    from email_triage.triage_logging import get_logger
    assert callable(get_logger)
