"""N-196 R20_9 structural pin — module-level stdlib logging.getLogger ratchet.

Census run20 R20_9 finding: ~65 modules across `providers/`, `classify/`,
`ai_backends/`, `style_learning/`, `engine/ics.py`, `secrets.py`, `backup.py`,
`jobs/` bind stdlib `logging.getLogger` instead of `TriageLogger` (the PHI-
sink-allowlisted logger family). Split-brain modules import TriageLogger
helpers yet bind stdlib logger — a subtle PHI-sink bypass.

Fix per census: (a) migrate module-level `logging.getLogger` binds to
`TriageLogger.get_logger` in the flagged directories, (b) AST pin banning
NEW `logging.getLogger` assignments outside an allow-list.

This pin captures the current baseline (21 module-level binds across the
census-flagged directories at 2026-07-01) and ratchets down per commit
(N-178 commit-coupled pattern). N-196b follow-up: migrate the 21 sites
to TriageLogger.get_logger and decrement to 0.
"""
from __future__ import annotations

import ast

from _pin_harness import SRC_ROOT, iter_files, parse_module, relpath


# Ratchet baseline (2026-07-01) — module-level `x = logging.getLogger(...)` in
# the census-flagged directories. Decrement in the SAME commit that migrates
# a site (commit-coupled per N-178).
_MAX_STDLIB_LOGGERS = 0  # 2026-07-02: STRICT-0 tree-wide. R21_4 close via 4 batches: SAFE 20 + UNSAFE 26 + scope-final 7 + web/ 12 = 65 total. Every module-level logger in src/email_triage now routes through email_triage.triage_logging.get_logger → PHI-sink allowlist active on EVERY module.

_CENSUS_SCOPE_DIRS = ("providers", "classify", "ai_backends", "style_learning", "jobs")
# N-196 R21_4 widening (2026-07-02): after tree-wide STRICT-0 the pin now walks
# ALL of src/email_triage, not just the initial census-flagged 5 dirs. Original
# scope kept in `_CENSUS_SCOPE_DIRS` for narrative + potential future
# scope-only re-report; the actual walk uses SRC_ROOT-wide iter_files below.


def _is_stdlib_getlogger_call(call: ast.AST) -> bool:
    """True if `call` is `logging.getLogger(...)`."""
    if not isinstance(call, ast.Call):
        return False
    f = call.func
    if not (isinstance(f, ast.Attribute) and f.attr == "getLogger"):
        return False
    base = f.value
    return isinstance(base, ast.Name) and base.id == "logging"


def _module_level_stdlib_logger_binds(tree: ast.AST) -> list[int]:
    """Line numbers of `<Name> = logging.getLogger(...)` assignments at
    MODULE scope (not inside a class/function body)."""
    hits = []
    for node in tree.body:  # module-level statements only
        if not isinstance(node, ast.Assign):
            continue
        if not _is_stdlib_getlogger_call(node.value):
            continue
        for tgt in node.targets:
            if isinstance(tgt, ast.Name):
                hits.append(node.lineno)
                break
    return hits


def _walk_scope():
    # N-196 R21_4 widening (2026-07-02): walk ALL of src/email_triage after
    # the tree-wide STRICT-0 close. Any NEW module (anywhere in src/) that
    # binds stdlib logging.getLogger at module scope is now caught.
    for path in iter_files(SRC_ROOT):
        yield path


def test_stdlib_logging_getlogger_ratchet():
    """Module-level `x = logging.getLogger(...)` binds in the census-flagged
    dirs (providers/, classify/, ai_backends/, style_learning/, jobs/) MUST
    ride the ratchet baseline. New binds outside the baseline MUST route
    through `TriageLogger.get_logger` for PHI-sink allowlist protection."""
    offenders: list[str] = []
    for path in _walk_scope():
        tree = parse_module(path)
        if tree is None:
            continue
        for ln in _module_level_stdlib_logger_binds(tree):
            offenders.append(f"{relpath(path)}:{ln}")
    assert len(offenders) <= _MAX_STDLIB_LOGGERS, (
        f"N-196 R20_9 stdlib logging.getLogger count {len(offenders)} > "
        f"baseline {_MAX_STDLIB_LOGGERS}: " + ", ".join(offenders[:15])
    )


def test_pin_has_teeth():
    bad = ast.parse("""
import logging
log = logging.getLogger(__name__)
""")
    assert _module_level_stdlib_logger_binds(bad)

    good = ast.parse("""
from email_triage.triage_logging import get_logger
log = get_logger("mod")
""")
    assert not _module_level_stdlib_logger_binds(good)

    # A logging.getLogger INSIDE a function is NOT module-level → not flagged.
    lazy = ast.parse("""
import logging
def h():
    log = logging.getLogger(__name__)
""")
    assert not _module_level_stdlib_logger_binds(lazy)
