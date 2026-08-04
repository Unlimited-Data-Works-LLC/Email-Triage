"""N-332 R30 structural pin: `<logger>.debug/info/warning(..., exc_info=…)`
is a silent-swallow of the traceback on TriageLogger callers.

BACKGROUND
==========
`TriageLogger.debug/info/warning` signatures (triage_logging.py:438-444)
are `(self, msg, *args, **extra)` — they DO NOT thread `exc_info`.
Passing `exc_info=<exception>` is silently swallowed into `**extra`
where nothing looks at it. Only `.error()`, `.critical()`, and `.log()`
extract `exc_info` explicitly and thread it into the underlying record
(triage_logging.py:447/459/464).

Trust-audit Phase 1 devils-advocate CONFIRMED live at HEAD: N-330's
migration from stdlib `logging.getLogger().debug(msg, exc_info=e)` to
`TriageLogger.debug(msg, exc_info=e)` silently dropped the OAuth push
traceback on `_dashboard_health_chips`. Pre-N-330 stdlib version honored
`exc_info`; post-N-330 sinks it.

WHY COUNT-AGNOSTIC + INTERPROCEDURAL
=====================================
The pin walks EVERY `.py` under `src/email_triage/` and flags any call
of the form `<any>.debug|info|warning(..., exc_info=…)`. It does NOT
require the receiver to be a specific TriageLogger binding — because
(a) at the point of writing, `get_logger` returns a TriageLogger project-
wide (`triage_logging` is the emitter SSOT per PD#3), (b) stdlib
`logging.Logger.debug/info/warning` DO thread `exc_info` but using them
is itself an SSOT bypass caught by the N-196b/N-242 STRICT-0 pins, so a
stdlib-logger caller of `.debug(exc_info=…)` is a DIFFERENT defect
(SSOT bypass) not covered here — and no stdlib-logger source that
survives those pins would land at HEAD anyway. Any legitimate stdlib
site can be added to `ALLOW_LIST` with a written justification.

WHY NOT `.error()`/.critical()/.log()`
=====================================
Those three explicitly thread `exc_info` — they're the ONLY correct
targets for a traceback-carrying log. The intent of this pin is:
if you need `exc_info`, use `.error()` (or `.critical()` for terminal).
"""
from __future__ import annotations

import ast

from _pin_harness import iter_src_files, parse_module, relpath

# Sites permitted to pass `exc_info` to a non-error method (with rationale).
# Empty at N-332 close — no legitimate site identified during trust-audit.
# Adding to this dict REQUIRES an inline justification of why the caller
# is stdlib-logging (which honors exc_info) rather than a TriageLogger.
ALLOW_LIST: dict[str, str] = {}

_BANNED_METHODS = {"debug", "info", "warning"}


def _emit_sites(tree: ast.Module) -> list[tuple[ast.Call, str]]:
    """Return (call, method_name) for every `<x>.debug|info|warning(..., exc_info=…)`."""
    out: list[tuple[ast.Call, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _BANNED_METHODS:
            continue
        if any(kw.arg == "exc_info" for kw in node.keywords):
            out.append((node, node.func.attr))
    return out


def test_no_exc_info_on_debug_info_warning():
    """Every log call in ``src/email_triage/`` that threads ``exc_info`` MUST
    target `.error()` / `.critical()` / `.log()` — never `.debug/.info/.warning`,
    which silently swallow `exc_info` on the TriageLogger SSOT."""
    import pytest
    violations: list[str] = []
    for fpath in iter_src_files():
        rel = relpath(fpath)
        text = fpath.read_text(encoding="utf-8")
        # Fast-path: nothing to scan if `exc_info` doesn't appear at all.
        if "exc_info" not in text:
            continue
        tree = parse_module(fpath)
        for call, method in _emit_sites(tree):
            key = f"{rel}:{call.lineno}:{method}"
            if key in ALLOW_LIST:
                continue
            violations.append(f"  {rel}:{call.lineno}  .{method}(..., exc_info=…) — use .error() instead")
    if violations:
        listed = "\n".join(violations)
        pytest.fail(
            "TriageLogger .debug/info/warning silently swallow `exc_info` (see "
            "triage_logging.py:438-444). Sites found:\n"
            f"{listed}\n"
            "Route through .error() / .critical() / .log() — those thread "
            "exc_info explicitly (triage_logging.py:447/459/464)."
        )
